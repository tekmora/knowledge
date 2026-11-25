# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
# SPDX-License-Identifier: EUPL-1.2

import ast
import importlib.util
import io
import json
import os
import re
import runpy
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from functools import partial
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
DEADLINE_PATHS = (
    "mcp/dogfood_dev_mcp.py",
    "mcp/dogfood_mcp.py",
    "pipeline/eval_authority.py",
    "pipeline/ingest.py",
    "pipeline/ingest_dev.py",
    "pipeline/served_routing_eval.py",
    "pipeline/verify_dev.py",
    "tools/knowledge-registry/snapshot_receipts_offline.py",
    "tools/knowledge-registry/tests/test_knowledge_registry.py",
    "tools/knowledge-registry/tests/test_p1_src03_acquisition_runner.py",
)
# Byte-pinned by execution-manifest.json; each needs a live HISS-02 exception in .standards.yaml.
DEADLINE_EXCEPTIONS = (
    "tools/knowledge-registry/p1-src03-acquisition-runner/verify_execution_manifest.py",
)
EXCEPTION_ENTRY = re.compile(r"^  - rule: (\S+)\n((?:    \S.*\n)*)", re.MULTILINE)
EXCEPTION_FIELD = re.compile(r"^    (\w+): (.*)$", re.MULTILINE)


def declared_exceptions(rule):
    """Map each path .standards.yaml excepts from rule to its expiry."""
    text = (REPO_ROOT / ".standards.yaml").read_text(encoding="utf-8")
    declared = {}
    for entry in EXCEPTION_ENTRY.finditer(text):
        if entry.group(1) != rule:
            continue
        fields = {
            key: value.strip().strip('"')
            for key, value in EXCEPTION_FIELD.findall(entry.group(2))
        }
        if "path" in fields:
            declared[fields["path"]] = fields.get("expires", "")
    return declared


def subprocess_run_calls(tree):
    """Yield each subprocess.run call in tree, by module or imported name."""
    aliases = {
        name.asname or name.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module == "subprocess"
        and node.level == 0
        for name in node.names
        if name.name == "run"
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in aliases:
            yield node
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "run"
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
        ):
            yield node


def run_or_timeout(command, *, timeout, timeout_command, stdout, **kwargs):
    """Fake subprocess.run: time out on timeout_command, else return stdout."""
    if timeout_command in command[:2]:
        raise subprocess.TimeoutExpired(command, timeout)
    return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


class SubprocessDeadlineTests(unittest.TestCase):
    def test_subprocess_runs_have_timeouts(self):
        """Every subprocess.run in the deadline paths sets a timeout."""
        for relative in DEADLINE_PATHS:
            with self.subTest(path=relative):
                source = (REPO_ROOT / relative).read_text(encoding="utf-8")
                tree = ast.parse(source, filename=relative)
                for call in subprocess_run_calls(tree):
                    with self.subTest(line=call.lineno):
                        self.assertTrue(
                            any(
                                kw.arg == "timeout"
                                and not (
                                    isinstance(kw.value, ast.Constant)
                                    and kw.value.value is None
                                )
                                for kw in call.keywords
                            ),
                            f"{relative}:{call.lineno}: subprocess.run needs an explicit timeout",
                        )

    def test_deadline_exceptions_are_declared(self):
        """Each path left out of the check has a live HISS-02 exception."""
        declared = declared_exceptions("HISS-02")
        for relative in DEADLINE_EXCEPTIONS:
            with self.subTest(path=relative):
                self.assertNotIn(relative, DEADLINE_PATHS)
                self.assertIn(relative, declared, f"{relative}: no HISS-02 exception")
                self.assertGreaterEqual(declared[relative], date.today().isoformat())

    def test_mcp_search_timeouts_return_errors(self):
        """A timed-out command in either MCP search returns its error."""
        for name in ("dogfood_dev_mcp", "dogfood_mcp"):
            path = REPO_ROOT / "mcp" / f"{name}.py"
            spec = importlib.util.spec_from_file_location(name, path)
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            config = dict.fromkeys(
                ("hyb", "hyb_sha", "dense", "dense_sha", "pol", "pol_sha"), "fixture"
            )
            with tempfile.TemporaryDirectory() as directory:
                artifact = Path(directory) / "signal.json"
                artifact.write_text("{}", encoding="utf-8")
                signal_result = json.dumps({"artifact_path": str(artifact)})
                for subcommand in ("materialize-query-signal", "hybrid-query"):
                    with (
                        self.subTest(module=name, command=subcommand),
                        patch.object(module, "_load", return_value=config),
                        patch.object(module, "ensure_endpoint", return_value=True),
                        patch.object(tempfile, "mkdtemp", return_value=directory),
                        patch.object(
                            subprocess,
                            "run",
                            side_effect=partial(
                                run_or_timeout,
                                timeout_command=subcommand,
                                stdout=signal_result,
                            ),
                        ),
                    ):
                        self.assertEqual(
                            {"error": f"{subcommand} timed out after 600 seconds"},
                            module.search("fixture query"),
                        )

    def test_served_routing_records_timeouts_as_failed_queries(self):
        """A timed-out query in served routing counts as a failed query."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                "retrieval-shared-full/hybrid-candidates/sha256/a/hybrid.json",
                "dense-46/dense-artifacts/sha256/a/dense.json",
            ):
                artifact = root / relative
                artifact.parent.mkdir(parents=True)
                artifact.write_text("{}", encoding="utf-8")
            evidence = root / "evidence.json"
            evidence.write_text(
                '{"files": [{"relative_path": "docs/topic.md"}]}', encoding="utf-8"
            )
            lineage = {
                "authority_id": "authority:fixture:v1",
                "admission_policy": "fixture",
                "admission_policy_sha256": "fixture",
                "evidence_manifest": str(evidence),
            }
            (root / "lineage-set-full.json").write_text(
                json.dumps({"lineages": [lineage]}), encoding="utf-8"
            )
            signal = root / "signal.json"
            signal.write_text("{}", encoding="utf-8")
            signal_result = json.dumps({"artifact_path": str(signal)})
            settings = {"ARCHEION_RAG_PROBE_HOME": directory}
            for timeout_command, call_count, expected_top in (
                ("rm", 1, "SIGNAL_FAIL"),
                ("materialize-query-signal", 2, "SIGNAL_FAIL"),
                ("hybrid-query", 3, "NONE"),
            ):
                with (
                    self.subTest(command=timeout_command),
                    patch.object(os.environ, "get", side_effect=settings.get),
                    patch.object(os.environ, "setdefault"),
                    patch.object(
                        subprocess,
                        "run",
                        side_effect=partial(
                            run_or_timeout,
                            timeout_command=timeout_command,
                            stdout=signal_result,
                        ),
                    ) as run,
                    redirect_stdout(io.StringIO()) as stdout,
                ):
                    runpy.run_path(str(REPO_ROOT / "pipeline/served_routing_eval.py"))
                    result = json.loads(stdout.getvalue().removeprefix("RESULT="))
                    self.assertEqual(run.call_count, call_count)
                    self.assertEqual(result["correct"], 0)
                    self.assertEqual(result["results"][0]["top"], expected_top)
                    self.assertIs(result["results"][0]["ok"], False)

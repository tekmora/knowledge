# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import tempfile
import unittest
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
with patch.object(sys, "path", [str(TOOL_ROOT), *sys.path]):
    import capture_live as live
    import knowledge_registry as kr

Record = dict[str, Any]
MAX_FIXTURE_ROWS = 4
OBSERVED = "2026-01-02T03:04:05Z"
LATER = "2026-01-02T03:04:06Z"
DIGEST = "sha256:" + "a" * 64
CHANNEL_URI = "https://example.org/app"
OCI_REGISTRY = "registry.example.org"
OCI_REPOSITORY = "example/app"
OCI_URI = f"oci://{OCI_REGISTRY}/{OCI_REPOSITORY}:1.2.3"
OCI_MEDIA = "application/vnd.oci.image.manifest.v1+json"


def only(records: Mapping[str, Record]) -> Record:
    """Return the sole observation from a builder table."""
    (record,) = records.values()
    return record


def gap_types(builder: kr.Builder) -> set[str]:
    """Collect the explicitly emitted gap types."""
    return {gap["gap_type"] for gap in fixture_rows(builder.extra_gaps)}


def fixture_rows(records: Mapping[str, Record]) -> tuple[Record, ...]:
    """Bound the builder tables inspected by fixture assertions."""
    if len(records) > MAX_FIXTURE_ROWS:
        raise AssertionError(f"builder table exceeds {MAX_FIXTURE_ROWS} fixture rows")
    return tuple(records.values())


def source_builder() -> tuple[kr.Builder, str]:
    """Create a builder with one neutral source."""
    builder = kr.Builder()
    source_id = builder.add_source("input.json", "fixture", content_hash=DIGEST)
    return builder, source_id


def local_builder() -> tuple[kr.Builder, str, str, str]:
    """Create a source and its local owner."""
    builder, source_id = source_builder()
    component, version = kr.add_local_root(builder, source_id, "input.json", "fixture")
    return builder, source_id, component, version


class FilesTestCase(unittest.TestCase):
    """Build temporary files and patch the tracked-path cache on demand."""

    def setUp(self) -> None:
        """Create a fresh directory for fixture I/O."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def write(self, relative: str, content: str | bytes) -> Path:
        """Write a fixture under the temporary root."""
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            content.encode("utf-8") if isinstance(content, str) else content
        )
        return path

    def track(self, *paths: str) -> None:
        """Model committed paths in the scanner's per-root cache."""
        tracked = {self.root.as_posix(): frozenset(paths)}
        self.enterContext(patch.dict(kr._COMMITTED_VIEW_TRACKED_PATHS, tracked))


class ScannerTests(FilesTestCase):
    """Build temporary manifests, scripts, and scanner configuration files."""

    def test_normalize_codex_projection_references(self) -> None:
        """Canonicalize the projection argument while preserving unrelated byte spans."""
        projection = kr.CODEX_CANONICAL_PROJECTION_REF.replace(b"0" * 64, b"a" * 64)
        header = b"# retained " + projection + b"\n[mcp_servers.app]\n"
        data = header + b'args = ["--projection", "' + projection + b'"]\n'
        expected = (
            header + b'args = ["--projection", "' + kr.CODEX_CANONICAL_PROJECTION_REF
        )
        self.assertEqual(
            kr.normalize_codex_projection_references(data), expected + b'"]\n'
        )
        escaped = data.replace(b' "' + projection, b' "\\u002e' + projection[1:])
        self.assertEqual(kr.normalize_codex_projection_references(escaped), escaped)
        unrelated = header + b'args = ["--projection", "fixtures/projection.json"]\n'
        self.assertEqual(kr.normalize_codex_projection_references(unrelated), unrelated)
        other_flag = data.replace(b'"--projection"', b'"--projection-other"')
        self.assertEqual(
            kr.normalize_codex_projection_references(other_flag), other_flag
        )
        self.assertEqual(kr.normalize_codex_projection_references(b"\xff"), b"\xff")

    def test_scan_chart_lock(self) -> None:
        """Record matching lock edges and flag an exact declaration mismatch."""
        text = (
            "dependencies:\n  - name: child\n    version: 1.2.3\n"
            "    repository: https://charts.example.org\n"
        )
        self.write("Chart.yaml", "name: app\nversion: 2.0.0\n" + text)
        path = self.write("Chart.lock", text)
        self.track("Chart.lock")
        builder = kr.Builder()
        self.assertIsNone(
            kr.scan_chart_lock(builder, self.root, path, text.encode(), text)
        )
        edge = only(builder.edges)
        occurrence = only(builder.occurrences)
        self.assertEqual((edge["relationship"], edge["constraint"]), ("locks", "1.2.3"))
        self.assertEqual(
            (occurrence["evidence_locator"], occurrence["raw_value"]),
            ("line:2:lock:0", "child@1.2.3"),
        )
        self.assertEqual(gap_types(builder), set())

        mismatched = text.replace("1.2.3", "1.2.4")
        refused = kr.Builder()
        kr.scan_chart_lock(refused, self.root, path, mismatched.encode(), mismatched)
        gap = only(refused.extra_gaps)
        self.assertEqual(gap["gap_type"], "helm-lock-version-mismatch")
        self.assertIn("Chart.yaml declares '1.2.3'", gap["message"])

        elsewhere = text.replace("charts.example.org", "charts.example.net")
        refused = kr.Builder()
        kr.scan_chart_lock(refused, self.root, path, elsewhere.encode(), elsewhere)
        gap = only(refused.extra_gaps)
        self.assertEqual(gap["gap_type"], "helm-lock-repository-mismatch")
        self.assertIn(
            "from 'https://charts.example.net', declared as 'https://charts.example.org'",
            gap["message"],
        )
        self.assertEqual(gap["evidence"], ["Chart.lock#L2", "Chart.yaml#L4"])

    def test_scan_pyproject(self) -> None:
        """Keep exact dependency pins and optional extras while ignoring ordinary strings."""
        text = (
            '[project]\nname = "app"\nversion = "1.2.3"\n'
            'description = "ordinary"\ndependencies = ["Example_Dep[extra]==2.3.4"]\n'
            'requires-python = ">=3.11"\n'
        )
        path = self.write("pyproject.toml", text)
        builder = kr.Builder()
        self.assertIsNone(
            kr.scan_pyproject(builder, self.root, path, text.encode(), text)
        )
        self.assertEqual(
            {row["name"] for row in fixture_rows(builder.components)},
            {"app", "example-dep", "python", "python-stdlib"},
        )
        observations = {row["role"]: row for row in fixture_rows(builder.occurrences)}
        occurrence = observations["pyproject-dependency"]
        self.assertEqual(occurrence["evidence_locator"], "line:5:column:17")
        self.assertIs(occurrence["optional"], True)
        version = builder.versions[occurrence["component_version_id"]]
        self.assertEqual(
            (version["resolved_version"], version["constraint"]), ("2.3.4", "==2.3.4")
        )
        toolchain = observations["python-requires-version"]
        self.assertEqual(toolchain["raw_value"], ">=3.11")
        self.assertEqual(toolchain["evidence_locator"], "line:6")
        self.assertEqual(toolchain["dependency_scope"], "build")
        self.assertEqual(
            builder.versions[toolchain["component_version_id"]]["constraint"], ">=3.11"
        )

    def test_scan_containerd_hosts(self) -> None:
        """Distinguish registry and mirror edges and flag malformed TOML."""
        text = (
            'server = "https://registry.example.org"\n'
            '[host."https://mirror.example.org"]\n'
            'capabilities = ["pull"]\nskip_verify = false\nunused = "ignore"\n'
        )
        path = self.write("hosts.toml", text)
        builder = kr.Builder()
        self.assertIsNone(
            kr.scan_containerd_hosts(builder, self.root, path, text.encode(), text)
        )
        occurrences = {row["role"]: row for row in fixture_rows(builder.occurrences)}
        mirror = occurrences["containerd-registry-mirror"]
        self.assertEqual(
            mirror["metadata"], {"capabilities": ["pull"], "skip_verify": False}
        )
        self.assertEqual(mirror["evidence_locator"], "line:2")
        self.assertEqual(
            occurrences["containerd-registry-server"]["evidence_locator"], "line:1"
        )
        self.assertEqual(
            {row["relationship"] for row in fixture_rows(builder.edges)},
            {"configures", "routes-through"},
        )
        bad = kr.Builder()
        kr.scan_containerd_hosts(bad, self.root, path, b"server = [", "server = [")
        self.assertEqual(gap_types(bad), {"toml-invalid"})
        self.assertEqual(bad.occurrences, {})

    def test_scan_codex_config(self) -> None:
        """Sort remote tool names and skip local servers without URLs."""
        text = (
            '[mcp_servers.app]\nurl = "https://example.org/mcp"\n'
            'enabled_tools = ["write", "read"]\nrequired = true\nenabled = false\n'
            '[mcp_servers.local]\ncommand = "app"\n'
        )
        path = self.write("config.toml", text)
        builder = kr.Builder()
        self.assertIsNone(
            kr.scan_codex_config(builder, self.root, path, text.encode(), text)
        )
        occurrence = only(builder.occurrences)
        self.assertEqual(occurrence["raw_value"], "https://example.org/mcp")
        self.assertEqual(occurrence["dependency_scope"], "development")
        self.assertEqual(
            occurrence["metadata"],
            {"enabled": False, "required": True, "enabled_tools": ["read", "write"]},
        )
        bad = kr.Builder()
        kr.scan_codex_config(bad, self.root, path, b"[", "[")
        self.assertEqual(gap_types(bad), {"toml-invalid"})
        self.assertEqual(bad.occurrences, {})

    def test_scan_script_dependencies(self) -> None:
        """Resolve sibling pins and flag optional imports without pins."""
        text = (
            "import yaml\n# import requests\nfrom jsonschema import validate\n"
            'command = "optimum-cli export"\n'
        )
        path = self.write("app.py", text)
        self.write("requirements.txt", "PyYAML==1.2.3\noptimum==2.3.4\n")
        self.track("app.py", "requirements.txt")
        builder = kr.Builder()
        self.assertIsNone(
            kr.scan_script_dependencies(builder, self.root, path, text.encode(), text)
        )
        occurrences = {
            row["evidence_locator"]: row for row in fixture_rows(builder.occurrences)
        }
        self.assertEqual(set(occurrences), {"line:1", "line:3", "line:4"})
        pinned = builder.versions[occurrences["line:1"]["component_version_id"]]
        self.assertEqual(pinned["resolved_version"], "1.2.3")
        self.assertEqual(
            pinned["evidence"], ["app.py#L1", "app.py#line:1", "requirements.txt#L1"]
        )
        self.assertTrue(occurrences["line:3"]["optional"])
        export = occurrences["line:4"]
        self.assertIs(export["optional"], False)
        self.assertEqual(export["metadata"], {"distribution": "optimum"})
        self.assertEqual(
            builder.versions[export["component_version_id"]]["resolved_version"],
            "2.3.4",
        )
        self.assertEqual(gap_types(builder), {"script-dependency-pin-missing"})

    def test_add_workflow_manifest_install(self) -> None:
        """Bind tracked manifests and report untracked inputs as gaps."""
        data = b'{"name":"app","version":"1.2.3"}'
        self.write("app/package.json", data)
        self.write("ignored/package.json", data)
        self.track("app/package.json")
        builder, source, component, version = local_builder()
        self.assertIsNone(
            kr.add_workflow_manifest_install(
                builder,
                self.root,
                source,
                component,
                version,
                working_directory="app",
                locator="/steps/0",
            )
        )
        occurrence = only(builder.occurrences)
        installed = builder.versions[occurrence["component_version_id"]]
        self.assertEqual(installed["resolved_version"], "1.2.3")
        self.assertEqual(installed["evidence"], ["app/package.json"])
        self.assertEqual(installed["source_ref"], kr.file_hash(data))
        self.assertEqual(occurrence["raw_value"], "npm install:app/package.json")
        self.assertEqual(only(builder.edges)["relationship"], "installs-manifest")
        kr.add_workflow_manifest_install(
            builder,
            self.root,
            source,
            component,
            version,
            working_directory="ignored",
            locator="/steps/1",
        )
        self.assertEqual(len(builder.occurrences), 1)
        gap = only(builder.extra_gaps)
        self.assertEqual(gap["gap_type"], "github-actions-install-manifest-unresolved")
        self.assertIn("no readable package.json in ignored", gap["message"])


class ObservationTests(unittest.TestCase):
    """Build in-memory registry observations from minimal source payloads."""

    def test_add_model_artifact_observation(self) -> None:
        """Persist immutable model identity, lineage, and unresolved mutable refs."""
        builder, source, component, version = local_builder()
        revision = "b" * 40
        kwargs = {
            "ecosystem": "huggingface",
            "identity": "example/app",
            "name": "app",
            "locator": "/model",
            "raw_value": "example/app",
            "role": "fixture-model",
        }
        model, pinned, occurrence = kr.add_model_artifact_observation(
            builder,
            source,
            component,
            version,
            **kwargs,
            revision=revision,
            artifact_digest=DIGEST,
            lineage_required=True,
        )
        metadata = {
            "artifact_identity": "example/app",
            "lineage_required": True,
            "lineage_evidence": ["input.json#/model"],
        }
        self.assertEqual(builder.components[model]["metadata"], metadata)
        self.assertEqual(builder.versions[pinned]["artifact_digest"], DIGEST)
        self.assertEqual(builder.versions[pinned]["resolved_version"], revision)
        self.assertEqual(builder.versions[pinned]["resolution_state"], "resolved")
        self.assertEqual(builder.occurrences[occurrence]["metadata"], metadata)
        self.assertEqual(only(builder.edges)["relationship"], "uses-model-artifact")
        self.assertEqual(gap_types(builder), set())

        _, unpinned, _ = kr.add_model_artifact_observation(
            builder,
            source,
            component,
            version,
            **kwargs,
            revision="main",
        )
        self.assertEqual(builder.versions[unpinned]["resolution_state"], "unresolved")
        self.assertEqual(
            builder.versions[unpinned]["constraint"],
            "immutable-revision-or-hash-required",
        )
        self.assertEqual(
            gap_types(builder),
            {
                "model-artifact-integrity-unresolved",
                "model-artifact-revision-unresolved",
            },
        )

    def test_add_model_artifact_observation_resolves_revision_without_digest(
        self,
    ) -> None:
        """Resolve an immutable revision when no digest is supplied."""
        builder, source, component, version = local_builder()
        revision = "b" * 40
        _, revision_only, _ = kr.add_model_artifact_observation(
            builder,
            source,
            component,
            version,
            ecosystem="huggingface",
            identity="example/app",
            name="app",
            locator="/model",
            raw_value="example/app",
            role="fixture-model",
            revision=revision,
        )
        revision_row = builder.versions[revision_only]
        self.assertEqual(revision_row["resolved_version"], revision)
        self.assertNotIn("artifact_digest", revision_row)
        self.assertEqual(revision_row["resolution_state"], "resolved")

    def test_json_walk(self) -> None:
        """Yield sorted object keys and escape pointer tokens while preserving list order."""
        payload = {"z": None, "a/b~": [1, {"x": False}]}
        self.assertEqual(
            list(kr.json_walk(payload)),
            [
                ("/", payload),
                ("/a~1b~0", [1, {"x": False}]),
                ("/a~1b~0/0", 1),
                ("/a~1b~0/1", {"x": False}),
                ("/a~1b~0/1/x", False),
                ("/z", None),
            ],
        )
        self.assertEqual(list(kr.json_walk([], "/prefix")), [("/prefix", [])])
        singleton = [{"x": False}]
        self.assertEqual(
            list(kr.json_walk(singleton)),
            [("/", singleton), ("/0", {"x": False}), ("/0/x", False)],
        )

    def test_enforce_exact_live_projection(self) -> None:
        """Accept exact server versions and refuse extra fields or unsupported types."""
        payload = {"serverVersion": {"gitVersion": "v1.2.3"}}
        self.assertIsNone(
            kr.enforce_exact_live_projection(payload, "server-version", live)
        )
        resources = {
            "apiVersion": "v1",
            "kind": "APIResourceList",
            "groupVersion": "widgets.example.org/v1",
            "resources": [{"name": "widgets", "kind": "Widget", "namespaced": False}],
        }
        self.assertIsNone(
            kr.enforce_exact_live_projection(resources, "APIResourceList", live)
        )
        with self.assertRaisesRegex(
            kr.RegistryInputError, "not the exact identity-only projection"
        ):
            kr.enforce_exact_live_projection(
                {**payload, "extra": "ignored"}, "server-version", live
            )
        with self.assertRaisesRegex(kr.RegistryInputError, "unsupported document type"):
            kr.enforce_exact_live_projection(payload, "unknown", live)

    def test_import_api_resource_list(self) -> None:
        """Emit one typed resource and flag a non-object with its pointer."""
        builder, source = source_builder()
        group_version = "widgets.example.org/v1"
        payload = {
            "groupVersion": group_version,
            "resources": [
                {
                    "name": "widgets",
                    "kind": "Widget",
                    "namespaced": False,
                    "storageVersionHash": "example-storage-hash",
                },
                "invalid",
            ],
        }
        self.assertIsNone(
            kr.import_api_resource_list(
                builder, source, payload, endpoint="/apis/widgets.example.org/v1"
            )
        )
        occurrence = only(builder.occurrences)
        self.assertEqual(occurrence["evidence_locator"], "/resources/0")
        self.assertEqual(occurrence["raw_value"], f"{group_version}/widgets:Widget")
        version = only(builder.versions)
        self.assertEqual(version["metadata"]["api_resource_name"], "widgets")
        self.assertIs(version["metadata"]["namespaced"], False)
        self.assertEqual(
            version["metadata"]["storage_version_hash"], "example-storage-hash"
        )
        gap = only(builder.extra_gaps)
        self.assertEqual(gap["gap_type"], "live-api-discovery-invalid")
        self.assertEqual(gap["evidence"], ["input.json#/resources/1"])
        self.assertIn("non-object resource", gap["message"])

    def test_import_openapi_v3_document(self) -> None:
        """Count only complete kinds and retain each schema's escaped evidence pointer."""
        builder, source = source_builder()
        schema = {
            "type": "object",
            "x-kubernetes-group-version-kind": [
                {"group": "", "version": "v1", "kind": "Widget"},
                {"group": "", "kind": "Incomplete"},
            ],
        }
        payload = {
            "openapi": "3.0.0",
            "components": {
                "schemas": {
                    "example/item": schema,
                    "example/alternate": {
                        "type": "object",
                        "x-kubernetes-group-version-kind": [
                            {"group": "", "version": "v1", "kind": "Alternate"}
                        ],
                    },
                }
            },
        }
        self.assertEqual(
            kr.import_openapi_v3_document(
                builder, source, payload, endpoint="/openapi/v3/api/v1"
            ),
            2,
        )
        first, second = builder.occurrences.values()
        self.assertEqual(first["raw_value"], "core/v1/Alternate")
        self.assertEqual(second["raw_value"], "core/v1/Widget")
        version = builder.versions[second["component_version_id"]]
        self.assertEqual(
            version["artifact_digest"], kr.file_hash(kr.canonical_json(schema).encode())
        )
        self.assertEqual(
            version["evidence"], ["input.json#/components/schemas/example~1item"]
        )
        self.assertEqual(
            kr.import_openapi_v3_document(builder, source, {}, endpoint="/openapi/v3"),
            0,
        )

    def test_import_crd_item(self) -> None:
        """Link named CRD versions to their defining object and schema digest."""
        builder, source = source_builder()
        schema = {"openAPIV3Schema": {"type": "object"}}
        payload = {
            "metadata": {"name": "widgets.example.org", "uid": "example-id"},
            "spec": {
                "group": "example.org",
                "names": {"kind": "Widget"},
                "versions": [
                    {},
                    {"name": "v1", "schema": schema, "served": True, "storage": False},
                ],
            },
        }
        self.assertIsNone(kr.import_crd_item(builder, source, payload, 2))
        occurrence = only(builder.occurrences)
        self.assertEqual(occurrence["evidence_locator"], "/items/2/spec/versions/1")
        self.assertEqual(occurrence["raw_value"], "example.org/v1/Widget")
        edge = only(builder.edges)
        self.assertEqual(edge["relationship"], "defines-api")
        self.assertEqual(
            builder.versions[edge["from_component_version_id"]]["source_ref"],
            "example-id",
        )
        version = builder.versions[occurrence["component_version_id"]]
        self.assertEqual(
            version["artifact_digest"], kr.file_hash(kr.canonical_json(schema).encode())
        )
        self.assertIs(version["metadata"]["served"], True)
        self.assertIs(version["metadata"]["storage"], False)

    def test_import_argo_item(self) -> None:
        """Prefer observed Helm revisions and flag source and revision count drift."""
        builder, source = source_builder()
        item = {
            "metadata": {"name": "app"},
            "spec": {
                "source": {
                    "repoURL": "https://charts.example.org",
                    "chart": "app",
                    "targetRevision": "1.2.3",
                }
            },
            "status": {"operationState": {"syncResult": {"revision": "1.2.4"}}},
        }
        self.assertIsNone(kr.import_argo_item(builder, source, item, 3))
        occurrences = {row["role"]: row for row in fixture_rows(builder.occurrences)}
        parent = occurrences["live-argo-application"]
        child = occurrences["live-argo-helm-source"]
        self.assertEqual(parent["raw_value"], "argocd/app")
        self.assertEqual(child["evidence_locator"], "/items/3/spec/source")
        version = builder.versions[child["component_version_id"]]
        self.assertEqual(
            (version["resolved_version"], version["constraint"]), ("1.2.4", "1.2.3")
        )
        self.assertEqual(
            only(builder.edges)["metadata"], {"observed_revision": "1.2.4"}
        )
        self.assertEqual(gap_types(builder), set())

        item["status"]["sync"] = {"revisions": ["1.2.4", "1.2.5"]}
        bad, bad_source = source_builder()
        kr.import_argo_item(bad, bad_source, item, 3)
        gap = only(bad.extra_gaps)
        self.assertEqual(gap["gap_type"], "argo-revision-cardinality")
        self.assertIn("1 sources but 2 observed revisions", gap["message"])


def policy_entry(template: str = CHANNEL_URI) -> Record:
    """Build a policy with one available channel."""
    return {
        "record": {
            "record_id": "fixture-policy",
            "scope": {"ecosystem": "pypi"},
            "review": {"reviewed_at": OBSERVED},
            "channels": [
                {
                    "channel_type": kr.OFFICIAL_CHANNEL_TYPES[0],
                    "disposition": "available",
                    "uri_template": template,
                }
            ],
        },
        "citation": f"policy.json@{DIGEST}",
        "sha256": DIGEST,
        "path": "policy.json",
        "preconditions": (),
    }


def package_builder(
    *,
    required: bool = True,
    observed: str = "1.2.3",
) -> tuple[kr.Builder, str, str]:
    """Build a package and one version with stable fixture evidence."""
    builder = kr.Builder()
    component = builder.add_component(
        kind="library",
        ecosystem="pypi",
        name="app",
        purl="pkg:pypi/app",
        official_channel_required=required,
    )
    version = builder.add_version(
        component, resolved_version=observed, evidence=("input.json",)
    )
    return builder, component, version


class ChannelRecordTests(unittest.TestCase):
    """Build reviewed channel and version records from in-memory policies."""

    def test_derived_channel(self) -> None:
        """Render available template channels and degrade unresolved templates."""
        builder, component, _ = package_builder()
        entry = policy_entry("https://example.org/{name}")
        record = kr.derived_component_record(
            entry, builder.components[component], "pkg:pypi/app", "baseline", None
        )
        (channel,) = record["channels"]
        self.assertEqual(
            channel,
            {
                "channel_id": f"chn:fixture-policy:{component}:{kr.OFFICIAL_CHANNEL_TYPES[0]}",
                "component_id": component,
                "channel_type": kr.OFFICIAL_CHANNEL_TYPES[0],
                "publisher": None,
                "access": "public",
                "rights": None,
                "refresh_policy": "on-version-change",
                "discovery_method": "generated",
                "confidence": "medium",
                "review_state": "accepted",
                "evidence": ["pkg:pypi/app", entry["citation"]],
                "availability_state": "available",
                "canonical_uri": CHANNEL_URI,
                "version_strategy": "per-version",
                "gap": None,
            },
        )

        entry["record"]["channels"][0]["uri_template"] = "https://example.org/{missing}"
        record = kr.derived_component_record(
            entry, builder.components[component], "pkg:pypi/app", "baseline", None
        )
        (channel,) = record["channels"]
        self.assertIsNone(channel["canonical_uri"])
        self.assertEqual(channel["availability_state"], "unresolved")
        self.assertEqual(
            channel["gap"],
            {
                "state": "unresolved",
                "reason": "uri-template-unrenderable: https://example.org/{missing}",
                "blocking": False,
                "evidence": [entry["citation"]],
                "next_action": "probe-wave",
            },
        )

    def test_derived_channel_cites_rendered_uri_in_gap(self) -> None:
        """Cite a renderable URI that still needs verification."""
        builder, component, _ = package_builder()
        entry = policy_entry("https://example.org/{name}")
        spec = entry["record"]["channels"][0]
        spec.update(
            disposition="derived-unverified",
            gap_reason="pending verification",
        )
        record = kr.derived_component_record(
            entry, builder.components[component], "pkg:pypi/app", "baseline", None
        )
        (channel,) = record["channels"]
        self.assertEqual(
            channel["gap"],
            {
                "state": "unresolved",
                "reason": "pending verification",
                "blocking": False,
                "evidence": [f"derived-uri:{CHANNEL_URI}", entry["citation"]],
                "next_action": "probe-wave",
            },
        )

    def test_component_table_channel(self) -> None:
        """Carry catalog provenance into available channels and explicit gaps."""
        builder, component, _ = package_builder()
        entry = policy_entry()
        entry["record"]["tables"] = {
            kr.CHANNEL_POLICY_PROVENANCE_TABLE: {
                "fixture": "https://example.net/catalog"
            },
        }
        row = {
            "channel_type": kr.OFFICIAL_CHANNEL_TYPES[0],
            "disposition": "available",
            "canonical_uri": CHANNEL_URI,
            "provenance": {"pass": "2", "refs": ["fixture", "missing"]},
            "probe": {"status": 200, "final_url": CHANNEL_URI},
        }
        record = kr.derived_component_record(
            entry,
            builder.components[component],
            "pkg:pypi/app",
            "baseline",
            None,
            row_set={"channels": [row]},
        )
        (channel,) = record["channels"]
        self.assertEqual(channel["discovery_method"], "inferred")
        self.assertEqual(channel["version_strategy"], "catalog-only")
        self.assertEqual(channel["canonical_uri"], CHANNEL_URI)
        self.assertEqual(
            channel["evidence"],
            sorted(
                [
                    "https://example.net/catalog",
                    "pkg:pypi/app",
                    entry["citation"],
                    f"probe:200:{CHANNEL_URI}",
                    "research-pass:2",
                ]
            ),
        )

        row.update(disposition="unresolved", reason="catalog unavailable")
        record = kr.derived_component_record(
            entry,
            builder.components[component],
            "pkg:pypi/app",
            "baseline",
            None,
            row_set={"channels": [row]},
        )
        (channel,) = record["channels"]
        self.assertIsNone(channel["canonical_uri"])
        self.assertEqual(channel["gap"]["reason"], "catalog unavailable")
        self.assertEqual(channel["gap"]["next_action"], "probe-wave")

    def test_derived_component_record(self) -> None:
        """Stamp the policy and strip fragment suffixes from document template values."""
        builder, component, _ = package_builder()
        entry = policy_entry("{evidence_document}")
        live_pointer = "live-export:fixture.json#/items/0"
        component_row = {**builder.components[component], "namespace": "example"}
        record = kr.derived_component_record(
            entry,
            component_row,
            "pkg:pypi/app",
            "baseline",
            "input.json",
            live_pointer,
        )
        self.assertEqual(record["record_id"], f"record:fixture-policy:{component}")
        self.assertEqual(
            record["review"],
            {
                "status": "accepted",
                "reviewed_by": f"{kr.CHANNEL_POLICY_REVIEWER_PREFIX}fixture-policy@{DIGEST}",
                "reviewed_at": OBSERVED,
                "evidence": ["baseline:baseline", entry["citation"]],
            },
        )
        self.assertEqual(record["component"]["registry_identity"], "pkg:pypi/app")
        self.assertEqual(record["component"]["namespace"], "example")
        self.assertEqual(record["component"]["registry_kind"], "library")
        self.assertEqual(record["component"]["kind"], "library")
        self.assertEqual((record["versions"], record["snapshots"]), ([], []))
        (channel,) = record["channels"]
        self.assertEqual(channel["canonical_uri"], "live-export:fixture.json")
        self.assertEqual(
            channel["evidence"],
            sorted(
                [
                    "input.json",
                    live_pointer,
                    "pkg:pypi/app",
                    entry["citation"],
                ]
            ),
        )

    def test_snapshot_reviewed_version_entry(self) -> None:
        """Skip digestless resolved images and select the next expressible version."""
        component = "cmp-fixture"
        version = {
            "component_version_id": "ver-fixture",
            "resolution_state": "resolved",
            "resolved_version": "1.2.3",
            "artifact_digest": DIGEST,
            "platform": "linux/amd64",
            "evidence": ["z.json", "a.json", "a.json"],
            "metadata": {"observed_at": "invalid"},
        }
        selected = kr.snapshot_reviewed_version_entry(
            component,
            [
                {**version, "component_version_id": "ver-later"},
                {
                    **version,
                    "component_version_id": "ver-earlier",
                    "artifact_digest": None,
                },
                version,
            ],
            OBSERVED,
            ecosystem="oci",
            kind="image",
        )
        self.assertEqual(
            selected,
            {
                "component_version_id": "ver-fixture",
                "component_id": component,
                "purl": None,
                "constraint": None,
                "resolved_version": "1.2.3",
                "source_ref": None,
                "artifact_digest": DIGEST,
                "platform": "linux/amd64",
                "build_metadata": {},
                "release_time": None,
                "observed_at": OBSERVED,
                "valid_from": None,
                "valid_to": None,
                "resolution_state": "resolved",
                "evidence": ["a.json", "z.json"],
            },
        )
        self.assertIsNone(
            kr.snapshot_reviewed_version_entry(
                component,
                [{**version, "artifact_digest": None}],
                OBSERVED,
                ecosystem="oci",
                kind="image",
            )
        )


class ManifestFixtureTestCase(FilesTestCase):
    """Patch the registry's __file__ and draft202012_validator for fixture manifests."""

    def setUp(self) -> None:
        """Isolate generator files and the schema engine from behavioral tests."""
        super().setUp()
        generator = self.write(kr.GENERATOR_SOURCE_REF, "# fixture generator\n")
        self.write(kr.DISCOVERY_SCHEMA_RELATIVE, "{}")
        self.enterContext(patch.object(kr, "__file__", str(generator)))
        validator = Mock()
        validator.iter_errors.return_value = ()
        self.enterContext(
            patch.object(kr, "draft202012_validator", return_value=validator)
        )

    def receipt(self, uri: str, subject: str, data: bytes) -> Record:
        """Store receipt bytes under their digest and return a receipt row."""
        content_hash = "sha256:" + hashlib.sha256(data).hexdigest()
        cas_path = f"cas/{content_hash[7:]}"
        self.write(cas_path, data)
        return {
            "canonical_uri": uri,
            "resolved_uri": uri,
            "channel_ids": [subject],
            "observed_at": OBSERVED,
            "fetched_at": OBSERVED,
            "content_hash": content_hash,
            "cas_path": cas_path,
            "status": "verified",
        }

    def write_receipts(self, *rows: Record) -> None:
        """Write the receipt JSONL consumed by registry binders."""
        if len(rows) > MAX_FIXTURE_ROWS:
            raise AssertionError(
                f"receipt batch exceeds {MAX_FIXTURE_ROWS} fixture rows"
            )
        self.write(
            "receipts/input.jsonl", "".join(json.dumps(row) + "\n" for row in rows)
        )

    def snapshot_fixture(self) -> tuple[Record, Record, str, str]:
        """Create one accepted channel and its bindable package version."""
        builder, component, version = package_builder()
        record = kr.derived_component_record(
            policy_entry(),
            builder.components[component],
            "pkg:pypi/app",
            "baseline",
            "input.json",
        )
        (channel,) = record["channels"]
        builder.components[component]["official_channels"] = [channel]
        return builder.manifest(), record, str(channel["channel_id"]), version

    def oci_receipt(self, version: str, architecture: str) -> Record:
        """Write single-platform OCI manifest and config bytes with matching digests."""
        config = json.dumps({"os": "linux", "architecture": architecture}).encode()
        config_hash = "sha256:" + hashlib.sha256(config).hexdigest()
        config_path = f"cas/{config_hash[7:]}"
        self.write(config_path, config)
        data = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": OCI_MEDIA,
                "config": {"digest": config_hash},
                "layers": [],
            }
        ).encode()
        row = self.receipt(OCI_URI, version, data)
        row["media_type"] = OCI_MEDIA
        row["coordinates"] = {
            "oci": {
                "registry": OCI_REGISTRY,
                "repository": OCI_REPOSITORY,
                "reference": "1.2.3",
                "reference_kind": "tag",
                "resolved_digest": row["content_hash"],
                "kind": "manifest",
                "config_content_hash": config_hash,
                "config_cas_path": config_path,
                "platforms": [f"linux/{architecture}"],
                "children": [],
                "excluded": [],
            }
        }
        return row


class ChannelWaveTests(ManifestFixtureTestCase):
    """Build channel policy waves, snapshot receipts, and comparison manifests."""

    def test_derive_channel_records(self) -> None:
        """Emit matching records and samples and skip failed preconditions."""
        builder, component, _ = package_builder()
        baseline = builder.manifest()
        entry = policy_entry()
        records, samples, summary = kr.derive_channel_records(baseline, [entry])
        ((identifier, record),) = records
        self.assertEqual(identifier, component)
        self.assertEqual(record["channels"][0]["canonical_uri"], CHANNEL_URI)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(
            summary["expected_accepted_slots_delta"], len(kr.OFFICIAL_CHANNEL_TYPES)
        )
        ((name, sample),) = samples
        self.assertEqual(name, "sample-pypi.json")
        self.assertEqual(sample["policy_path"], "policy.json")
        self.assertEqual(
            sample["entries"],
            [
                {
                    "component_id": component,
                    "name": "app",
                    "purl": "pkg:pypi/app",
                    "channels": [
                        {
                            "channel_type": kr.OFFICIAL_CHANNEL_TYPES[0],
                            "availability_state": "available",
                            "canonical_uri": CHANNEL_URI,
                        }
                    ],
                }
            ],
        )

        entry["preconditions"] = [("name", re.compile("^other$"))]
        records, _, summary = kr.derive_channel_records(baseline, [entry])
        self.assertEqual(records, [])
        self.assertEqual(summary["skipped"], {"precondition-mismatch": 1})
        with self.assertRaisesRegex(
            kr.RegistryInputError, "derive-channels baseline is invalid"
        ):
            kr.derive_channel_records({}, [entry])

    def test_channel_wave_gate(self) -> None:
        """Check the declared wave size and reject a component delta."""
        builder, _, _ = package_builder()
        baseline = builder.manifest()
        accepted = kr.channel_wave_gate(
            baseline, baseline, policies=[], expected_matched=0
        )
        self.assertIs(accepted["pass"], True)
        refused = kr.channel_wave_gate(
            baseline, baseline, policies=[], expected_matched=1
        )
        self.assertIs(refused["pass"], False)
        self.assertEqual(
            refused["checks"]["accepted-slots"],
            {
                "pass": False,
                "baseline": 0,
                "merged": 0,
                "delta": 0,
                "expected_delta": 0,
                "policy_stamped_components": 0,
                "baseline_policy_stamped_components": 0,
                "wave_policy_stamped_components": 0,
                "reclassified_accepted_slots": 0,
                "expected_matched": 1,
            },
        )

        added = builder.add_component(
            kind="library",
            ecosystem="pypi",
            name="other",
            purl="pkg:pypi/other",
            official_channel_required=False,
        )
        changed = kr.channel_wave_gate(
            baseline, builder.manifest(), policies=[], expected_matched=0
        )
        self.assertIs(changed["pass"], False)
        self.assertEqual(
            changed["checks"]["zero-new-components"],
            {"pass": False, "new_component_ids": [added], "removed_component_ids": []},
        )

    def test_bind_channel_snapshot_receipts(self) -> None:
        """Bind verified CAS bytes and report receipts for unknown channels."""
        baseline, record, channel, version = self.snapshot_fixture()
        component = record["component"]["component_id"]
        row = self.receipt(CHANNEL_URI, channel, b"fixture snapshot\n")
        other = {**row, "channel_ids": ["chn:other"]}
        self.write_receipts(row, other)
        summary = kr.bind_channel_snapshot_receipts(
            [(component, record)], baseline, str(self.root)
        )
        self.assertEqual(
            summary,
            {
                "receipts_dir": self.root.as_posix(),
                "receipt_rows": 2,
                "receipt_rows_rejected": 0,
                "rejected_receipts": [],
                "channels_receipted": 2,
                "channels_bound": 1,
                "bound_channel_ids_digest": kr.digest_ids([channel]),
                "channels_unbound": [
                    {
                        "channel_id": "chn:other",
                        "reason": "input.jsonl:2: receipt does not match a derived available channel",
                    }
                ],
            },
        )
        (snapshot,) = record["snapshots"]
        self.assertEqual(snapshot["component_version_id"], version)
        self.assertEqual(
            snapshot["snapshot_id"], f"snap:{channel}:{row['content_hash'][7:19]}"
        )
        self.assertEqual(snapshot["content_hash"], row["content_hash"])
        self.assertEqual(record["versions"][0]["observed_at"], OBSERVED)

    def test_bind_channel_snapshot_receipts_rejects_uri_mismatch(self) -> None:
        """Refuse a verified receipt with a known channel ID and a different URI."""
        baseline, record, channel, _ = self.snapshot_fixture()
        component = record["component"]["component_id"]
        row = self.receipt("https://example.net/app", channel, b"fixture snapshot\n")
        self.write_receipts(row)
        summary = kr.bind_channel_snapshot_receipts(
            [(component, record)], baseline, str(self.root)
        )
        self.assertEqual(summary["receipt_rows_rejected"], 0)
        self.assertEqual(summary["channels_bound"], 0)
        self.assertEqual(
            summary["channels_unbound"],
            [
                {
                    "channel_id": channel,
                    "reason": "input.jsonl:1: receipt canonical_uri does not match the channel",
                }
            ],
        )
        self.assertEqual(record["snapshots"], [])

    def test_channel_snapshot_gate(self) -> None:
        """Require a traced snapshot for each bindable receipt."""
        baseline, record, channel, _ = self.snapshot_fixture()
        component = record["component"]["component_id"]
        row = self.receipt(CHANNEL_URI, channel, b"fixture snapshot\n")
        self.write_receipts(row)
        refused = kr.channel_snapshot_gate(
            baseline, baseline, receipts_dir=str(self.root)
        )
        self.assertIs(refused["pass"], False)
        self.assertEqual(
            refused["checks"]["snapshot-arithmetic"]["uncredited_expected"], [channel]
        )
        self.assertEqual(
            refused["checks"]["no-silent-drop"]["dropped_verified_channels"], [channel]
        )

        kr.bind_channel_snapshot_receipts(
            [(component, record)], baseline, str(self.root)
        )
        (original,) = baseline["components"]
        changed = {**original, "official_channel_snapshots": record["snapshots"]}
        merged = kr.seal_manifest({**baseline, "components": [changed]})
        accepted = kr.channel_snapshot_gate(
            baseline, merged, receipts_dir=str(self.root)
        )
        self.assertIs(accepted["pass"], True, accepted)
        self.assertEqual(
            accepted["checks"]["snapshot-arithmetic"]["credited_channels"], 1
        )
        self.assertEqual(
            accepted["checks"]["added-snapshots-trace"],
            {
                "pass": True,
                "added_snapshots": 1,
                "violations": [],
            },
        )

        added_builder, _, added_id = package_builder(observed="1.2.4")
        added = only(added_builder.versions)
        changed = kr.seal_manifest({**merged, "versions": [*merged["versions"], added]})
        drift = kr.channel_snapshot_gate(baseline, changed, receipts_dir=str(self.root))
        self.assertIs(drift["pass"], False)
        self.assertEqual(drift["checks"]["merged-valid"], {"pass": True, "errors": []})
        self.assertEqual(
            drift["checks"]["zero-new-versions"],
            {
                "pass": False,
                "versions": 2,
                "new_version_ids": [added_id],
                "removed_version_ids": [],
            },
        )


class IdentityTests(ManifestFixtureTestCase):
    """Build Git and OCI receipts and compare control, treatment, and anchor manifests."""

    def test_bind_gitops_identity(self) -> None:
        """Bind a verified commit to a mutable ref without reminting the version."""
        builder = kr.Builder()
        component = builder.add_component(
            kind="git-repository",
            ecosystem="git",
            name="self",
            identity="git:repository:self",
            metadata={"self_repository": True},
            official_channel_required=False,
        )
        version = builder.add_version(
            component, source_ref="main", evidence=("input.json",)
        )
        other = builder.add_component(
            kind="git-repository",
            ecosystem="git",
            name="other",
            identity="git:repository:other",
            metadata={"self_repository": False},
            official_channel_required=False,
        )
        builder.add_version(other, source_ref="main", evidence=("input.json",))
        baseline = builder.manifest()
        data = (
            f"tree {'a' * 40}\nauthor Example <app@example.org> 1767323045 +0000\n"
            "committer Example <app@example.org> 1767323045 +0000\n\nfixture\n"
        ).encode()
        commit = hashlib.sha1(f"commit {len(data)}\0".encode() + data).hexdigest()
        row = self.receipt(
            "https://git.example.org/example/app",
            f"chn:fixture:{component}:source",
            data,
        )
        row["channel_ids"].append(f"chn:fixture:{other}:source")
        row.update(media_type=kr.GITOPS_COMMIT_MEDIA_TYPE, upstream_ref=commit)
        self.write_receipts(row)
        fragment, summary = kr.bind_gitops_identity(
            baseline, str(self.root), observed_ref="MAIN"
        )
        self.assertEqual(summary["observed_ref"], "main")
        self.assertEqual(summary["commits"], [commit])
        self.assertEqual(summary["versions_bound"], 1)
        self.assertEqual(summary["skipped"], {"not-a-self-repository-component": 1})
        (bound,) = fragment["versions"]
        self.assertEqual(bound["component_version_id"], version)
        self.assertEqual(
            bound["metadata"][kr.GITOPS_OBSERVATION_KEY],
            {
                "evidence_cas_path": row["cas_path"],
                "evidence_content_hash": row["content_hash"],
                "observed_at": OBSERVED,
                "observed_commit": commit,
                "observed_ref": "main",
                "receipt_canonical_uri": row["canonical_uri"],
                "resolver": "git-commit-object-receipt",
            },
        )
        with self.assertRaisesRegex(kr.RegistryInputError, "is not a mutable ref"):
            kr.bind_gitops_identity(baseline, str(self.root), observed_ref=commit)

    def test_bind_oci_identity(self) -> None:
        """Bind OCI manifest identity and reject conflicting receipts for one tag."""
        builder, source = source_builder()
        _, version, _ = builder.add_image(
            f"{OCI_REGISTRY}/{OCI_REPOSITORY}:1.2.3", source, "/image", "fixture-image"
        )
        baseline = builder.manifest()
        row = self.oci_receipt(version, "amd64")
        newer = {**row, "observed_at": LATER, "fetched_at": LATER}
        self.write_receipts(newer, row)
        fragment, summary = kr.bind_oci_identity(baseline, str(self.root))
        self.assertEqual(summary["versions_bound"], 1)
        self.assertEqual(summary["planned_refs_unreceipted"], [])
        (bound,) = fragment["versions"]
        self.assertEqual(bound["component_version_id"], version)
        observation = bound["metadata"][kr.OCI_OBSERVATION_KEY]
        self.assertEqual(observation["resolved_digest"], row["content_hash"])
        self.assertEqual(observation["platforms"], ["linux/amd64"])
        self.assertEqual(observation["receipt_canonical_uri"], OCI_URI)
        self.assertEqual(observation["observed_at"], LATER)

        conflicting = self.oci_receipt(version, "arm64")
        self.write_receipts(row, conflicting)
        with self.assertRaisesRegex(
            kr.RegistryInputError, "disagree on the identity.*2 distinct manifests"
        ):
            kr.bind_oci_identity(baseline, str(self.root))

    def test_identity_gate(self) -> None:
        """Require every added version to appear in the expected plan."""
        builder, component, _ = package_builder(required=False)
        control = builder.manifest()
        new_version = builder.add_version(component, resolved_version="1.2.4")
        treatment = builder.manifest()
        self.write_receipts()
        refused = kr.identity_gate(
            control, treatment, receipts_dir=str(self.root), anchor=control
        )
        self.assertIs(refused["pass"], False)
        self.assertEqual(
            refused["checks"]["version-delta-justified"],
            {
                "pass": False,
                "versions": 2,
                "declared_new": 0,
                "declared_removed": 0,
                "undeclared_new_version_ids": [new_version],
                "undeclared_removed_version_ids": [],
            },
        )
        accepted = kr.identity_gate(
            control,
            treatment,
            receipts_dir=str(self.root),
            anchor=control,
            expected_plan={"expected_new_version_ids": [new_version]},
        )
        self.assertIs(accepted["pass"], True, accepted)
        self.assertEqual(
            accepted["checks"]["generation-anchored"]["anchor_manifest_id"],
            control["manifest_id"],
        )
        self.assertEqual(
            accepted["checks"]["version-delta-justified"]["undeclared_new_version_ids"],
            [],
        )

        anchor = kr.Builder().manifest()
        drift = kr.identity_gate(
            control,
            treatment,
            receipts_dir=str(self.root),
            anchor=anchor,
            expected_plan={"expected_new_version_ids": [new_version]},
        )
        self.assertIs(drift["pass"], False)
        self.assertEqual(
            drift["checks"]["generation-anchored"],
            {
                "pass": False,
                "anchor_manifest_id": anchor["manifest_id"],
                "control_identity_blocking": 0,
                "violations": ["control components differ from the anchor generation"],
            },
        )


class MergeTests(ManifestFixtureTestCase):
    """Build manifest candidates and conflicting records for strict merges."""

    def test_strict_merge_candidate_value(self) -> None:
        """Union evidence and keep the latest timestamp while rejecting scalar conflicts."""
        left = {
            "evidence": ["z.json", "a.json"],
            "metadata": {"observed_at": LATER},
            "source_ref": "1.2.3",
        }
        right = {
            "evidence": ["b.json", "a.json"],
            "metadata": {"observed_at": OBSERVED},
            "source_ref": "1.2.3",
        }
        result = kr.strict_merge_candidate_record(
            "versions", "ver-fixture", left, right
        )
        self.assertEqual(
            result,
            {
                "evidence": ["a.json", "b.json", "z.json"],
                "metadata": {"observed_at": LATER},
                "source_ref": "1.2.3",
            },
        )
        self.assertEqual(
            kr.strict_merge_candidate_record("versions", "ver-fixture", right, left),
            result,
        )
        with self.assertRaisesRegex(
            kr.RegistryInputError,
            "merge conflict for versions record ver-fixture at /source_ref",
        ):
            kr.strict_merge_candidate_record(
                "versions", "ver-fixture", left, {**right, "source_ref": "1.2.4"}
            )

    def test_merge_manifests(self) -> None:
        """Produce deterministic merged evidence and lineage from temporal candidates."""
        builder, component, version = package_builder(required=False)
        older = kr.seal_manifest(
            {
                **builder.manifest(),
                "observation": {
                    "observed_at": OBSERVED,
                    "source_valid_at": OBSERVED,
                    "source_valid_time_basis": "git-commit-committer-time",
                },
            }
        )
        builder.add_version(
            component, resolved_version="1.2.3", evidence=("other.json",)
        )
        newer = kr.seal_manifest(
            {
                **builder.manifest(base_manifest_id=older["manifest_id"]),
                "observation": {**older["observation"], "observed_at": LATER},
            }
        )
        merged = kr.merge_manifests([newer, older])
        self.assertEqual(merged, kr.merge_manifests([older, newer]))
        self.assertEqual(merged["observation"], newer["observation"])
        self.assertEqual(
            merged["merge_lineage"],
            {
                "selection_policy": kr.MERGE_SELECTION_POLICY,
                "input_manifest_ids": sorted(
                    [older["manifest_id"], newer["manifest_id"]]
                ),
                "current_manifest_id": newer["manifest_id"],
                "previous_manifest_id": older["manifest_id"],
            },
        )
        (merged_version,) = merged["versions"]
        self.assertEqual(merged_version["component_version_id"], version)
        self.assertEqual(merged_version["evidence"], ["input.json", "other.json"])
        with self.assertRaisesRegex(
            kr.RegistryInputError, "merge requires at least one candidate manifest"
        ):
            kr.merge_manifests([])
        with self.assertRaisesRegex(
            kr.RegistryInputError, "merge input 1 is invalid: schema_version must equal"
        ):
            kr.merge_manifests([older, {**newer, "schema_version": "invalid"}])


class CommandTests(FilesTestCase):
    """Build temporary CLI paths and capture registry and live helper output."""

    def test_capture_live_main(self) -> None:
        """Reject a non-UTC observation time before capture opens any inputs."""
        output = self.root / "capture"
        args = [
            "--output-dir",
            str(output),
            "--kubeconfig",
            str(self.root / "unused.yaml"),
            "--git-commit",
            "a" * 40,
            "--observed-at",
            "2026-01-02",
        ]
        with (
            redirect_stdout(io.StringIO()) as stdout,
            redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(live.main(args), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "capture failed: observed-at must be an exact UTC second\n",
        )
        self.assertFalse(output.exists())

    def test_main(self) -> None:
        """Write canonical capabilities once and refuse an existing output file."""
        output = self.root / "capabilities.json"
        args = ["capabilities", "--output", str(output)]
        with (
            redirect_stdout(io.StringIO()) as stdout,
            redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(kr.main(args), 0)
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
        expected = {
            "allowed": [
                "discover-repo",
                "import-live",
                "import-reviewed",
                "merge",
                "derive-channels",
                "bind-identity",
                "bind-oci-identity",
                "wave-gate",
                "snapshot-gate",
                "identity-gate",
                "validate",
                "summarize",
                "coverage",
                "gaps",
            ],
            "network_access": False,
            "cluster_access": "read-only capture helper only",
            "source_acquisition": False,
            "source_admission": False,
            "retrieval_release": False,
            "signing": False,
            "pointer_mutation": False,
            "production_mutation": False,
        }
        original = output.read_bytes()
        self.assertEqual(json.loads(original), expected)
        self.assertEqual(original, (kr.canonical_json(expected) + "\n").encode())
        with redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(kr.main(args), 2)
        self.assertIn("output must be a fresh non-symlink file", stderr.getvalue())
        self.assertEqual(output.read_bytes(), original)

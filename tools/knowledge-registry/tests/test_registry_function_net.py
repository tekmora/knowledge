# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

import ast
import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from collections.abc import Callable, Mapping
from dataclasses import asdict
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import CodeType, ModuleType
from typing import Any
from unittest.mock import patch

TOOL_ROOT = Path(__file__).resolve().parents[1]


class RegistrySourceLoader(SourceFileLoader):
    """Load the exact named source without reading or creating bytecode files."""

    def get_code(self, fullname: str) -> CodeType:
        """Compile the source file named by the bound module spec."""
        path = self.get_filename(fullname)
        return self.source_to_code(self.get_data(path), path)


def load_module(
    tool_root: Path, stem: str, aliases: dict[str, ModuleType]
) -> ModuleType:
    """Execute one test module with temporary import bindings."""
    path = tool_root / f"{stem}.py"
    key = hashlib.sha256(str(tool_root).encode()).hexdigest()
    name = f"_registry_function_net_{key}_{stem}"
    loader = RegistrySourceLoader(name, str(path))
    spec = importlib.util.spec_from_file_location(name, path, loader=loader)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {name: module, **aliases}):
        spec.loader.exec_module(module)
    return module


def load_tool_modules(tool_root: Path) -> tuple[ModuleType, ModuleType]:
    """Load the registry and its capture helper from the same resolved root."""
    root = tool_root.resolve()
    registry = load_module(root, "knowledge_registry", {})
    capture = load_module(root, "capture_live", {"knowledge_registry": registry})
    return registry, capture


kr, live = load_tool_modules(TOOL_ROOT)

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


BIND_ARGUMENT_COUNT = 3
MAX_OUTPUT_TABLES = 8
OUTPUT_TABLES = (
    "sources",
    "components",
    "versions",
    "occurrences",
    "edges",
    "extra_gaps",
    "discovery_inputs",
    "node_platforms",
)


def observation_state(builder: kr.Builder) -> Record:
    """Keep the keys, full records, and insertion order of every builder table."""
    return {
        table: list(getattr(builder, table).items())
        for table in OUTPUT_TABLES[:MAX_OUTPUT_TABLES]
    }


def assert_output(
    case: unittest.TestCase, expected: str, value: Any, args: tuple[Any, ...]
) -> None:
    """Compare the complete return value and each caller-owned output collection."""
    if args and isinstance(args[0], kr.Builder):
        value = (value, observation_state(args[0]))
    elif args and isinstance(args[0], list) and len(args) == BIND_ARGUMENT_COUNT:
        value = (value, args[0])
    root = getattr(case, "root", None)
    if root is not None and "/__fixture_root__" in expected:
        escaped_root = (
            str(root).replace("\\", "\\\\").replace("'", "\\x27").replace('"', "\\x22")
        )
        expected = expected.replace("/__fixture_root__", escaped_root)
    case.assertEqual(value, ast.literal_eval(expected))


def check_output(
    case: unittest.TestCase,
    expected: dict[str, str],
    label: str,
    call: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Check the function result, complete error, and caller-owned state."""
    try:
        value = call(*args, **kwargs)
    except kr.RegistryInputError as exc:
        assert_output(case, expected[label], (type(exc).__name__, str(exc)), args)
        raise
    assert_output(case, expected[label], value, args)
    return value


EXPECTED: dict[str, str] = {
    "test_add_workflow_manifest_install.1": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-96798a62afd2f5a456064757', {'component_id': 'cmp-96798a62afd2f5a456064757', 'ecosystem': 'local', 'kind': 'fixture', 'lifecycles': ['repository-used'], 'name': 'input.json', 'namespace': '', 'official_channel_required': False, 'official_channels': []}), ('cmp-f97173ccf16a0fa3fe954c60', {'component_id': 'cmp-f97173ccf16a0fa3fe954c60', 'ecosystem': 'npm', 'kind': 'node-project', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-b5e5f51f6ef2c47aceaed9ef', {'component_id': 'cmp-96798a62afd2f5a456064757', 'component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'evidence': ['input.json'], 'resolution_state': 'resolved', 'source_ref': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}),
               ('ver-98289a24cf73e05fb9bddcbe', {'component_id': 'cmp-f97173ccf16a0fa3fe954c60', 'component_version_id': 'ver-98289a24cf73e05fb9bddcbe', 'evidence': ['app/package.json'], 'resolution_state': 'resolved', 'resolved_version': '1.2.3', 'source_ref': 'sha256:055f36abac1de416965362266ef0524f9a464b3c06f628cf546587d51779cf8c'})],
  'occurrences': [('occ-bda9a82b749007b4fbd88203', {'component_id': 'cmp-f97173ccf16a0fa3fe954c60', 'component_version_id': 'ver-98289a24cf73e05fb9bddcbe', 'dependency_scope': 'ci', 'directness': 'direct', 'evidence_locator': '/steps/0', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-bda9a82b749007b4fbd88203', 'optional': False, 'raw_value': 'npm install:app/package.json', 'role': 'github-actions-manifest-install', 'root_id': 'cmp-96798a62afd2f5a456064757', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-7afeb484016f94c632a3ac8f', {'edge_id': 'edge-7afeb484016f94c632a3ac8f', 'from_component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'optional': False, 'relationship': 'installs-manifest', 'resolver': 'github-actions', 'scope': 'ci', 'source_occurrence_id': 'occ-bda9a82b749007b4fbd88203', 'to_component_version_id': 'ver-98289a24cf73e05fb9bddcbe'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_add_workflow_manifest_install.2": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-96798a62afd2f5a456064757', {'component_id': 'cmp-96798a62afd2f5a456064757', 'ecosystem': 'local', 'kind': 'fixture', 'lifecycles': ['repository-used'], 'name': 'input.json', 'namespace': '', 'official_channel_required': False, 'official_channels': []}), ('cmp-f97173ccf16a0fa3fe954c60', {'component_id': 'cmp-f97173ccf16a0fa3fe954c60', 'ecosystem': 'npm', 'kind': 'node-project', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-b5e5f51f6ef2c47aceaed9ef', {'component_id': 'cmp-96798a62afd2f5a456064757', 'component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'evidence': ['input.json'], 'resolution_state': 'resolved', 'source_ref': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}),
               ('ver-98289a24cf73e05fb9bddcbe', {'component_id': 'cmp-f97173ccf16a0fa3fe954c60', 'component_version_id': 'ver-98289a24cf73e05fb9bddcbe', 'evidence': ['app/package.json'], 'resolution_state': 'resolved', 'resolved_version': '1.2.3', 'source_ref': 'sha256:055f36abac1de416965362266ef0524f9a464b3c06f628cf546587d51779cf8c'})],
  'occurrences': [('occ-bda9a82b749007b4fbd88203', {'component_id': 'cmp-f97173ccf16a0fa3fe954c60', 'component_version_id': 'ver-98289a24cf73e05fb9bddcbe', 'dependency_scope': 'ci', 'directness': 'direct', 'evidence_locator': '/steps/0', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-bda9a82b749007b4fbd88203', 'optional': False, 'raw_value': 'npm install:app/package.json', 'role': 'github-actions-manifest-install', 'root_id': 'cmp-96798a62afd2f5a456064757', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-7afeb484016f94c632a3ac8f', {'edge_id': 'edge-7afeb484016f94c632a3ac8f', 'from_component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'optional': False, 'relationship': 'installs-manifest', 'resolver': 'github-actions', 'scope': 'ci', 'source_occurrence_id': 'occ-bda9a82b749007b4fbd88203', 'to_component_version_id': 'ver-98289a24cf73e05fb9bddcbe'})],
  'extra_gaps': [('gap-80e80dc73696bd53b17326b4', {'evidence': ['input.json#/steps/1'], 'gap_id': 'gap-80e80dc73696bd53b17326b4', 'gap_type': 'github-actions-install-manifest-unresolved', 'message': 'npm install at /steps/1 has no readable package.json in ignored', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_scan_chart_lock.1": r"""(None,
 {'sources': [('src-035e3dcf3af885cdc940aaa6', {'content_hash': 'sha256:5d6b46ec9a4ede324b28f8732dd446bb861cce2789e6690bc196f4e282b3389d', 'evidence_uri': 'Chart.lock', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-035e3dcf3af885cdc940aaa6', 'source_type': 'helm-chart-lock'}),
              ('src-b836decc2466786191594c81', {'content_hash': 'sha256:8884eaf2869865cc8e8c9597073c498222381f5db083b58b498fa3577393d81e', 'evidence_uri': 'Chart.yaml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-b836decc2466786191594c81', 'source_type': 'helm-chart-metadata'})],
  'components': [('cmp-10e5b92b9c672353486d6b0d', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-a253a30045bfbe31e7bec233', {'component_id': 'cmp-a253a30045bfbe31e7bec233', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['repository-used'], 'metadata': {'chart_repository': 'https://charts.example.org'}, 'name': 'child', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-fa505e79446445b2bce533b0', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'component_version_id': 'ver-fa505e79446445b2bce533b0', 'evidence': ['Chart.yaml'], 'resolution_state': 'resolved', 'resolved_version': '2.0.0', 'source_ref': 'sha256:8884eaf2869865cc8e8c9597073c498222381f5db083b58b498fa3577393d81e'}), ('ver-974bf8da8def146365baba11', {'component_id': 'cmp-a253a30045bfbe31e7bec233', 'component_version_id': 'ver-974bf8da8def146365baba11', 'evidence': ['Chart.lock#L2'], 'resolution_state': 'resolved', 'resolved_version': '1.2.3'})],
  'occurrences': [('occ-ede445a90460c95cb1a8de8b', {'component_id': 'cmp-a253a30045bfbe31e7bec233', 'component_version_id': 'ver-974bf8da8def146365baba11', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': 'line:2:lock:0', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-ede445a90460c95cb1a8de8b', 'optional': False, 'raw_value': 'child@1.2.3', 'role': 'helm-locked-dependency', 'root_id': 'cmp-10e5b92b9c672353486d6b0d', 'source_id': 'src-035e3dcf3af885cdc940aaa6'})],
  'edges': [('edge-2f00007d5167c671caefaeac', {'constraint': '1.2.3', 'edge_id': 'edge-2f00007d5167c671caefaeac', 'from_component_version_id': 'ver-fa505e79446445b2bce533b0', 'optional': False, 'relationship': 'locks', 'resolver': 'helm-lock', 'scope': 'runtime', 'source_occurrence_id': 'occ-ede445a90460c95cb1a8de8b', 'to_component_version_id': 'ver-974bf8da8def146365baba11'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_scan_chart_lock.2": r"""(None,
 {'sources': [('src-035e3dcf3af885cdc940aaa6', {'content_hash': 'sha256:5d6b46ec9a4ede324b28f8732dd446bb861cce2789e6690bc196f4e282b3389d', 'evidence_uri': 'Chart.lock', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-035e3dcf3af885cdc940aaa6', 'source_type': 'helm-chart-lock'}),
              ('src-04b35e20b1ec627715465363', {'content_hash': 'sha256:67b3fc5c5f146761fe76135436d14ae3869aee6c935cff85dd8ef465c16d3078', 'evidence_uri': 'Chart.yaml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-04b35e20b1ec627715465363', 'source_type': 'helm-chart-metadata'})],
  'components': [('cmp-10e5b92b9c672353486d6b0d', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-a253a30045bfbe31e7bec233', {'component_id': 'cmp-a253a30045bfbe31e7bec233', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['repository-used'], 'metadata': {'chart_repository': 'https://charts.example.org'}, 'name': 'child', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-08e1970c0bb179bb7ffe6317', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'component_version_id': 'ver-08e1970c0bb179bb7ffe6317', 'evidence': ['Chart.yaml'], 'resolution_state': 'resolved', 'resolved_version': '2.0.0', 'source_ref': 'sha256:67b3fc5c5f146761fe76135436d14ae3869aee6c935cff85dd8ef465c16d3078'}), ('ver-974bf8da8def146365baba11', {'component_id': 'cmp-a253a30045bfbe31e7bec233', 'component_version_id': 'ver-974bf8da8def146365baba11', 'evidence': ['Chart.lock#L2'], 'resolution_state': 'resolved', 'resolved_version': '1.2.3'})],
  'occurrences': [('occ-ede445a90460c95cb1a8de8b', {'component_id': 'cmp-a253a30045bfbe31e7bec233', 'component_version_id': 'ver-974bf8da8def146365baba11', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': 'line:2:lock:0', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-ede445a90460c95cb1a8de8b', 'optional': False, 'raw_value': 'child@1.2.3', 'role': 'helm-locked-dependency', 'root_id': 'cmp-10e5b92b9c672353486d6b0d', 'source_id': 'src-035e3dcf3af885cdc940aaa6'})],
  'edges': [('edge-a5de9566f050f8374c659bf2', {'constraint': '^1.2.0', 'edge_id': 'edge-a5de9566f050f8374c659bf2', 'from_component_version_id': 'ver-08e1970c0bb179bb7ffe6317', 'optional': False, 'relationship': 'locks', 'resolver': 'helm-lock', 'scope': 'runtime', 'source_occurrence_id': 'occ-ede445a90460c95cb1a8de8b', 'to_component_version_id': 'ver-974bf8da8def146365baba11'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_scan_chart_lock.3": r"""(None,
 {'sources': [('src-22c3c9734cdd15e6a2998833', {'content_hash': 'sha256:4d840406bc73f4a8458f54af84744318ffa8470e76a50921351481d4563e24a9', 'evidence_uri': 'Chart.lock', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-22c3c9734cdd15e6a2998833', 'source_type': 'helm-chart-lock'}),
              ('src-b836decc2466786191594c81', {'content_hash': 'sha256:8884eaf2869865cc8e8c9597073c498222381f5db083b58b498fa3577393d81e', 'evidence_uri': 'Chart.yaml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-b836decc2466786191594c81', 'source_type': 'helm-chart-metadata'})],
  'components': [('cmp-10e5b92b9c672353486d6b0d', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-a253a30045bfbe31e7bec233', {'component_id': 'cmp-a253a30045bfbe31e7bec233', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['repository-used'], 'metadata': {'chart_repository': 'https://charts.example.org'}, 'name': 'child', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-fa505e79446445b2bce533b0', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'component_version_id': 'ver-fa505e79446445b2bce533b0', 'evidence': ['Chart.yaml'], 'resolution_state': 'resolved', 'resolved_version': '2.0.0', 'source_ref': 'sha256:8884eaf2869865cc8e8c9597073c498222381f5db083b58b498fa3577393d81e'}), ('ver-21334cc14822eec2921d4d2e', {'component_id': 'cmp-a253a30045bfbe31e7bec233', 'component_version_id': 'ver-21334cc14822eec2921d4d2e', 'evidence': ['Chart.lock#L2'], 'resolution_state': 'resolved', 'resolved_version': '1.2.4'})],
  'occurrences': [('occ-d8ccf5004f11125ef24debdb', {'component_id': 'cmp-a253a30045bfbe31e7bec233', 'component_version_id': 'ver-21334cc14822eec2921d4d2e', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': 'line:2:lock:0', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-d8ccf5004f11125ef24debdb', 'optional': False, 'raw_value': 'child@1.2.4', 'role': 'helm-locked-dependency', 'root_id': 'cmp-10e5b92b9c672353486d6b0d', 'source_id': 'src-22c3c9734cdd15e6a2998833'})],
  'edges': [('edge-76bffba006ac5f0d2a2fa388', {'constraint': '1.2.3', 'edge_id': 'edge-76bffba006ac5f0d2a2fa388', 'from_component_version_id': 'ver-fa505e79446445b2bce533b0', 'optional': False, 'relationship': 'locks', 'resolver': 'helm-lock', 'scope': 'runtime', 'source_occurrence_id': 'occ-d8ccf5004f11125ef24debdb', 'to_component_version_id': 'ver-21334cc14822eec2921d4d2e'})],
  'extra_gaps': [('gap-988b0da28eb47128b7e5e6f5', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'component_version_id': 'ver-fa505e79446445b2bce533b0', 'evidence': ['Chart.lock#L2'], 'gap_id': 'gap-988b0da28eb47128b7e5e6f5', 'gap_type': 'helm-lock-version-mismatch', 'message': "Chart.lock locks 'child' at '1.2.4', but Chart.yaml declares '1.2.3'", 'source_id': 'src-22c3c9734cdd15e6a2998833'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_scan_chart_lock.4": r"""(None,
 {'sources': [('src-f734a572e8640ef89ea076bc', {'content_hash': 'sha256:0df94ce5ec4b5512129e8547022f265ca59d05d1a16999f307bcd69b8f1b44c0', 'evidence_uri': 'Chart.lock', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-f734a572e8640ef89ea076bc', 'source_type': 'helm-chart-lock'}),
              ('src-b836decc2466786191594c81', {'content_hash': 'sha256:8884eaf2869865cc8e8c9597073c498222381f5db083b58b498fa3577393d81e', 'evidence_uri': 'Chart.yaml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-b836decc2466786191594c81', 'source_type': 'helm-chart-metadata'})],
  'components': [('cmp-10e5b92b9c672353486d6b0d', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-693e4f424eec09cf695e7d4e', {'component_id': 'cmp-693e4f424eec09cf695e7d4e', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['repository-used'], 'metadata': {'chart_repository': 'https://charts.example.net'}, 'name': 'child', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-fa505e79446445b2bce533b0', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'component_version_id': 'ver-fa505e79446445b2bce533b0', 'evidence': ['Chart.yaml'], 'resolution_state': 'resolved', 'resolved_version': '2.0.0', 'source_ref': 'sha256:8884eaf2869865cc8e8c9597073c498222381f5db083b58b498fa3577393d81e'}), ('ver-bed8ffbd0134b0f27014b1d8', {'component_id': 'cmp-693e4f424eec09cf695e7d4e', 'component_version_id': 'ver-bed8ffbd0134b0f27014b1d8', 'evidence': ['Chart.lock#L2'], 'resolution_state': 'resolved', 'resolved_version': '1.2.3'})],
  'occurrences': [('occ-cf795f86722bc2df0cdfb980', {'component_id': 'cmp-693e4f424eec09cf695e7d4e', 'component_version_id': 'ver-bed8ffbd0134b0f27014b1d8', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': 'line:2:lock:0', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-cf795f86722bc2df0cdfb980', 'optional': False, 'raw_value': 'child@1.2.3', 'role': 'helm-locked-dependency', 'root_id': 'cmp-10e5b92b9c672353486d6b0d', 'source_id': 'src-f734a572e8640ef89ea076bc'})],
  'edges': [('edge-82d2fca36945d9838dad39e2', {'constraint': '1.2.3', 'edge_id': 'edge-82d2fca36945d9838dad39e2', 'from_component_version_id': 'ver-fa505e79446445b2bce533b0', 'optional': False, 'relationship': 'locks', 'resolver': 'helm-lock', 'scope': 'runtime', 'source_occurrence_id': 'occ-cf795f86722bc2df0cdfb980', 'to_component_version_id': 'ver-bed8ffbd0134b0f27014b1d8'})],
  'extra_gaps': [('gap-2cc58fa55f1ff050369f22a7', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'component_version_id': 'ver-fa505e79446445b2bce533b0', 'evidence': ['Chart.lock#L2', 'Chart.yaml#L4'], 'gap_id': 'gap-2cc58fa55f1ff050369f22a7', 'gap_type': 'helm-lock-repository-mismatch', 'message': "Chart.lock locks 'child' from 'https://charts.example.net', declared as 'https://charts.example.org'", 'source_id': 'src-f734a572e8640ef89ea076bc'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_scan_codex_config.1": r"""(None,
 {'sources': [('src-44d5eb656d3b809441976981', {'content_hash': 'sha256:f38f255712959f2515e551e14c2795773a52817139cad07a91e197769e173a1b', 'evidence_uri': 'config.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-44d5eb656d3b809441976981', 'source_type': 'codex-config'})],
  'components': [('cmp-0e2047679351ff658356304a', {'component_id': 'cmp-0e2047679351ff658356304a', 'ecosystem': 'local', 'kind': 'codex-config', 'lifecycles': ['repository-used'], 'name': 'config.toml', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-b7dcdede2070f224392f4504', {'component_id': 'cmp-b7dcdede2070f224392f4504', 'ecosystem': 'mcp', 'kind': 'mcp-server-endpoint', 'lifecycles': ['repository-used'], 'metadata': {'endpoint': 'https://example.org/mcp'}, 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-a438b92c28eaf6733559ac7c', {'component_id': 'cmp-a438b92c28eaf6733559ac7c', 'ecosystem': 'mcp', 'kind': 'mcp-server-endpoint', 'lifecycles': ['repository-used'], 'metadata': {'endpoint': 'https://example.net/mcp'}, 'name': 'default', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-0bb09fc328b53f15fe2f2641', {'component_id': 'cmp-0e2047679351ff658356304a', 'component_version_id': 'ver-0bb09fc328b53f15fe2f2641', 'evidence': ['config.toml'], 'resolution_state': 'resolved', 'source_ref': 'sha256:f38f255712959f2515e551e14c2795773a52817139cad07a91e197769e173a1b'}),
               ('ver-e2ec6d2a35b494be99aaac53', {'component_id': 'cmp-b7dcdede2070f224392f4504', 'component_version_id': 'ver-e2ec6d2a35b494be99aaac53', 'evidence': ['config.toml#L1'], 'resolution_state': 'resolved', 'source_ref': 'sha256:f38f255712959f2515e551e14c2795773a52817139cad07a91e197769e173a1b'}),
               ('ver-ffd54fc02dfe4fe7940ccf28', {'component_id': 'cmp-a438b92c28eaf6733559ac7c', 'component_version_id': 'ver-ffd54fc02dfe4fe7940ccf28', 'evidence': ['config.toml#L6'], 'resolution_state': 'resolved', 'source_ref': 'sha256:f38f255712959f2515e551e14c2795773a52817139cad07a91e197769e173a1b'})],
  'occurrences': [('occ-138a5a109d7423aaa3357bc8',
                   {'component_id': 'cmp-b7dcdede2070f224392f4504', 'component_version_id': 'ver-e2ec6d2a35b494be99aaac53', 'dependency_scope': 'development', 'directness': 'direct', 'evidence_locator': 'line:1', 'lifecycle': 'repository-used', 'metadata': {'enabled': False, 'required': True, 'enabled_tools': ['read', 'write']}, 'occurrence_id': 'occ-138a5a109d7423aaa3357bc8', 'optional': False, 'raw_value': 'https://example.org/mcp', 'role': 'mcp-server-endpoint', 'root_id': 'cmp-0e2047679351ff658356304a', 'source_id': 'src-44d5eb656d3b809441976981'}),
                  ('occ-db4b052518d305c8e2c29d09', {'component_id': 'cmp-a438b92c28eaf6733559ac7c', 'component_version_id': 'ver-ffd54fc02dfe4fe7940ccf28', 'dependency_scope': 'development', 'directness': 'direct', 'evidence_locator': 'line:6', 'lifecycle': 'repository-used', 'metadata': {'enabled': True, 'required': False, 'enabled_tools': []}, 'occurrence_id': 'occ-db4b052518d305c8e2c29d09', 'optional': False, 'raw_value': 'https://example.net/mcp', 'role': 'mcp-server-endpoint', 'root_id': 'cmp-0e2047679351ff658356304a', 'source_id': 'src-44d5eb656d3b809441976981'})],
  'edges': [('edge-e2509f18211580300bfcdf40', {'edge_id': 'edge-e2509f18211580300bfcdf40', 'from_component_version_id': 'ver-0bb09fc328b53f15fe2f2641', 'metadata': {'enabled': False, 'required': True, 'enabled_tools': ['read', 'write']}, 'optional': False, 'relationship': 'configures', 'resolver': 'codex-config', 'scope': 'development', 'source_occurrence_id': 'occ-138a5a109d7423aaa3357bc8', 'to_component_version_id': 'ver-e2ec6d2a35b494be99aaac53'}),
            ('edge-7d1585911c31df8f2511746d', {'edge_id': 'edge-7d1585911c31df8f2511746d', 'from_component_version_id': 'ver-0bb09fc328b53f15fe2f2641', 'metadata': {'enabled': True, 'required': False, 'enabled_tools': []}, 'optional': False, 'relationship': 'configures', 'resolver': 'codex-config', 'scope': 'development', 'source_occurrence_id': 'occ-db4b052518d305c8e2c29d09', 'to_component_version_id': 'ver-ffd54fc02dfe4fe7940ccf28'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_scan_codex_config.2": r"""(None,
 {'sources': [('src-d0cb320485a81e8eac03f72a', {'content_hash': 'sha256:245843abef9e72e7efac30138a994bf6301e7e1d7d7042a33d42e863d2638811', 'evidence_uri': 'config.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-d0cb320485a81e8eac03f72a', 'source_type': 'codex-config'})],
  'components': [],
  'versions': [],
  'occurrences': [],
  'edges': [],
  'extra_gaps': [('gap-cdb6374cc219d4a1b9c92303', {'evidence': ['/__fixture_root__/config.toml'], 'gap_id': 'gap-cdb6374cc219d4a1b9c92303', 'gap_type': 'toml-invalid', 'message': 'Invalid initial character for a key part (at end of document)', 'source_id': 'src-d0cb320485a81e8eac03f72a'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_scan_containerd_hosts.1": r"""(None,
 {'sources': [('src-c6f32ee1d7580679c61395df', {'content_hash': 'sha256:fa06d50f5722c1460029bb3fcc517ffe75498986a42837ab350a6b9159fe84ff', 'evidence_uri': 'hosts.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-c6f32ee1d7580679c61395df', 'source_type': 'containerd-hosts'})],
  'components': [('cmp-bf447d20dea721e92f1f0db9', {'component_id': 'cmp-bf447d20dea721e92f1f0db9', 'ecosystem': 'local', 'kind': 'containerd-hosts', 'lifecycles': ['repository-used'], 'name': 'hosts.toml', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-46b2866a7f560d01e5a21285', {'component_id': 'cmp-46b2866a7f560d01e5a21285', 'ecosystem': 'oci-registry', 'kind': 'registry-endpoint', 'lifecycles': ['repository-used'], 'metadata': {'endpoint': 'https://registry.example.org'}, 'name': 'https://registry.example.org', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-1ceabc92035cd5e96035d3c2', {'component_id': 'cmp-1ceabc92035cd5e96035d3c2', 'ecosystem': 'oci-registry', 'kind': 'registry-endpoint', 'lifecycles': ['repository-used'], 'metadata': {'endpoint': 'https://mirror.example.org'}, 'name': 'https://mirror.example.org', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-83c9aa570551f951e003dec4', {'component_id': 'cmp-bf447d20dea721e92f1f0db9', 'component_version_id': 'ver-83c9aa570551f951e003dec4', 'evidence': ['hosts.toml'], 'resolution_state': 'resolved', 'source_ref': 'sha256:fa06d50f5722c1460029bb3fcc517ffe75498986a42837ab350a6b9159fe84ff'}),
               ('ver-f7a42635f12dc1ca86b539f5', {'component_id': 'cmp-46b2866a7f560d01e5a21285', 'component_version_id': 'ver-f7a42635f12dc1ca86b539f5', 'evidence': ['hosts.toml#L1'], 'resolution_state': 'resolved', 'source_ref': 'sha256:fa06d50f5722c1460029bb3fcc517ffe75498986a42837ab350a6b9159fe84ff'}),
               ('ver-941df3cee76f41ac79967191', {'component_id': 'cmp-1ceabc92035cd5e96035d3c2', 'component_version_id': 'ver-941df3cee76f41ac79967191', 'evidence': ['hosts.toml#L2'], 'resolution_state': 'resolved', 'source_ref': 'sha256:fa06d50f5722c1460029bb3fcc517ffe75498986a42837ab350a6b9159fe84ff'})],
  'occurrences': [('occ-97cfb10f2b093fe01e83921d', {'component_id': 'cmp-46b2866a7f560d01e5a21285', 'component_version_id': 'ver-f7a42635f12dc1ca86b539f5', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': 'line:1', 'lifecycle': 'repository-used', 'metadata': {'registry_server': True}, 'occurrence_id': 'occ-97cfb10f2b093fe01e83921d', 'optional': False, 'raw_value': 'https://registry.example.org', 'role': 'containerd-registry-server', 'root_id': 'cmp-bf447d20dea721e92f1f0db9', 'source_id': 'src-c6f32ee1d7580679c61395df'}),
                  ('occ-e3df28b1adda40faac902b49',
                   {'component_id': 'cmp-1ceabc92035cd5e96035d3c2', 'component_version_id': 'ver-941df3cee76f41ac79967191', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': 'line:2', 'lifecycle': 'repository-used', 'metadata': {'capabilities': ['pull'], 'override_path': True, 'skip_verify': False}, 'occurrence_id': 'occ-e3df28b1adda40faac902b49', 'optional': False, 'raw_value': 'https://mirror.example.org', 'role': 'containerd-registry-mirror', 'root_id': 'cmp-bf447d20dea721e92f1f0db9', 'source_id': 'src-c6f32ee1d7580679c61395df'})],
  'edges': [('edge-3b365d053d55d83ba766d4b4', {'edge_id': 'edge-3b365d053d55d83ba766d4b4', 'from_component_version_id': 'ver-83c9aa570551f951e003dec4', 'metadata': {'registry_server': True}, 'optional': False, 'relationship': 'configures', 'resolver': 'containerd-hosts', 'scope': 'deployment', 'source_occurrence_id': 'occ-97cfb10f2b093fe01e83921d', 'to_component_version_id': 'ver-f7a42635f12dc1ca86b539f5'}),
            ('edge-7a7bdf2adcad8f66316e1192', {'edge_id': 'edge-7a7bdf2adcad8f66316e1192', 'from_component_version_id': 'ver-83c9aa570551f951e003dec4', 'metadata': {'capabilities': ['pull'], 'override_path': True, 'skip_verify': False}, 'optional': False, 'relationship': 'routes-through', 'resolver': 'containerd-hosts', 'scope': 'deployment', 'source_occurrence_id': 'occ-e3df28b1adda40faac902b49', 'to_component_version_id': 'ver-941df3cee76f41ac79967191'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_scan_containerd_hosts.2": r"""(None,
 {'sources': [('src-ea9f055e935931a82d293c50', {'content_hash': 'sha256:5842c97e862ef11691b4bd3aebf57eb42aff22d9d6e2386fb7d8ce9cea37ee75', 'evidence_uri': 'hosts.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-ea9f055e935931a82d293c50', 'source_type': 'containerd-hosts'})],
  'components': [],
  'versions': [],
  'occurrences': [],
  'edges': [],
  'extra_gaps': [('gap-25751460c118371e37907db2', {'evidence': ['/__fixture_root__/hosts.toml'], 'gap_id': 'gap-25751460c118371e37907db2', 'gap_type': 'toml-invalid', 'message': 'Invalid value (at end of document)', 'source_id': 'src-ea9f055e935931a82d293c50'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_scan_pyproject.1": r"""(None,
 {'sources': [('src-aaa24686549db347ae21281c', {'content_hash': 'sha256:80ef73d9ed5fba18153aca5dc32e09c4cfc0a568489650576fdd297128dbe375', 'evidence_uri': 'pyproject.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-aaa24686549db347ae21281c', 'source_type': 'python-pyproject'})],
  'components': [('cmp-d9338ccdf165a0f8be71aa02', {'component_id': 'cmp-d9338ccdf165a0f8be71aa02', 'ecosystem': 'pypi', 'kind': 'python-project', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': [], 'purl': 'pkg:pypi/app'}),
                 ('cmp-16057b6621f6bbc3107663e7', {'component_id': 'cmp-16057b6621f6bbc3107663e7', 'ecosystem': 'python-toolchain', 'kind': 'language-toolchain', 'lifecycles': ['repository-used'], 'metadata': {'language': 'python'}, 'name': 'python', 'namespace': '', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:generic/python-toolchain'}),
                 ('cmp-3b610d576cae0def35a7cb37', {'component_id': 'cmp-3b610d576cae0def35a7cb37', 'ecosystem': 'python-toolchain', 'kind': 'standard-library', 'lifecycles': ['repository-used'], 'metadata': {'language': 'python', 'coupled_to_toolchain': True}, 'name': 'python-stdlib', 'namespace': '', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:generic/python-stdlib'}),
                 ('cmp-257fc68c98b4e395108581b2', {'component_id': 'cmp-257fc68c98b4e395108581b2', 'ecosystem': 'pypi', 'kind': 'library', 'lifecycles': ['repository-used'], 'name': 'example-dep', 'namespace': '', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:pypi/example-dep'})],
  'versions': [('ver-ce4b555ae08ed56184ed246a', {'component_id': 'cmp-d9338ccdf165a0f8be71aa02', 'component_version_id': 'ver-ce4b555ae08ed56184ed246a', 'evidence': ['pyproject.toml'], 'resolution_state': 'resolved', 'resolved_version': '1.2.3', 'source_ref': 'sha256:80ef73d9ed5fba18153aca5dc32e09c4cfc0a568489650576fdd297128dbe375'}),
               ('ver-9bf3c76ea001be386641821c', {'component_id': 'cmp-16057b6621f6bbc3107663e7', 'component_version_id': 'ver-9bf3c76ea001be386641821c', 'constraint': '>=3.11', 'evidence': ['pyproject.toml#line:6'], 'metadata': {'raw_toolchain_version': '>=3.11'}, 'resolution_state': 'partial'}), ('ver-729bda291bf45690811ec47f', {'component_id': 'cmp-3b610d576cae0def35a7cb37', 'component_version_id': 'ver-729bda291bf45690811ec47f', 'constraint': '>=3.11', 'evidence': ['pyproject.toml#line:6'], 'metadata': {'raw_toolchain_version': '>=3.11'}, 'resolution_state': 'partial'}),
               ('ver-795f58aea434ef6b37e4df99', {'component_id': 'cmp-257fc68c98b4e395108581b2', 'component_version_id': 'ver-795f58aea434ef6b37e4df99', 'constraint': '==2.3.4', 'evidence': ['pyproject.toml#line:5:column:17'], 'resolution_state': 'resolved', 'resolved_version': '2.3.4'})],
  'occurrences': [('occ-f84b4dd84779b3905c3290a6', {'component_id': 'cmp-16057b6621f6bbc3107663e7', 'component_version_id': 'ver-9bf3c76ea001be386641821c', 'dependency_scope': 'build', 'directness': 'direct', 'evidence_locator': 'line:6', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-f84b4dd84779b3905c3290a6', 'optional': False, 'raw_value': '>=3.11', 'role': 'python-requires-version', 'root_id': 'cmp-d9338ccdf165a0f8be71aa02', 'source_id': 'src-aaa24686549db347ae21281c'}),
                  ('occ-e4c55a731f4158a8a07c4e61', {'component_id': 'cmp-3b610d576cae0def35a7cb37', 'component_version_id': 'ver-729bda291bf45690811ec47f', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': 'line:6:stdlib', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-e4c55a731f4158a8a07c4e61', 'optional': False, 'raw_value': '>=3.11', 'role': 'python-standard-library', 'root_id': 'cmp-16057b6621f6bbc3107663e7', 'source_id': 'src-aaa24686549db347ae21281c'}),
                  ('occ-67180144d2c1f0681576d58a', {'component_id': 'cmp-257fc68c98b4e395108581b2', 'component_version_id': 'ver-795f58aea434ef6b37e4df99', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': 'line:5:column:17', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-67180144d2c1f0681576d58a', 'optional': True, 'raw_value': 'Example_Dep==2.3.4', 'role': 'pyproject-dependency', 'root_id': 'cmp-d9338ccdf165a0f8be71aa02', 'source_id': 'src-aaa24686549db347ae21281c'})],
  'edges': [('edge-acf0a5a2fbbd972301dea296', {'constraint': '>=3.11', 'edge_id': 'edge-acf0a5a2fbbd972301dea296', 'from_component_version_id': 'ver-ce4b555ae08ed56184ed246a', 'optional': False, 'relationship': 'requires-toolchain', 'resolver': 'toolchain-observation', 'scope': 'build', 'source_occurrence_id': 'occ-f84b4dd84779b3905c3290a6', 'to_component_version_id': 'ver-9bf3c76ea001be386641821c'}),
            ('edge-fcb4d95ca898676cf5e0f25d', {'constraint': '>=3.11', 'edge_id': 'edge-fcb4d95ca898676cf5e0f25d', 'from_component_version_id': 'ver-9bf3c76ea001be386641821c', 'optional': False, 'relationship': 'provides-standard-library', 'resolver': 'toolchain-observation', 'scope': 'runtime', 'source_occurrence_id': 'occ-e4c55a731f4158a8a07c4e61', 'to_component_version_id': 'ver-729bda291bf45690811ec47f'}),
            ('edge-127c08811dc00f053a9a73fa', {'constraint': '==2.3.4', 'edge_id': 'edge-127c08811dc00f053a9a73fa', 'from_component_version_id': 'ver-ce4b555ae08ed56184ed246a', 'optional': True, 'relationship': 'depends-on', 'resolver': 'python-manifest', 'scope': 'runtime', 'source_occurrence_id': 'occ-67180144d2c1f0681576d58a', 'to_component_version_id': 'ver-795f58aea434ef6b37e4df99'})],
  'extra_gaps': [('gap-3e692835043537cc37322962', {'component_id': 'cmp-16057b6621f6bbc3107663e7', 'component_version_id': 'ver-9bf3c76ea001be386641821c', 'evidence': ['pyproject.toml#line:6'], 'gap_id': 'gap-3e692835043537cc37322962', 'gap_type': 'toolchain-exact-version-unresolved', 'message': "python toolchain constraint '>=3.11' lacks an exact runtime version", 'metadata': {'language': 'python', 'surface': 'toolchain'}, 'source_id': 'src-aaa24686549db347ae21281c'}),
                 ('gap-1cc6ceadf8a5f1956ef82f22', {'component_id': 'cmp-3b610d576cae0def35a7cb37', 'component_version_id': 'ver-729bda291bf45690811ec47f', 'evidence': ['pyproject.toml#line:6'], 'gap_id': 'gap-1cc6ceadf8a5f1956ef82f22', 'gap_type': 'toolchain-exact-version-unresolved', 'message': "python standard library constraint '>=3.11' lacks an exact runtime version", 'metadata': {'language': 'python', 'surface': 'standard library'}, 'source_id': 'src-aaa24686549db347ae21281c'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_scan_script_dependencies.1": r"""(None,
 {'sources': [('src-039fe82820b9cd97109e4c21', {'content_hash': 'sha256:c9a717d10b2584f2348086ff72a6652096f37afce764801c33c62440370bf5ef', 'evidence_uri': 'app.py', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-039fe82820b9cd97109e4c21', 'source_type': 'script-dependencies'})],
  'components': [('cmp-573ec625b75de401a754c4db', {'component_id': 'cmp-573ec625b75de401a754c4db', 'ecosystem': 'local', 'kind': 'automation-script', 'lifecycles': ['repository-used'], 'name': 'app.py', 'namespace': '', 'official_channel_required': False, 'official_channels': []}), ('cmp-d80183028eb6e50b2f53021e', {'component_id': 'cmp-d80183028eb6e50b2f53021e', 'ecosystem': 'pypi', 'kind': 'library', 'lifecycles': ['repository-used'], 'name': 'pyyaml', 'namespace': '', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:pypi/pyyaml'}),
                 ('cmp-2b67f332d5fc6fb28d8bd9c4', {'component_id': 'cmp-2b67f332d5fc6fb28d8bd9c4', 'ecosystem': 'pypi', 'kind': 'library', 'lifecycles': ['repository-used'], 'name': 'jsonschema', 'namespace': '', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:pypi/jsonschema'}),
                 ('cmp-f9dffcd8a9c72f6b0e786db7', {'component_id': 'cmp-f9dffcd8a9c72f6b0e786db7', 'ecosystem': 'pypi', 'kind': 'library', 'lifecycles': ['repository-used'], 'name': 'optimum', 'namespace': '', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:pypi/optimum'})],
  'versions': [('ver-c96da01036b38cc571a238d1', {'component_id': 'cmp-573ec625b75de401a754c4db', 'component_version_id': 'ver-c96da01036b38cc571a238d1', 'evidence': ['app.py'], 'resolution_state': 'resolved', 'source_ref': 'sha256:c9a717d10b2584f2348086ff72a6652096f37afce764801c33c62440370bf5ef'}), ('ver-fb600f6d874284f295f4da89', {'component_id': 'cmp-d80183028eb6e50b2f53021e', 'component_version_id': 'ver-fb600f6d874284f295f4da89', 'evidence': ['app.py#L1', 'app.py#line:1', 'requirements.txt#L1'], 'resolution_state': 'resolved', 'resolved_version': '1.2.3'}),
               ('ver-5f26612414163eb7be772fd0', {'component_id': 'cmp-2b67f332d5fc6fb28d8bd9c4', 'component_version_id': 'ver-5f26612414163eb7be772fd0', 'constraint': 'unversioned', 'evidence': ['app.py#line:3'], 'resolution_state': 'unresolved'}), ('ver-9c19406f2c21e15453feccd8', {'component_id': 'cmp-f9dffcd8a9c72f6b0e786db7', 'component_version_id': 'ver-9c19406f2c21e15453feccd8', 'evidence': ['app.py#L4', 'app.py#line:4', 'requirements.txt#L2'], 'resolution_state': 'resolved', 'resolved_version': '2.3.4'})],
  'occurrences': [('occ-5facf4223e401a10c98675a5', {'component_id': 'cmp-d80183028eb6e50b2f53021e', 'component_version_id': 'ver-fb600f6d874284f295f4da89', 'dependency_scope': 'automation', 'directness': 'direct', 'evidence_locator': 'line:1', 'lifecycle': 'repository-used', 'metadata': {'distribution': 'PyYAML'}, 'occurrence_id': 'occ-5facf4223e401a10c98675a5', 'optional': False, 'raw_value': 'PyYAML==1.2.3', 'role': 'script-direct-dependency', 'root_id': 'cmp-573ec625b75de401a754c4db', 'source_id': 'src-039fe82820b9cd97109e4c21'}),
                  ('occ-9c4c665ee7a2c047de73b2d3', {'component_id': 'cmp-2b67f332d5fc6fb28d8bd9c4', 'component_version_id': 'ver-5f26612414163eb7be772fd0', 'dependency_scope': 'automation', 'directness': 'direct', 'evidence_locator': 'line:3', 'lifecycle': 'conditional', 'metadata': {'distribution': 'jsonschema'}, 'occurrence_id': 'occ-9c4c665ee7a2c047de73b2d3', 'optional': True, 'raw_value': 'jsonschema', 'role': 'script-direct-dependency', 'root_id': 'cmp-573ec625b75de401a754c4db', 'source_id': 'src-039fe82820b9cd97109e4c21'}),
                  ('occ-fd9ef95546f167cdff21c70f', {'component_id': 'cmp-f9dffcd8a9c72f6b0e786db7', 'component_version_id': 'ver-9c19406f2c21e15453feccd8', 'dependency_scope': 'automation', 'directness': 'direct', 'evidence_locator': 'line:4', 'lifecycle': 'repository-used', 'metadata': {'distribution': 'optimum'}, 'occurrence_id': 'occ-fd9ef95546f167cdff21c70f', 'optional': False, 'raw_value': 'optimum==2.3.4', 'role': 'script-direct-dependency', 'root_id': 'cmp-573ec625b75de401a754c4db', 'source_id': 'src-039fe82820b9cd97109e4c21'})],
  'edges': [('edge-a350255d3facd7a5808bf9ac', {'constraint': '1.2.3', 'edge_id': 'edge-a350255d3facd7a5808bf9ac', 'from_component_version_id': 'ver-c96da01036b38cc571a238d1', 'metadata': {'distribution': 'PyYAML'}, 'optional': False, 'relationship': 'depends-on', 'resolver': 'sibling-python-requirements', 'scope': 'automation', 'source_occurrence_id': 'occ-5facf4223e401a10c98675a5', 'to_component_version_id': 'ver-fb600f6d874284f295f4da89'}),
            ('edge-623b43f0b58bd74baf92acd2', {'constraint': 'unversioned', 'edge_id': 'edge-623b43f0b58bd74baf92acd2', 'from_component_version_id': 'ver-c96da01036b38cc571a238d1', 'metadata': {'distribution': 'jsonschema'}, 'optional': True, 'relationship': 'depends-on', 'resolver': 'sibling-python-requirements', 'scope': 'automation', 'source_occurrence_id': 'occ-9c4c665ee7a2c047de73b2d3', 'to_component_version_id': 'ver-5f26612414163eb7be772fd0'}),
            ('edge-30e52f244ce1eaadadc196cf', {'constraint': '2.3.4', 'edge_id': 'edge-30e52f244ce1eaadadc196cf', 'from_component_version_id': 'ver-c96da01036b38cc571a238d1', 'metadata': {'distribution': 'optimum'}, 'optional': False, 'relationship': 'depends-on', 'resolver': 'sibling-python-requirements', 'scope': 'automation', 'source_occurrence_id': 'occ-fd9ef95546f167cdff21c70f', 'to_component_version_id': 'ver-9c19406f2c21e15453feccd8'})],
  'extra_gaps': [('gap-fa32665673cf1bf5670e9469', {'component_id': 'cmp-2b67f332d5fc6fb28d8bd9c4', 'component_version_id': 'ver-5f26612414163eb7be772fd0', 'evidence': ['app.py#L3'], 'gap_id': 'gap-fa32665673cf1bf5670e9469', 'gap_type': 'script-dependency-pin-missing', 'message': "app.py directly uses 'jsonschema' without a sibling requirement pin", 'source_id': 'src-039fe82820b9cd97109e4c21'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_add_model_artifact_observation.1": r"""(('cmp-c29cb040a3285ba7e6ab95f8', 'ver-c682df2d3e0cddf406b3e9e3', 'occ-f7fb378dcce9f53863d39559'),
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-96798a62afd2f5a456064757', {'component_id': 'cmp-96798a62afd2f5a456064757', 'ecosystem': 'local', 'kind': 'fixture', 'lifecycles': ['repository-used'], 'name': 'input.json', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-c29cb040a3285ba7e6ab95f8', {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'ecosystem': 'huggingface', 'kind': 'model-artifact', 'lifecycles': ['repository-used'], 'metadata': {'artifact_identity': 'example/app', 'lineage_required': True, 'lineage_evidence': ['input.json#/model']}, 'name': 'app', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-b5e5f51f6ef2c47aceaed9ef', {'component_id': 'cmp-96798a62afd2f5a456064757', 'component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'evidence': ['input.json'], 'resolution_state': 'resolved', 'source_ref': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}),
               ('ver-c682df2d3e0cddf406b3e9e3', {'artifact_digest': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-c682df2d3e0cddf406b3e9e3', 'evidence': ['input.json#/model'], 'metadata': {'artifact_identity': 'example/app', 'lineage_required': True, 'lineage_evidence': ['input.json#/model']}, 'resolution_state': 'resolved', 'resolved_version': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'source_ref': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'})],
  'occurrences': [('occ-f7fb378dcce9f53863d39559',
                   {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-c682df2d3e0cddf406b3e9e3', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/model', 'lifecycle': 'repository-used', 'metadata': {'artifact_identity': 'example/app', 'lineage_required': True, 'lineage_evidence': ['input.json#/model']}, 'occurrence_id': 'occ-f7fb378dcce9f53863d39559', 'optional': False, 'raw_value': 'example/app', 'role': 'fixture-model', 'root_id': 'cmp-96798a62afd2f5a456064757', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-b699180541f493e7c42925f7', {'edge_id': 'edge-b699180541f493e7c42925f7', 'from_component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'optional': False, 'relationship': 'uses-model-artifact', 'resolver': 'model-artifact-discovery', 'scope': 'runtime', 'source_occurrence_id': 'occ-f7fb378dcce9f53863d39559', 'to_component_version_id': 'ver-c682df2d3e0cddf406b3e9e3'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_add_model_artifact_observation.2": r"""(('cmp-c29cb040a3285ba7e6ab95f8', 'ver-157817821115105f98e0a27c', 'occ-5459e825fcd718eeccf78e52'),
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-96798a62afd2f5a456064757', {'component_id': 'cmp-96798a62afd2f5a456064757', 'ecosystem': 'local', 'kind': 'fixture', 'lifecycles': ['repository-used'], 'name': 'input.json', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-c29cb040a3285ba7e6ab95f8', {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'ecosystem': 'huggingface', 'kind': 'model-artifact', 'lifecycles': ['repository-used'], 'metadata': {'artifact_identity': 'example/app', 'lineage_required': True, 'lineage_evidence': ['input.json#/model']}, 'name': 'app', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-b5e5f51f6ef2c47aceaed9ef', {'component_id': 'cmp-96798a62afd2f5a456064757', 'component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'evidence': ['input.json'], 'resolution_state': 'resolved', 'source_ref': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}),
               ('ver-c682df2d3e0cddf406b3e9e3', {'artifact_digest': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-c682df2d3e0cddf406b3e9e3', 'evidence': ['input.json#/model'], 'metadata': {'artifact_identity': 'example/app', 'lineage_required': True, 'lineage_evidence': ['input.json#/model']}, 'resolution_state': 'resolved', 'resolved_version': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'source_ref': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}),
               ('ver-157817821115105f98e0a27c', {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-157817821115105f98e0a27c', 'constraint': 'immutable-revision-or-hash-required', 'evidence': ['input.json#/model'], 'metadata': {'artifact_identity': 'example/app'}, 'resolution_state': 'unresolved', 'source_ref': 'main'})],
  'occurrences': [('occ-f7fb378dcce9f53863d39559',
                   {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-c682df2d3e0cddf406b3e9e3', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/model', 'lifecycle': 'repository-used', 'metadata': {'artifact_identity': 'example/app', 'lineage_required': True, 'lineage_evidence': ['input.json#/model']}, 'occurrence_id': 'occ-f7fb378dcce9f53863d39559', 'optional': False, 'raw_value': 'example/app', 'role': 'fixture-model', 'root_id': 'cmp-96798a62afd2f5a456064757', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-5459e825fcd718eeccf78e52', {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-157817821115105f98e0a27c', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/model', 'lifecycle': 'repository-used', 'metadata': {'artifact_identity': 'example/app'}, 'occurrence_id': 'occ-5459e825fcd718eeccf78e52', 'optional': False, 'raw_value': 'example/app', 'role': 'fixture-model', 'root_id': 'cmp-96798a62afd2f5a456064757', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-b699180541f493e7c42925f7', {'edge_id': 'edge-b699180541f493e7c42925f7', 'from_component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'optional': False, 'relationship': 'uses-model-artifact', 'resolver': 'model-artifact-discovery', 'scope': 'runtime', 'source_occurrence_id': 'occ-f7fb378dcce9f53863d39559', 'to_component_version_id': 'ver-c682df2d3e0cddf406b3e9e3'}),
            ('edge-50e9197852b5834781246365', {'edge_id': 'edge-50e9197852b5834781246365', 'from_component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'optional': False, 'relationship': 'uses-model-artifact', 'resolver': 'model-artifact-discovery', 'scope': 'runtime', 'source_occurrence_id': 'occ-5459e825fcd718eeccf78e52', 'to_component_version_id': 'ver-157817821115105f98e0a27c'})],
  'extra_gaps': [('gap-d35924e733f6a3decd08e01c', {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-157817821115105f98e0a27c', 'evidence': ['input.json#/model'], 'gap_id': 'gap-d35924e733f6a3decd08e01c', 'gap_type': 'model-artifact-integrity-unresolved', 'message': "Model artifact 'example/app' has no immutable content hash", 'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                 ('gap-1f4e783ff6af748c71066815', {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-157817821115105f98e0a27c', 'evidence': ['input.json#/model'], 'gap_id': 'gap-1f4e783ff6af748c71066815', 'gap_type': 'model-artifact-revision-unresolved', 'message': "Hugging Face model 'example/app' has no immutable revision", 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_add_model_artifact_observation_resolves_revision_without_digest.1": r"""(('cmp-c29cb040a3285ba7e6ab95f8', 'ver-5cee9f5b2c7237f5871223f6', 'occ-93c5a8c9b53834d3b7477f30'),
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-96798a62afd2f5a456064757', {'component_id': 'cmp-96798a62afd2f5a456064757', 'ecosystem': 'local', 'kind': 'fixture', 'lifecycles': ['repository-used'], 'name': 'input.json', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-c29cb040a3285ba7e6ab95f8', {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'ecosystem': 'huggingface', 'kind': 'model-artifact', 'lifecycles': ['repository-used'], 'metadata': {'artifact_identity': 'example/app'}, 'name': 'app', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-b5e5f51f6ef2c47aceaed9ef', {'component_id': 'cmp-96798a62afd2f5a456064757', 'component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'evidence': ['input.json'], 'resolution_state': 'resolved', 'source_ref': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}),
               ('ver-5cee9f5b2c7237f5871223f6', {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-5cee9f5b2c7237f5871223f6', 'evidence': ['input.json#/model'], 'metadata': {'artifact_identity': 'example/app'}, 'resolution_state': 'resolved', 'resolved_version': '1.2.3', 'source_ref': '1.2.3'})],
  'occurrences': [('occ-93c5a8c9b53834d3b7477f30', {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-5cee9f5b2c7237f5871223f6', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/model', 'lifecycle': 'repository-used', 'metadata': {'artifact_identity': 'example/app'}, 'occurrence_id': 'occ-93c5a8c9b53834d3b7477f30', 'optional': False, 'raw_value': 'example/app', 'role': 'fixture-model', 'root_id': 'cmp-96798a62afd2f5a456064757', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-c61f681334ef203f4502ea5a', {'edge_id': 'edge-c61f681334ef203f4502ea5a', 'from_component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'optional': False, 'relationship': 'uses-model-artifact', 'resolver': 'model-artifact-discovery', 'scope': 'runtime', 'source_occurrence_id': 'occ-93c5a8c9b53834d3b7477f30', 'to_component_version_id': 'ver-5cee9f5b2c7237f5871223f6'})],
  'extra_gaps': [('gap-9a9ce7b487530c5ab119ad62', {'component_id': 'cmp-c29cb040a3285ba7e6ab95f8', 'component_version_id': 'ver-5cee9f5b2c7237f5871223f6', 'evidence': ['input.json#/model'], 'gap_id': 'gap-9a9ce7b487530c5ab119ad62', 'gap_type': 'model-artifact-integrity-unresolved', 'message': "Model artifact 'example/app' has no immutable content hash", 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "argo-empty": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-1d4bb1461c07ff4730edbaf5', {'component_id': 'cmp-1d4bb1461c07ff4730edbaf5', 'ecosystem': 'argocd', 'kind': 'argo-applicationset', 'lifecycles': ['deployed'], 'name': 'app', 'namespace': 'example', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-9d9d126b0ef5b6bf449e5b4b', {'component_id': 'cmp-1d4bb1461c07ff4730edbaf5', 'component_version_id': 'ver-9d9d126b0ef5b6bf449e5b4b', 'constraint': 'live-observation', 'evidence': ['input.json#/items/0'], 'metadata': {'sync_status': None, 'health_status': None, 'reconciled_at': None, 'revisions': [], 'operation_phase': None, 'operation_started_at': None, 'operation_finished_at': None}, 'resolution_state': 'unresolved'})],
  'occurrences': [('occ-a8b80af27bdca9b01cdeeb59', {'component_id': 'cmp-1d4bb1461c07ff4730edbaf5', 'component_version_id': 'ver-9d9d126b0ef5b6bf449e5b4b', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/items/0', 'lifecycle': 'deployed', 'metadata': {'uid': None, 'resource_version': None}, 'occurrence_id': 'occ-a8b80af27bdca9b01cdeeb59', 'optional': False, 'raw_value': 'example/app', 'role': 'live-argo-application', 'root_id': 'cmp-1d4bb1461c07ff4730edbaf5', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "argo-git-target": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-3d5c1cbd9f2912e953741e57', {'component_id': 'cmp-3d5c1cbd9f2912e953741e57', 'ecosystem': 'argocd', 'kind': 'argo-application', 'lifecycles': ['deployed'], 'name': 'app', 'namespace': 'argocd', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-692b82b6e8949d9b4716581e', {'component_id': 'cmp-692b82b6e8949d9b4716581e', 'ecosystem': 'git', 'kind': 'git-repository', 'lifecycles': ['deployed'], 'metadata': {'source_repo': 'https://git.example.org/example/app.git', 'path': ''}, 'name': 'app', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-cb71ace23283960ece6af136', {'component_id': 'cmp-3d5c1cbd9f2912e953741e57', 'component_version_id': 'ver-cb71ace23283960ece6af136', 'constraint': 'live-observation', 'evidence': ['input.json#/items/0'], 'metadata': {'sync_status': None, 'health_status': None, 'reconciled_at': None, 'revisions': [], 'operation_phase': None, 'operation_started_at': None, 'operation_finished_at': None}, 'resolution_state': 'unresolved'}),
               ('ver-f3d67f1d9bc58663fcd64ed8', {'component_id': 'cmp-692b82b6e8949d9b4716581e', 'component_version_id': 'ver-f3d67f1d9bc58663fcd64ed8', 'constraint': 'main', 'evidence': ['input.json#/items/0/spec/sources/1'], 'metadata': {'observed_revision': None}, 'resolution_state': 'unresolved', 'source_ref': 'main'})],
  'occurrences': [('occ-1bf0de38c846e9f337ca6ac1', {'component_id': 'cmp-3d5c1cbd9f2912e953741e57', 'component_version_id': 'ver-cb71ace23283960ece6af136', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/items/0', 'lifecycle': 'deployed', 'metadata': {'uid': None, 'resource_version': None}, 'occurrence_id': 'occ-1bf0de38c846e9f337ca6ac1', 'optional': False, 'raw_value': 'argocd/app', 'role': 'live-argo-application', 'root_id': 'cmp-3d5c1cbd9f2912e953741e57', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-412c2ee55ea921996764671b', {'component_id': 'cmp-692b82b6e8949d9b4716581e', 'component_version_id': 'ver-f3d67f1d9bc58663fcd64ed8', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': '/items/0/spec/sources/1', 'lifecycle': 'deployed', 'occurrence_id': 'occ-412c2ee55ea921996764671b', 'optional': False, 'raw_value': 'https://git.example.org/example/app.git#@main', 'role': 'live-argo-git-source', 'root_id': 'cmp-3d5c1cbd9f2912e953741e57', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-c6cfc98fdec101c3bbf648af', {'constraint': 'main', 'edge_id': 'edge-c6cfc98fdec101c3bbf648af', 'from_component_version_id': 'ver-cb71ace23283960ece6af136', 'metadata': {'observed_revision': None}, 'optional': False, 'relationship': 'desired-source', 'resolver': 'live-argocd', 'scope': 'deployment', 'source_occurrence_id': 'occ-412c2ee55ea921996764671b', 'to_component_version_id': 'ver-f3d67f1d9bc58663fcd64ed8'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "argo-observed-sources": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-3c51f46bb03bc673794dc2c2', {'component_id': 'cmp-3c51f46bb03bc673794dc2c2', 'ecosystem': 'argocd', 'kind': 'argo-application', 'lifecycles': ['deployed'], 'name': 'app', 'namespace': 'example', 'official_channel_required': False, 'official_channels': []}), ('cmp-02192ba03104976a9815028b', {'component_id': 'cmp-02192ba03104976a9815028b', 'ecosystem': 'git', 'kind': 'git-repository', 'lifecycles': ['deployed'], 'metadata': {'source_repo': 'https://git.example.org/example/app.git', 'path': 'app'}, 'name': 'app', 'namespace': '', 'official_channel_required': True, 'official_channels': []}),
                 ('cmp-217b2449447cfbbacbd34ffd', {'component_id': 'cmp-217b2449447cfbbacbd34ffd', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['deployed'], 'metadata': {'chart_repository': 'https://charts.example.org'}, 'name': 'app', 'namespace': '', 'official_channel_required': True, 'official_channels': []}),
                 ('cmp-e3a2012f0f8df626445ba38f', {'component_id': 'cmp-e3a2012f0f8df626445ba38f', 'ecosystem': 'oci', 'kind': 'oci-image', 'lifecycles': ['runtime-resolved'], 'metadata': {'oci_repository': 'registry.example.org/example/app'}, 'name': 'app', 'namespace': 'registry.example.org/example', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:oci/app?repository_url=registry.example.org/example/app'}),
                 ('cmp-be42d174ff2a25c887290790', {'component_id': 'cmp-be42d174ff2a25c887290790', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-api', 'lifecycles': ['deployed'], 'metadata': {'api_group': 'apps', 'gvk': 'apps/v1/Deployment'}, 'name': 'Deployment', 'namespace': 'apps', 'official_channel_required': True, 'official_channels': []}),
                 ('cmp-cce4c95ee3054b756308f6ce', {'component_id': 'cmp-cce4c95ee3054b756308f6ce', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-api', 'lifecycles': ['deployed'], 'metadata': {'api_group': 'core', 'gvk': 'core/unknown/unknown'}, 'name': 'unknown', 'namespace': 'core', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-91a6e4b3011d7a0c561637e3',
                {'component_id': 'cmp-3c51f46bb03bc673794dc2c2', 'component_version_id': 'ver-91a6e4b3011d7a0c561637e3', 'evidence': ['input.json#/items/1'], 'metadata': {'sync_status': 'Synced', 'health_status': 'Healthy', 'reconciled_at': '2026-01-02T03:04:05Z', 'revisions': ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '2.0.1'], 'operation_phase': 'Succeeded', 'operation_started_at': '2026-01-02T03:04:05Z', 'operation_finished_at': '2026-01-02T03:04:06Z'}, 'resolution_state': 'resolved', 'source_ref': 'revisions-sha256:d24eab624d08e6306fea3ee1ec88a3b2694d02de535870803ade42652563a4e0'}),
               ('ver-a907cc3e61b2919c31066743', {'component_id': 'cmp-02192ba03104976a9815028b', 'component_version_id': 'ver-a907cc3e61b2919c31066743', 'constraint': 'main', 'evidence': ['input.json#/items/1/spec/sources/0'], 'metadata': {'observed_revision': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}, 'resolution_state': 'resolved', 'source_ref': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}),
               ('ver-c16d75d5d5cec46431d5b05e', {'component_id': 'cmp-217b2449447cfbbacbd34ffd', 'component_version_id': 'ver-c16d75d5d5cec46431d5b05e', 'constraint': '2.0.0', 'evidence': ['input.json#/items/1/spec/sources/1'], 'metadata': {'observed_revision': '2.0.1'}, 'resolution_state': 'resolved', 'resolved_version': '2.0.1'}),
               ('ver-1c3c4d5499f1433309cbcaa4', {'artifact_digest': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'component_id': 'cmp-e3a2012f0f8df626445ba38f', 'component_version_id': 'ver-1c3c4d5499f1433309cbcaa4', 'evidence': ['input.json#/items/1/status/operationState/syncResult/images/0'], 'resolution_state': 'resolved'}),
               ('ver-657f03f1131dc2456116084f', {'artifact_digest': 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'component_id': 'cmp-e3a2012f0f8df626445ba38f', 'component_version_id': 'ver-657f03f1131dc2456116084f', 'evidence': ['input.json#/items/1/status/summary/images/0'], 'resolution_state': 'resolved'}), ('ver-c35cf67618df849203244857', {'component_id': 'cmp-be42d174ff2a25c887290790', 'component_version_id': 'ver-c35cf67618df849203244857', 'evidence': ['input.json#/items/1/status/resources/1'], 'resolution_state': 'resolved', 'resolved_version': 'v1'}),
               ('ver-6e2d82e4b9b56515b2125f93', {'component_id': 'cmp-cce4c95ee3054b756308f6ce', 'component_version_id': 'ver-6e2d82e4b9b56515b2125f93', 'evidence': ['input.json#/items/1/status/resources/2'], 'resolution_state': 'resolved', 'resolved_version': 'unknown'})],
  'occurrences': [('occ-4effded7600f749f770172c7', {'component_id': 'cmp-3c51f46bb03bc673794dc2c2', 'component_version_id': 'ver-91a6e4b3011d7a0c561637e3', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/items/1', 'lifecycle': 'deployed', 'metadata': {'uid': 'fixture-id', 'resource_version': '42'}, 'occurrence_id': 'occ-4effded7600f749f770172c7', 'optional': False, 'raw_value': 'example/app', 'role': 'live-argo-application', 'root_id': 'cmp-3c51f46bb03bc673794dc2c2', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-b4a50772d913d36479cc3a44', {'component_id': 'cmp-02192ba03104976a9815028b', 'component_version_id': 'ver-a907cc3e61b2919c31066743', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': '/items/1/spec/sources/0', 'lifecycle': 'deployed', 'occurrence_id': 'occ-b4a50772d913d36479cc3a44', 'optional': False, 'raw_value': 'https://git.example.org/example/app.git#app@main', 'role': 'live-argo-git-source', 'root_id': 'cmp-3c51f46bb03bc673794dc2c2', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-3b09c2baf9f6dccf3d729457', {'component_id': 'cmp-217b2449447cfbbacbd34ffd', 'component_version_id': 'ver-c16d75d5d5cec46431d5b05e', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': '/items/1/spec/sources/1', 'lifecycle': 'deployed', 'occurrence_id': 'occ-3b09c2baf9f6dccf3d729457', 'optional': False, 'raw_value': 'https://charts.example.org#app@2.0.0', 'role': 'live-argo-helm-source', 'root_id': 'cmp-3c51f46bb03bc673794dc2c2', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-17a7a711033cc194046c2a21',
                   {'component_id': 'cmp-e3a2012f0f8df626445ba38f',
                    'component_version_id': 'ver-1c3c4d5499f1433309cbcaa4',
                    'dependency_scope': 'runtime',
                    'directness': 'direct',
                    'evidence_locator': '/items/1/status/operationState/syncResult/images/0',
                    'lifecycle': 'runtime-resolved',
                    'metadata': {'application': 'app', 'namespace': 'example', 'status_path': '/items/1/status/operationState/syncResult/images'},
                    'occurrence_id': 'occ-17a7a711033cc194046c2a21',
                    'optional': False,
                    'raw_value': 'registry.example.org/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'role': 'live-argo-operation-image',
                    'root_id': 'cmp-3c51f46bb03bc673794dc2c2',
                    'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-47fa63394aeb97fa2bd4838b',
                   {'component_id': 'cmp-e3a2012f0f8df626445ba38f',
                    'component_version_id': 'ver-657f03f1131dc2456116084f',
                    'dependency_scope': 'runtime',
                    'directness': 'direct',
                    'evidence_locator': '/items/1/status/summary/images/0',
                    'lifecycle': 'runtime-resolved',
                    'metadata': {'application': 'app', 'namespace': 'example', 'status_path': '/items/1/status/summary/images'},
                    'occurrence_id': 'occ-47fa63394aeb97fa2bd4838b',
                    'optional': False,
                    'raw_value': 'registry.example.org/example/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'role': 'live-argo-observed-image',
                    'root_id': 'cmp-3c51f46bb03bc673794dc2c2',
                    'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-30ac7a62a85ca601f85c13e8', {'component_id': 'cmp-be42d174ff2a25c887290790', 'component_version_id': 'ver-c35cf67618df849203244857', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/items/1/status/resources/1', 'lifecycle': 'deployed', 'metadata': {'namespace': 'example', 'name': 'app', 'status': 'Synced'}, 'occurrence_id': 'occ-30ac7a62a85ca601f85c13e8', 'optional': False, 'raw_value': 'apps/v1/Deployment', 'role': 'live-argo-managed-resource', 'root_id': 'cmp-3c51f46bb03bc673794dc2c2', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-6b26a4c39038a9cbb8d673aa', {'component_id': 'cmp-cce4c95ee3054b756308f6ce', 'component_version_id': 'ver-6e2d82e4b9b56515b2125f93', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/items/1/status/resources/2', 'lifecycle': 'deployed', 'occurrence_id': 'occ-6b26a4c39038a9cbb8d673aa', 'optional': False, 'raw_value': 'core/unknown/unknown', 'role': 'live-argo-managed-resource', 'root_id': 'cmp-3c51f46bb03bc673794dc2c2', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-9b15a861926f0d7c0783abb9', {'constraint': 'main', 'edge_id': 'edge-9b15a861926f0d7c0783abb9', 'from_component_version_id': 'ver-91a6e4b3011d7a0c561637e3', 'metadata': {'observed_revision': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}, 'optional': False, 'relationship': 'desired-source', 'resolver': 'live-argocd', 'scope': 'deployment', 'source_occurrence_id': 'occ-b4a50772d913d36479cc3a44', 'to_component_version_id': 'ver-a907cc3e61b2919c31066743'}),
            ('edge-4a8fb458c114b1405421a192', {'constraint': '2.0.0', 'edge_id': 'edge-4a8fb458c114b1405421a192', 'from_component_version_id': 'ver-91a6e4b3011d7a0c561637e3', 'metadata': {'observed_revision': '2.0.1'}, 'optional': False, 'relationship': 'desired-source', 'resolver': 'live-argocd', 'scope': 'deployment', 'source_occurrence_id': 'occ-3b09c2baf9f6dccf3d729457', 'to_component_version_id': 'ver-c16d75d5d5cec46431d5b05e'}),
            ('edge-7ccbe6662eb647e6b1beb2f6', {'edge_id': 'edge-7ccbe6662eb647e6b1beb2f6', 'from_component_version_id': 'ver-91a6e4b3011d7a0c561637e3', 'optional': False, 'relationship': 'observes-image', 'resolver': 'live-argocd-status', 'scope': 'runtime', 'source_occurrence_id': 'occ-17a7a711033cc194046c2a21', 'to_component_version_id': 'ver-1c3c4d5499f1433309cbcaa4'}),
            ('edge-469d4295244bf27382d7529f', {'edge_id': 'edge-469d4295244bf27382d7529f', 'from_component_version_id': 'ver-91a6e4b3011d7a0c561637e3', 'optional': False, 'relationship': 'observes-image', 'resolver': 'live-argocd-status', 'scope': 'runtime', 'source_occurrence_id': 'occ-47fa63394aeb97fa2bd4838b', 'to_component_version_id': 'ver-657f03f1131dc2456116084f'}),
            ('edge-7ec9837d1d7d643491de9e8d', {'edge_id': 'edge-7ec9837d1d7d643491de9e8d', 'from_component_version_id': 'ver-91a6e4b3011d7a0c561637e3', 'optional': False, 'relationship': 'manages-api', 'resolver': 'live-argocd-status', 'scope': 'deployment', 'source_occurrence_id': 'occ-30ac7a62a85ca601f85c13e8', 'to_component_version_id': 'ver-c35cf67618df849203244857'}),
            ('edge-28a95a41d986c4ce72059c14', {'edge_id': 'edge-28a95a41d986c4ce72059c14', 'from_component_version_id': 'ver-91a6e4b3011d7a0c561637e3', 'optional': False, 'relationship': 'manages-api', 'resolver': 'live-argocd-status', 'scope': 'deployment', 'source_occurrence_id': 'occ-6b26a4c39038a9cbb8d673aa', 'to_component_version_id': 'ver-6e2d82e4b9b56515b2125f93'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_import_api_resource_list.1": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-fa36a7b4e43c7144d2ee0f16', {'component_id': 'cmp-fa36a7b4e43c7144d2ee0f16', 'ecosystem': 'kubernetes', 'kind': 'platform', 'lifecycles': ['deployed'], 'metadata': {'inventory_scope': 'cluster'}, 'name': 'kubernetes', 'namespace': 'k8s.io', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:k8s/k8s.io%2Fkubernetes'}),
                 ('cmp-1dd1ebc31415ff4307c0b264', {'component_id': 'cmp-1dd1ebc31415ff4307c0b264', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-api', 'lifecycles': ['deployed'], 'metadata': {'api_group': 'core', 'gvk': 'core/v1/Widget'}, 'name': 'Widget', 'namespace': 'core', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-d025308d4100191c10ed65ac', {'component_id': 'cmp-1dd1ebc31415ff4307c0b264', 'component_version_id': 'ver-d025308d4100191c10ed65ac', 'evidence': ['input.json#/resources/0'], 'metadata': {'api_discovery_endpoint': '/api/v1', 'api_resource_name': 'widgets', 'namespaced': False, 'singular_name': 'widget', 'verbs': ['get', 'list'], 'short_names': ['wd'], 'categories': ['example'], 'storage_version_hash': 'example-storage-hash'}, 'resolution_state': 'resolved', 'resolved_version': 'v1'})],
  'occurrences': [('occ-c6edc736d9e8abae433dd87d', {'component_id': 'cmp-1dd1ebc31415ff4307c0b264', 'component_version_id': 'ver-d025308d4100191c10ed65ac', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/resources/0', 'lifecycle': 'deployed', 'metadata': {'endpoint': '/api/v1'}, 'occurrence_id': 'occ-c6edc736d9e8abae433dd87d', 'optional': False, 'raw_value': 'v1/widgets:Widget', 'role': 'live-kubernetes-api-discovery', 'root_id': 'cmp-fa36a7b4e43c7144d2ee0f16', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [],
  'extra_gaps': [('gap-c28951cfa4a658a517f0a9cc', {'evidence': ['input.json#/resources/1'], 'gap_id': 'gap-c28951cfa4a658a517f0a9cc', 'gap_type': 'live-api-discovery-invalid', 'message': 'API discovery endpoint /api/v1 has a non-object resource', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'}), ('gap-fda377435f1f3df2db12346e', {'evidence': ['input.json#/resources/2'], 'gap_id': 'gap-fda377435f1f3df2db12346e', 'gap_type': 'live-api-discovery-invalid', 'message': 'API discovery endpoint /api/v1 has a resource without name or kind', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_import_argo_item.1": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-3d5c1cbd9f2912e953741e57', {'component_id': 'cmp-3d5c1cbd9f2912e953741e57', 'ecosystem': 'argocd', 'kind': 'argo-application', 'lifecycles': ['deployed'], 'name': 'app', 'namespace': 'argocd', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-217b2449447cfbbacbd34ffd', {'component_id': 'cmp-217b2449447cfbbacbd34ffd', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['deployed'], 'metadata': {'chart_repository': 'https://charts.example.org'}, 'name': 'app', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-aee6fcfb3fa685f0ac8290e4', {'component_id': 'cmp-3d5c1cbd9f2912e953741e57', 'component_version_id': 'ver-aee6fcfb3fa685f0ac8290e4', 'evidence': ['input.json#/items/3'], 'metadata': {'sync_status': None, 'health_status': None, 'reconciled_at': None, 'revisions': ['1.2.4'], 'operation_phase': None, 'operation_started_at': None, 'operation_finished_at': None}, 'resolution_state': 'resolved', 'source_ref': '1.2.4'}),
               ('ver-210eedc7957ed7b0d3c1c7cb', {'component_id': 'cmp-217b2449447cfbbacbd34ffd', 'component_version_id': 'ver-210eedc7957ed7b0d3c1c7cb', 'constraint': '1.2.3', 'evidence': ['input.json#/items/3/spec/source'], 'metadata': {'observed_revision': '1.2.4'}, 'resolution_state': 'resolved', 'resolved_version': '1.2.4'})],
  'occurrences': [('occ-55ca55c43df51c54482b9bab', {'component_id': 'cmp-3d5c1cbd9f2912e953741e57', 'component_version_id': 'ver-aee6fcfb3fa685f0ac8290e4', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/items/3', 'lifecycle': 'deployed', 'metadata': {'uid': None, 'resource_version': None}, 'occurrence_id': 'occ-55ca55c43df51c54482b9bab', 'optional': False, 'raw_value': 'argocd/app', 'role': 'live-argo-application', 'root_id': 'cmp-3d5c1cbd9f2912e953741e57', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-050928eb1c4cba81b402fb7f', {'component_id': 'cmp-217b2449447cfbbacbd34ffd', 'component_version_id': 'ver-210eedc7957ed7b0d3c1c7cb', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': '/items/3/spec/source', 'lifecycle': 'deployed', 'occurrence_id': 'occ-050928eb1c4cba81b402fb7f', 'optional': False, 'raw_value': 'https://charts.example.org#app@1.2.3', 'role': 'live-argo-helm-source', 'root_id': 'cmp-3d5c1cbd9f2912e953741e57', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-a2dfa1a2fdc9ddc20be3f65d', {'constraint': '1.2.3', 'edge_id': 'edge-a2dfa1a2fdc9ddc20be3f65d', 'from_component_version_id': 'ver-aee6fcfb3fa685f0ac8290e4', 'metadata': {'observed_revision': '1.2.4'}, 'optional': False, 'relationship': 'desired-source', 'resolver': 'live-argocd', 'scope': 'deployment', 'source_occurrence_id': 'occ-050928eb1c4cba81b402fb7f', 'to_component_version_id': 'ver-210eedc7957ed7b0d3c1c7cb'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_import_argo_item.2": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-3d5c1cbd9f2912e953741e57', {'component_id': 'cmp-3d5c1cbd9f2912e953741e57', 'ecosystem': 'argocd', 'kind': 'argo-application', 'lifecycles': ['deployed'], 'name': 'app', 'namespace': 'argocd', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-217b2449447cfbbacbd34ffd', {'component_id': 'cmp-217b2449447cfbbacbd34ffd', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['deployed'], 'metadata': {'chart_repository': 'https://charts.example.org'}, 'name': 'app', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-25c36d174210059ffc386b4a', {'component_id': 'cmp-3d5c1cbd9f2912e953741e57', 'component_version_id': 'ver-25c36d174210059ffc386b4a', 'evidence': ['input.json#/items/3'], 'metadata': {'sync_status': None, 'health_status': None, 'reconciled_at': None, 'revisions': ['1.2.4', '1.2.5'], 'operation_phase': None, 'operation_started_at': None, 'operation_finished_at': None}, 'resolution_state': 'resolved', 'source_ref': 'revisions-sha256:e15be8028bba1abeabacc24732c7d3a294c0946f16500f4f7e772d58703def28'}),
               ('ver-210eedc7957ed7b0d3c1c7cb', {'component_id': 'cmp-217b2449447cfbbacbd34ffd', 'component_version_id': 'ver-210eedc7957ed7b0d3c1c7cb', 'constraint': '1.2.3', 'evidence': ['input.json#/items/3/spec/source'], 'metadata': {'observed_revision': '1.2.4'}, 'resolution_state': 'resolved', 'resolved_version': '1.2.4'})],
  'occurrences': [('occ-8505c920eb91535a7e061774', {'component_id': 'cmp-3d5c1cbd9f2912e953741e57', 'component_version_id': 'ver-25c36d174210059ffc386b4a', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/items/3', 'lifecycle': 'deployed', 'metadata': {'uid': None, 'resource_version': None}, 'occurrence_id': 'occ-8505c920eb91535a7e061774', 'optional': False, 'raw_value': 'argocd/app', 'role': 'live-argo-application', 'root_id': 'cmp-3d5c1cbd9f2912e953741e57', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-050928eb1c4cba81b402fb7f', {'component_id': 'cmp-217b2449447cfbbacbd34ffd', 'component_version_id': 'ver-210eedc7957ed7b0d3c1c7cb', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': '/items/3/spec/source', 'lifecycle': 'deployed', 'occurrence_id': 'occ-050928eb1c4cba81b402fb7f', 'optional': False, 'raw_value': 'https://charts.example.org#app@1.2.3', 'role': 'live-argo-helm-source', 'root_id': 'cmp-3d5c1cbd9f2912e953741e57', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-f6e7815c43187366b3e33fc4', {'constraint': '1.2.3', 'edge_id': 'edge-f6e7815c43187366b3e33fc4', 'from_component_version_id': 'ver-25c36d174210059ffc386b4a', 'metadata': {'observed_revision': '1.2.4'}, 'optional': False, 'relationship': 'desired-source', 'resolver': 'live-argocd', 'scope': 'deployment', 'source_occurrence_id': 'occ-050928eb1c4cba81b402fb7f', 'to_component_version_id': 'ver-210eedc7957ed7b0d3c1c7cb'})],
  'extra_gaps': [('gap-c6a94afbea4ee319aa0c4dd5', {'component_id': 'cmp-3d5c1cbd9f2912e953741e57', 'component_version_id': 'ver-25c36d174210059ffc386b4a', 'evidence': ['input.json#/items/3/status/sync'], 'gap_id': 'gap-c6a94afbea4ee319aa0c4dd5', 'gap_type': 'argo-revision-cardinality', 'message': 'Argo Application argocd/app has 1 sources but 2 observed revisions', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_import_crd_item.1": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-a3e2bcda87c32a7c25488e55', {'component_id': 'cmp-a3e2bcda87c32a7c25488e55', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-crd', 'lifecycles': ['deployed'], 'metadata': {'group': 'example.org', 'resource_kind': 'Widget'}, 'name': 'widgets.example.org', 'namespace': 'example.org', 'official_channel_required': True, 'official_channels': []}),
                 ('cmp-c2c71c8b4366e890876f9362', {'component_id': 'cmp-c2c71c8b4366e890876f9362', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-api', 'lifecycles': ['deployed'], 'metadata': {'api_group': 'example.org', 'gvk': 'example.org/v1/Widget', 'crd_name': 'widgets.example.org'}, 'name': 'Widget', 'namespace': 'example.org', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-36583166d25551cb104266bd', {'component_id': 'cmp-a3e2bcda87c32a7c25488e55', 'component_version_id': 'ver-36583166d25551cb104266bd', 'evidence': ['input.json#/items/2'], 'resolution_state': 'resolved', 'source_ref': 'example-id'}),
               ('ver-0b87e5144f965a44a79540d2', {'artifact_digest': 'sha256:28ec55202b90e6b021793c3b91faa495efea3dfb8576f3e3e69546557c6a23db', 'component_id': 'cmp-c2c71c8b4366e890876f9362', 'component_version_id': 'ver-0b87e5144f965a44a79540d2', 'evidence': ['input.json#/items/2/spec/versions/2'], 'metadata': {'served': True, 'storage': False, 'deprecated': True, 'deprecation_warning': 'Use v2.', 'conversion': {'strategy': 'None'}}, 'resolution_state': 'resolved', 'resolved_version': 'v1'})],
  'occurrences': [('occ-24a2091fe82b2af474ce95cd', {'component_id': 'cmp-c2c71c8b4366e890876f9362', 'component_version_id': 'ver-0b87e5144f965a44a79540d2', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/items/2/spec/versions/2', 'lifecycle': 'deployed', 'occurrence_id': 'occ-24a2091fe82b2af474ce95cd', 'optional': False, 'raw_value': 'example.org/v1/Widget', 'role': 'live-crd-api', 'root_id': 'cmp-a3e2bcda87c32a7c25488e55', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-d03fcb83398f27093162a348', {'edge_id': 'edge-d03fcb83398f27093162a348', 'from_component_version_id': 'ver-36583166d25551cb104266bd', 'optional': False, 'relationship': 'defines-api', 'resolver': 'live-crd', 'scope': 'api', 'source_occurrence_id': 'occ-24a2091fe82b2af474ce95cd', 'to_component_version_id': 'ver-0b87e5144f965a44a79540d2'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_import_openapi_v3_document.1": r"""(2,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-f7840bb47bcd68a4311f7112', {'component_id': 'cmp-f7840bb47bcd68a4311f7112', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-api', 'lifecycles': ['deployed'], 'metadata': {'api_group': 'core', 'gvk': 'core/v1/Alternate'}, 'name': 'Alternate', 'namespace': 'core', 'official_channel_required': True, 'official_channels': []}),
                 ('cmp-1dd1ebc31415ff4307c0b264', {'component_id': 'cmp-1dd1ebc31415ff4307c0b264', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-api', 'lifecycles': ['deployed'], 'metadata': {'api_group': 'core', 'gvk': 'core/v1/Widget'}, 'name': 'Widget', 'namespace': 'core', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-4e792d73260c0be603ce23d4', {'artifact_digest': 'sha256:af12dccf05f465964d925eaefd378f2a47b09a6625144df227337852b434f5f4', 'component_id': 'cmp-f7840bb47bcd68a4311f7112', 'component_version_id': 'ver-4e792d73260c0be603ce23d4', 'evidence': ['input.json#/components/schemas/example~1alternate'], 'metadata': {'openapi_endpoint': '/openapi/v3/api/v1', 'openapi_schema_name': 'example/alternate', 'openapi_version': '3.0.0'}, 'resolution_state': 'resolved', 'resolved_version': 'v1'}),
               ('ver-14c014e62d22ca5e60528738', {'artifact_digest': 'sha256:8d1fb3ef3aaf256bb8ea3661486329b37ec2b2acd137383318bb46115e1a26ff', 'component_id': 'cmp-1dd1ebc31415ff4307c0b264', 'component_version_id': 'ver-14c014e62d22ca5e60528738', 'evidence': ['input.json#/components/schemas/example~1item'], 'metadata': {'openapi_endpoint': '/openapi/v3/api/v1', 'openapi_schema_name': 'example/item', 'openapi_version': '3.0.0'}, 'resolution_state': 'resolved', 'resolved_version': 'v1'})],
  'occurrences': [('occ-9b157b5ddf230185ef793a45',
                   {'component_id': 'cmp-f7840bb47bcd68a4311f7112',
                    'component_version_id': 'ver-4e792d73260c0be603ce23d4',
                    'dependency_scope': 'runtime',
                    'directness': 'direct',
                    'evidence_locator': '/components/schemas/example~1alternate/x-kubernetes-group-version-kind/0',
                    'lifecycle': 'deployed',
                    'metadata': {'endpoint': '/openapi/v3/api/v1', 'schema_digest': 'sha256:af12dccf05f465964d925eaefd378f2a47b09a6625144df227337852b434f5f4', 'schema_name': 'example/alternate'},
                    'occurrence_id': 'occ-9b157b5ddf230185ef793a45',
                    'optional': False,
                    'raw_value': 'core/v1/Alternate',
                    'role': 'live-kubernetes-openapi-schema',
                    'root_id': 'cmp-f7840bb47bcd68a4311f7112',
                    'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-3e454211b5eb754e2a770ab5',
                   {'component_id': 'cmp-1dd1ebc31415ff4307c0b264',
                    'component_version_id': 'ver-14c014e62d22ca5e60528738',
                    'dependency_scope': 'runtime',
                    'directness': 'direct',
                    'evidence_locator': '/components/schemas/example~1item/x-kubernetes-group-version-kind/0',
                    'lifecycle': 'deployed',
                    'metadata': {'endpoint': '/openapi/v3/api/v1', 'schema_digest': 'sha256:8d1fb3ef3aaf256bb8ea3661486329b37ec2b2acd137383318bb46115e1a26ff', 'schema_name': 'example/item'},
                    'occurrence_id': 'occ-3e454211b5eb754e2a770ab5',
                    'optional': False,
                    'raw_value': 'core/v1/Widget',
                    'role': 'live-kubernetes-openapi-schema',
                    'root_id': 'cmp-1dd1ebc31415ff4307c0b264',
                    'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_import_openapi_v3_document.2": r"""(0,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-f7840bb47bcd68a4311f7112', {'component_id': 'cmp-f7840bb47bcd68a4311f7112', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-api', 'lifecycles': ['deployed'], 'metadata': {'api_group': 'core', 'gvk': 'core/v1/Alternate'}, 'name': 'Alternate', 'namespace': 'core', 'official_channel_required': True, 'official_channels': []}),
                 ('cmp-1dd1ebc31415ff4307c0b264', {'component_id': 'cmp-1dd1ebc31415ff4307c0b264', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-api', 'lifecycles': ['deployed'], 'metadata': {'api_group': 'core', 'gvk': 'core/v1/Widget'}, 'name': 'Widget', 'namespace': 'core', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-4e792d73260c0be603ce23d4', {'artifact_digest': 'sha256:af12dccf05f465964d925eaefd378f2a47b09a6625144df227337852b434f5f4', 'component_id': 'cmp-f7840bb47bcd68a4311f7112', 'component_version_id': 'ver-4e792d73260c0be603ce23d4', 'evidence': ['input.json#/components/schemas/example~1alternate'], 'metadata': {'openapi_endpoint': '/openapi/v3/api/v1', 'openapi_schema_name': 'example/alternate', 'openapi_version': '3.0.0'}, 'resolution_state': 'resolved', 'resolved_version': 'v1'}),
               ('ver-14c014e62d22ca5e60528738', {'artifact_digest': 'sha256:8d1fb3ef3aaf256bb8ea3661486329b37ec2b2acd137383318bb46115e1a26ff', 'component_id': 'cmp-1dd1ebc31415ff4307c0b264', 'component_version_id': 'ver-14c014e62d22ca5e60528738', 'evidence': ['input.json#/components/schemas/example~1item'], 'metadata': {'openapi_endpoint': '/openapi/v3/api/v1', 'openapi_schema_name': 'example/item', 'openapi_version': '3.0.0'}, 'resolution_state': 'resolved', 'resolved_version': 'v1'})],
  'occurrences': [('occ-9b157b5ddf230185ef793a45',
                   {'component_id': 'cmp-f7840bb47bcd68a4311f7112',
                    'component_version_id': 'ver-4e792d73260c0be603ce23d4',
                    'dependency_scope': 'runtime',
                    'directness': 'direct',
                    'evidence_locator': '/components/schemas/example~1alternate/x-kubernetes-group-version-kind/0',
                    'lifecycle': 'deployed',
                    'metadata': {'endpoint': '/openapi/v3/api/v1', 'schema_digest': 'sha256:af12dccf05f465964d925eaefd378f2a47b09a6625144df227337852b434f5f4', 'schema_name': 'example/alternate'},
                    'occurrence_id': 'occ-9b157b5ddf230185ef793a45',
                    'optional': False,
                    'raw_value': 'core/v1/Alternate',
                    'role': 'live-kubernetes-openapi-schema',
                    'root_id': 'cmp-f7840bb47bcd68a4311f7112',
                    'source_id': 'src-98a53e0ca7d133d11ccc09e7'}),
                  ('occ-3e454211b5eb754e2a770ab5',
                   {'component_id': 'cmp-1dd1ebc31415ff4307c0b264',
                    'component_version_id': 'ver-14c014e62d22ca5e60528738',
                    'dependency_scope': 'runtime',
                    'directness': 'direct',
                    'evidence_locator': '/components/schemas/example~1item/x-kubernetes-group-version-kind/0',
                    'lifecycle': 'deployed',
                    'metadata': {'endpoint': '/openapi/v3/api/v1', 'schema_digest': 'sha256:8d1fb3ef3aaf256bb8ea3661486329b37ec2b2acd137383318bb46115e1a26ff', 'schema_name': 'example/item'},
                    'occurrence_id': 'occ-3e454211b5eb754e2a770ab5',
                    'optional': False,
                    'raw_value': 'core/v1/Widget',
                    'role': 'live-kubernetes-openapi-schema',
                    'root_id': 'cmp-1dd1ebc31415ff4307c0b264',
                    'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "model-digest-only": r"""(('cmp-bae444d2ed75815c3da47462', 'ver-2f7fb6f98c6733bd705eee92', 'occ-2a29afdeae4619e0b7073ca2'),
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-96798a62afd2f5a456064757', {'component_id': 'cmp-96798a62afd2f5a456064757', 'ecosystem': 'local', 'kind': 'fixture', 'lifecycles': ['repository-used'], 'name': 'input.json', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-bae444d2ed75815c3da47462', {'component_id': 'cmp-bae444d2ed75815c3da47462', 'ecosystem': 'oci', 'kind': 'model-artifact', 'lifecycles': ['deployed'], 'metadata': {'fixture': True, 'artifact_identity': 'example/app'}, 'name': 'app', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-b5e5f51f6ef2c47aceaed9ef', {'component_id': 'cmp-96798a62afd2f5a456064757', 'component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'evidence': ['input.json'], 'resolution_state': 'resolved', 'source_ref': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}),
               ('ver-2f7fb6f98c6733bd705eee92', {'artifact_digest': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'component_id': 'cmp-bae444d2ed75815c3da47462', 'component_version_id': 'ver-2f7fb6f98c6733bd705eee92', 'evidence': ['input.json#/model'], 'metadata': {'fixture': True, 'artifact_identity': 'example/app'}, 'resolution_state': 'resolved'})],
  'occurrences': [('occ-2a29afdeae4619e0b7073ca2', {'component_id': 'cmp-bae444d2ed75815c3da47462', 'component_version_id': 'ver-2f7fb6f98c6733bd705eee92', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/model', 'lifecycle': 'deployed', 'metadata': {'fixture': True, 'artifact_identity': 'example/app'}, 'occurrence_id': 'occ-2a29afdeae4619e0b7073ca2', 'optional': False, 'raw_value': 'example/app', 'role': 'fixture-model', 'root_id': 'cmp-96798a62afd2f5a456064757', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-969de9bc29b2c0e3ef2db6e4', {'edge_id': 'edge-969de9bc29b2c0e3ef2db6e4', 'from_component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'optional': False, 'relationship': 'provides-artifact', 'resolver': 'model-artifact-discovery', 'scope': 'runtime', 'source_occurrence_id': 'occ-2a29afdeae4619e0b7073ca2', 'to_component_version_id': 'ver-2f7fb6f98c6733bd705eee92'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "discovery-no-group": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [],
  'versions': [],
  'occurrences': [],
  'edges': [],
  'extra_gaps': [('gap-133339d52004679dc9bafee0', {'evidence': ['input.json#/resources'], 'gap_id': 'gap-133339d52004679dc9bafee0', 'gap_type': 'live-api-discovery-invalid', 'message': 'API discovery endpoint /api/v1 has no typed resources array', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "discovery-no-array": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [],
  'versions': [],
  'occurrences': [],
  'edges': [],
  'extra_gaps': [('gap-133339d52004679dc9bafee0', {'evidence': ['input.json#/resources'], 'gap_id': 'gap-133339d52004679dc9bafee0', 'gap_type': 'live-api-discovery-invalid', 'message': 'API discovery endpoint /api/v1 has no typed resources array', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "discovery-empty": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-fa36a7b4e43c7144d2ee0f16', {'component_id': 'cmp-fa36a7b4e43c7144d2ee0f16', 'ecosystem': 'kubernetes', 'kind': 'platform', 'lifecycles': ['deployed'], 'metadata': {'inventory_scope': 'cluster'}, 'name': 'kubernetes', 'namespace': 'k8s.io', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:k8s/k8s.io%2Fkubernetes'})],
  'versions': [],
  'occurrences': [],
  'edges': [],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "discovery-defaults": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-fa36a7b4e43c7144d2ee0f16', {'component_id': 'cmp-fa36a7b4e43c7144d2ee0f16', 'ecosystem': 'kubernetes', 'kind': 'platform', 'lifecycles': ['deployed'], 'metadata': {'inventory_scope': 'cluster'}, 'name': 'kubernetes', 'namespace': 'k8s.io', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:k8s/k8s.io%2Fkubernetes'}),
                 ('cmp-1dd1ebc31415ff4307c0b264', {'component_id': 'cmp-1dd1ebc31415ff4307c0b264', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-api', 'lifecycles': ['deployed'], 'metadata': {'api_group': 'core', 'gvk': 'core/v1/Widget'}, 'name': 'Widget', 'namespace': 'core', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-d025308d4100191c10ed65ac', {'component_id': 'cmp-1dd1ebc31415ff4307c0b264', 'component_version_id': 'ver-d025308d4100191c10ed65ac', 'evidence': ['input.json#/resources/0'], 'metadata': {'api_discovery_endpoint': '/api/v1', 'api_resource_name': 'widgets', 'namespaced': None, 'singular_name': None, 'verbs': [], 'short_names': [], 'categories': [], 'storage_version_hash': None}, 'resolution_state': 'resolved', 'resolved_version': 'v1'})],
  'occurrences': [('occ-c6edc736d9e8abae433dd87d', {'component_id': 'cmp-1dd1ebc31415ff4307c0b264', 'component_version_id': 'ver-d025308d4100191c10ed65ac', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/resources/0', 'lifecycle': 'deployed', 'metadata': {'endpoint': '/api/v1'}, 'occurrence_id': 'occ-c6edc736d9e8abae433dd87d', 'optional': False, 'raw_value': 'v1/widgets:Widget', 'role': 'live-kubernetes-api-discovery', 'root_id': 'cmp-fa36a7b4e43c7144d2ee0f16', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "openapi-empty": "(0, {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})], 'components': [], 'versions': [], 'occurrences': [], 'edges': [], 'extra_gaps': [], 'discovery_inputs': [], 'node_platforms': []})",
    "crd-defaults": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-a3e2bcda87c32a7c25488e55', {'component_id': 'cmp-a3e2bcda87c32a7c25488e55', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-crd', 'lifecycles': ['deployed'], 'metadata': {'group': 'unknown', 'resource_kind': 'widgets.example.org'}, 'name': 'widgets.example.org', 'namespace': 'unknown', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-d3b745598baff4e3f9e664d7', {'component_id': 'cmp-a3e2bcda87c32a7c25488e55', 'component_version_id': 'ver-d3b745598baff4e3f9e664d7', 'evidence': ['input.json#/items/0'], 'resolution_state': 'resolved', 'source_ref': '42'})],
  'occurrences': [],
  'edges': [],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "crd-no-schema": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-a3e2bcda87c32a7c25488e55', {'component_id': 'cmp-a3e2bcda87c32a7c25488e55', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-crd', 'lifecycles': ['deployed'], 'metadata': {'group': 'unknown', 'resource_kind': 'widgets.example.org'}, 'name': 'widgets.example.org', 'namespace': 'unknown', 'official_channel_required': True, 'official_channels': []}),
                 ('cmp-13dfb72adc6b2fdef88e4885', {'component_id': 'cmp-13dfb72adc6b2fdef88e4885', 'ecosystem': 'kubernetes', 'kind': 'kubernetes-api', 'lifecycles': ['deployed'], 'metadata': {'api_group': 'unknown', 'gvk': 'unknown/v2/widgets.example.org', 'crd_name': 'widgets.example.org'}, 'name': 'widgets.example.org', 'namespace': 'unknown', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-2515f9ff56dc88460580ff05', {'component_id': 'cmp-a3e2bcda87c32a7c25488e55', 'component_version_id': 'ver-2515f9ff56dc88460580ff05', 'evidence': ['input.json#/items/0'], 'resolution_state': 'resolved'}),
               ('ver-540a6e4315ad4c15a2b8ebfd', {'component_id': 'cmp-13dfb72adc6b2fdef88e4885', 'component_version_id': 'ver-540a6e4315ad4c15a2b8ebfd', 'evidence': ['input.json#/items/0/spec/versions/0'], 'metadata': {'served': None, 'storage': None, 'deprecated': None, 'deprecation_warning': None, 'conversion': None}, 'resolution_state': 'resolved', 'resolved_version': 'v2'})],
  'occurrences': [('occ-57faec4712ee818880046814', {'component_id': 'cmp-13dfb72adc6b2fdef88e4885', 'component_version_id': 'ver-540a6e4315ad4c15a2b8ebfd', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': '/items/0/spec/versions/0', 'lifecycle': 'deployed', 'occurrence_id': 'occ-57faec4712ee818880046814', 'optional': False, 'raw_value': 'unknown/v2/widgets.example.org', 'role': 'live-crd-api', 'root_id': 'cmp-a3e2bcda87c32a7c25488e55', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-eb55216ee6572c0d71cc4317', {'edge_id': 'edge-eb55216ee6572c0d71cc4317', 'from_component_version_id': 'ver-2515f9ff56dc88460580ff05', 'optional': False, 'relationship': 'defines-api', 'resolver': 'live-crd', 'scope': 'api', 'source_occurrence_id': 'occ-57faec4712ee818880046814', 'to_component_version_id': 'ver-540a6e4315ad4c15a2b8ebfd'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
}


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


class ModuleBindingTests(FilesTestCase):
    """Check that each checkout supplies its own registry and capture modules."""

    def test_load_tool_modules(self) -> None:
        """Load two copies while preserving canonical aliases and the import path."""
        self.assertEqual(
            (
                Path(kr.__file__).resolve().parent,
                Path(live.__file__).resolve().parent,
                live.kr,
            ),
            (TOOL_ROOT, TOOL_ROOT, kr),
        )
        first, second = self.root / "first", self.root / "second"
        for root in (first, second):
            root.mkdir()
            for filename in ("knowledge_registry.py", "capture_live.py"):
                shutil.copyfile(TOOL_ROOT / filename, root / filename)
        with patch.dict(sys.modules, {"knowledge_registry": kr, "capture_live": live}):
            before = sys.modules.copy()
            original_path = sys.path.copy()
            a, a_live = load_tool_modules(first)
            b, b_live = load_tool_modules(second)
            self.assertEqual((sys.modules, sys.path), (before, original_path))
        self.assertEqual(
            tuple(Path(module.__file__).resolve() for module in (a, a_live, b, b_live)),
            (
                first / "knowledge_registry.py",
                first / "capture_live.py",
                second / "knowledge_registry.py",
                second / "capture_live.py",
            ),
        )
        self.assertEqual(
            (a_live.kr, b_live.kr, a is b, a_live is b_live), (a, b, False, False)
        )


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
        mixed = escaped + b"[mcp_servers.other]\n" + data.split(b"\n")[-2] + b"\n"
        self.assertEqual(kr.normalize_codex_projection_references(mixed), mixed)
        literal = data + b"[mcp_servers.other]\n" + data.split(b"\n")[-2] + b"\n"
        self.assertEqual(
            kr.normalize_codex_projection_references(literal),
            expected
            + b'"]\n'
            + b"[mcp_servers.other]\n"
            + expected.split(b"\n")[-1]
            + b'"]\n',
        )
        self.assertEqual(kr.normalize_codex_projection_references(b""), b"")
        unrelated = header + b'args = ["--projection", "fixtures/projection.json"]\n'
        self.assertEqual(kr.normalize_codex_projection_references(unrelated), unrelated)
        other_flag = data.replace(b'"--projection"', b'"--projection-other"')
        self.assertEqual(
            kr.normalize_codex_projection_references(other_flag), other_flag
        )
        self.assertEqual(kr.normalize_codex_projection_references(b"\xff"), b"\xff")

    def test_scan_chart_lock(self) -> None:
        """Retain declared ranges and distinguish version and repository mismatches."""
        text = (
            "dependencies:\n  - name: child\n    version: 1.2.3\n"
            "    repository: https://charts.example.org\n"
        )
        chart = "name: app\nversion: 2.0.0\n" + text
        path = self.write("Chart.lock", text)
        self.track("Chart.lock")
        for label, declaration, lock in (
            ("test_scan_chart_lock.1", chart, text),
            ("test_scan_chart_lock.2", chart.replace("1.2.3", "^1.2.0"), text),
            ("test_scan_chart_lock.3", chart, text.replace("1.2.3", "1.2.4")),
            (
                "test_scan_chart_lock.4",
                chart,
                text.replace("charts.example.org", "charts.example.net"),
            ),
        ):
            self.write("Chart.yaml", declaration)
            check_output(
                self,
                EXPECTED,
                label,
                kr.scan_chart_lock,
                kr.Builder(),
                self.root,
                path,
                lock.encode(),
                lock,
            )

    def test_scan_pyproject(self) -> None:
        """Keep exact dependency pins and optional extras while ignoring ordinary strings."""
        text = (
            '[project]\nname = "app"\nversion = "1.2.3"\n'
            'description = "ordinary"\ndependencies = ["Example_Dep[extra]==2.3.4"]\n'
            'requires-python = ">=3.11"\n'
        )
        path = self.write("pyproject.toml", text)
        builder = kr.Builder()
        check_output(
            self,
            EXPECTED,
            "test_scan_pyproject.1",
            kr.scan_pyproject,
            builder,
            self.root,
            path,
            text.encode(),
            text,
        )

    def test_scan_containerd_hosts(self) -> None:
        """Distinguish registry and mirror edges and flag malformed TOML."""
        text = (
            'server = "https://registry.example.org"\n'
            '[host."https://mirror.example.org"]\n'
            'capabilities = ["pull"]\noverride_path = true\nskip_verify = false\nunused = "ignore"\n'
        )
        path = self.write("hosts.toml", text)
        builder = kr.Builder()
        check_output(
            self,
            EXPECTED,
            "test_scan_containerd_hosts.1",
            kr.scan_containerd_hosts,
            builder,
            self.root,
            path,
            text.encode(),
            text,
        )
        bad = kr.Builder()
        check_output(
            self,
            EXPECTED,
            "test_scan_containerd_hosts.2",
            kr.scan_containerd_hosts,
            bad,
            self.root,
            path,
            b"server = [",
            "server = [",
        )

    def test_scan_codex_config(self) -> None:
        """Sort remote tool names and skip local servers without URLs."""
        text = (
            '[mcp_servers.app]\nurl = "https://example.org/mcp"\n'
            'enabled_tools = ["write", "read"]\nrequired = true\nenabled = false\n'
            '[mcp_servers.default]\nurl = "https://example.net/mcp"\n'
            '[mcp_servers.local]\ncommand = "app"\n'
        )
        path = self.write("config.toml", text)
        builder = kr.Builder()
        check_output(
            self,
            EXPECTED,
            "test_scan_codex_config.1",
            kr.scan_codex_config,
            builder,
            self.root,
            path,
            text.encode(),
            text,
        )
        bad = kr.Builder()
        check_output(
            self,
            EXPECTED,
            "test_scan_codex_config.2",
            kr.scan_codex_config,
            bad,
            self.root,
            path,
            b"[",
            "[",
        )

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
        check_output(
            self,
            EXPECTED,
            "test_scan_script_dependencies.1",
            kr.scan_script_dependencies,
            builder,
            self.root,
            path,
            text.encode(),
            text,
        )

    def test_add_workflow_manifest_install(self) -> None:
        """Bind tracked manifests and report untracked inputs as gaps."""
        data = b'{"name":"app","version":"1.2.3"}'
        self.write("app/package.json", data)
        self.write("ignored/package.json", data)
        self.track("app/package.json")
        builder, source, component, version = local_builder()
        check_output(
            self,
            EXPECTED,
            "test_add_workflow_manifest_install.1",
            kr.add_workflow_manifest_install,
            builder,
            self.root,
            source,
            component,
            version,
            working_directory="app",
            locator="/steps/0",
        )
        check_output(
            self,
            EXPECTED,
            "test_add_workflow_manifest_install.2",
            kr.add_workflow_manifest_install,
            builder,
            self.root,
            source,
            component,
            version,
            working_directory="ignored",
            locator="/steps/1",
        )


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
        check_output(
            self,
            EXPECTED,
            "test_add_model_artifact_observation.1",
            kr.add_model_artifact_observation,
            builder,
            source,
            component,
            version,
            **kwargs,
            revision=revision,
            artifact_digest=DIGEST,
            lineage_required=True,
        )

        check_output(
            self,
            EXPECTED,
            "test_add_model_artifact_observation.2",
            kr.add_model_artifact_observation,
            builder,
            source,
            component,
            version,
            **kwargs,
            revision="main",
        )

    def test_add_model_artifact_observation_resolves_revision_without_digest(
        self,
    ) -> None:
        """Resolve an immutable revision when no digest is supplied."""
        builder, source, component, version = local_builder()
        revision = "1.2.3"
        check_output(
            self,
            EXPECTED,
            "test_add_model_artifact_observation_resolves_revision_without_digest.1",
            kr.add_model_artifact_observation,
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

    def assert_projection(
        self,
        kind: str,
        payload: Record,
        surface: str,
        response_type: str,
        expected_kind: str | None,
    ) -> None:
        """Check the unchanged payload projection and the exact query sent to the runtime."""
        with patch.object(
            live, "project_query_payload", wraps=live.project_query_payload
        ) as project:
            result = kr.enforce_exact_live_projection(payload, kind, live)
        ((query, projected),) = [entry.args for entry in project.call_args_list]
        self.assertEqual(
            (result, asdict(query), projected),
            (
                None,
                {
                    "surface": surface,
                    "filename": "projection.json",
                    "args": (),
                    "expected_kind": expected_kind,
                    "response_type": response_type,
                },
                payload,
            ),
        )

    def test_enforce_exact_live_projection(self) -> None:
        """Accept exact server, discovery, resource, and OpenAPI documents."""
        self.assert_projection(
            "server-version",
            {"serverVersion": {"gitVersion": "v1.2.3"}},
            "server-version",
            "server-version",
            None,
        )
        self.assert_projection(
            "APIResourceList",
            {
                "apiVersion": "v1",
                "kind": "APIResourceList",
                "groupVersion": "widgets.example.org/v1",
                "resources": [
                    {"name": "widgets", "kind": "Widget", "namespaced": False}
                ],
            },
            "api-discovery",
            "api-resource-list",
            "APIResourceList",
        )
        self.assert_projection(
            "OpenAPIv3Document",
            {
                "openapi": "3.0.0",
                "components": {"schemas": {"example.Widget": {"type": "object"}}},
            },
            "builtin-openapi",
            "openapi-document",
            "OpenAPIv3Document",
        )
        self.assert_projection(
            "OpenAPIv3Discovery",
            {
                "paths": {"api/v1": {"serverRelativeURL": "/openapi/v3/api/v1"}},
            },
            "builtin-openapi",
            "openapi-index",
            "OpenAPIv3Discovery",
        )
        for kind, field, values in (
            ("APIVersions", "versions", ["v1"]),
            ("APIGroupList", "groups", []),
        ):
            self.assert_projection(
                kind,
                {"apiVersion": "v1", "kind": kind, field: values},
                "api-discovery",
                "typed-object",
                kind,
            )

    def test_enforce_exact_typed_list_projections(self) -> None:
        """Accept a typed list from each supported live object family."""
        for kind, version in (
            ("Application", "argoproj.io/v1alpha1"),
            ("ApplicationSet", "argoproj.io/v1alpha1"),
            ("ClusterSbomReport", "aquasecurity.github.io/v1alpha1"),
            ("CustomResourceDefinition", "apiextensions.k8s.io/v1"),
            ("Namespace", "v1"),
            ("Node", "v1"),
            ("Pod", "v1"),
            ("SbomReport", "aquasecurity.github.io/v1alpha1"),
        ):
            with self.subTest(kind=kind):
                self.assert_projection(
                    kind,
                    {
                        "apiVersion": version,
                        "kind": f"{kind}List",
                        "metadata": {},
                        "items": [],
                    },
                    "projection",
                    "typed-list",
                    kind,
                )

    def test_enforce_exact_live_projection_rejects_drift(self) -> None:
        """Refuse additional fields, unsupported document types, and malformed projections."""
        server = {"serverVersion": {"gitVersion": "v1.2.3"}}
        cases = (
            (
                {**server, "extra": "ignored"},
                "server-version",
                "live export is not the exact identity-only projection",
            ),
            (server, "unknown", "live export has an unsupported document type"),
            ({}, "server-version", "live export violates identity-only projection"),
            (
                {"data": {}},
                "server-version",
                "live export violates identity-only projection at /data",
            ),
        )
        for payload, kind, message in cases:
            with self.subTest(kind=kind, message=message):
                with self.assertRaises(kr.RegistryInputError) as caught:
                    kr.enforce_exact_live_projection(payload, kind, live)
                self.assertEqual(
                    (type(caught.exception), str(caught.exception)),
                    (kr.RegistryInputError, message),
                )

    def test_import_api_resource_list(self) -> None:
        """Emit one typed resource and flag a non-object with its pointer."""
        builder, source = source_builder()
        group_version = "v1"
        payload = {
            "groupVersion": group_version,
            "resources": [
                {
                    "name": "widgets",
                    "kind": "Widget",
                    "namespaced": False,
                    "verbs": ["get", "list"],
                    "singularName": "widget",
                    "shortNames": ["wd"],
                    "categories": ["example"],
                    "storageVersionHash": "example-storage-hash",
                },
                "invalid",
                {"name": "missing-kind"},
            ],
        }
        check_output(
            self,
            EXPECTED,
            "test_import_api_resource_list.1",
            kr.import_api_resource_list,
            builder,
            source,
            payload,
            endpoint="/api/v1",
        )

    def test_import_openapi_v3_document(self) -> None:
        """Count only complete kinds and retain each schema's escaped evidence pointer."""
        builder, source = source_builder()
        schema = {
            "type": "object",
            "x-kubernetes-group-version-kind": [
                {"group": "", "version": "v1", "kind": "Widget"},
                {"group": "", "kind": "Incomplete"},
                {"group": "other.example.org", "version": "v1"},
                "invalid",
            ],
        }
        payload = {
            "openapi": "3.0.0",
            "components": {
                "schemas": {
                    "example/item": schema,
                    "example/no-gvks": {"type": "object"},
                    "example/invalid": False,
                    "example/alternate": {
                        "type": "object",
                        "x-kubernetes-group-version-kind": [
                            {"group": "", "version": "v1", "kind": "Alternate"}
                        ],
                    },
                }
            },
        }
        check_output(
            self,
            EXPECTED,
            "test_import_openapi_v3_document.1",
            kr.import_openapi_v3_document,
            builder,
            source,
            payload,
            endpoint="/openapi/v3/api/v1",
        )
        check_output(
            self,
            EXPECTED,
            "test_import_openapi_v3_document.2",
            kr.import_openapi_v3_document,
            builder,
            source,
            {},
            endpoint="/openapi/v3",
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
                    False,
                    {
                        "name": "v1",
                        "schema": schema,
                        "served": True,
                        "storage": False,
                        "deprecated": True,
                        "deprecationWarning": "Use v2.",
                    },
                ],
                "conversion": {"strategy": "None"},
            },
        }
        check_output(
            self,
            EXPECTED,
            "test_import_crd_item.1",
            kr.import_crd_item,
            builder,
            source,
            payload,
            2,
        )

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
        check_output(
            self,
            EXPECTED,
            "test_import_argo_item.1",
            kr.import_argo_item,
            builder,
            source,
            item,
            3,
        )

        item["status"]["sync"] = {"revisions": ["1.2.4", "1.2.5"]}
        bad, bad_source = source_builder()
        check_output(
            self,
            EXPECTED,
            "test_import_argo_item.2",
            kr.import_argo_item,
            bad,
            bad_source,
            item,
            3,
        )

    def test_observation_defaults(self) -> None:
        """Keep the complete output for absent discovery, schemas, and CRD versions."""
        builder, source = source_builder()
        check_output(
            self,
            EXPECTED,
            "discovery-no-group",
            kr.import_api_resource_list,
            builder,
            source,
            {"resources": []},
            endpoint="/api/v1",
        )
        builder, source = source_builder()
        check_output(
            self,
            EXPECTED,
            "discovery-no-array",
            kr.import_api_resource_list,
            builder,
            source,
            {"groupVersion": "v1"},
            endpoint="/api/v1",
        )
        builder, source = source_builder()
        check_output(
            self,
            EXPECTED,
            "discovery-empty",
            kr.import_api_resource_list,
            builder,
            source,
            {"groupVersion": "v1", "resources": []},
            endpoint="/api/v1",
        )
        builder, source = source_builder()
        check_output(
            self,
            EXPECTED,
            "discovery-defaults",
            kr.import_api_resource_list,
            builder,
            source,
            {
                "groupVersion": "v1",
                "resources": [{"kind": "Widget", "name": "widgets"}],
            },
            endpoint="/api/v1",
        )

    def test_schema_and_crd_defaults(self) -> None:
        """Keep whole observations for empty schemas and missing CRD versions or digests."""
        builder, source = source_builder()
        check_output(
            self,
            EXPECTED,
            "openapi-empty",
            kr.import_openapi_v3_document,
            builder,
            source,
            {"components": {"schemas": {}}},
            endpoint="/openapi/v3",
        )
        builder, source = source_builder()
        check_output(
            self,
            EXPECTED,
            "crd-defaults",
            kr.import_crd_item,
            builder,
            source,
            {"metadata": {"name": "widgets.example.org", "resourceVersion": "42"}},
            0,
        )
        builder, source = source_builder()
        check_output(
            self,
            EXPECTED,
            "crd-no-schema",
            kr.import_crd_item,
            builder,
            source,
            {
                "metadata": {"name": "widgets.example.org"},
                "spec": {"versions": [{"name": "v2"}]},
            },
            0,
        )

    def test_model_artifact_digest_only(self) -> None:
        """Resolve content with a digest even when the artifact has no revision."""
        builder, source, component, version = local_builder()
        check_output(
            self,
            EXPECTED,
            "model-digest-only",
            kr.add_model_artifact_observation,
            builder,
            source,
            component,
            version,
            ecosystem="oci",
            identity="example/app",
            name="app",
            locator="/model",
            raw_value="example/app",
            role="fixture-model",
            artifact_digest=DIGEST,
            lifecycle="deployed",
            metadata={"fixture": True},
            root_relationship="provides-artifact",
        )

    def test_argo_empty_status(self) -> None:
        """Record an application with no observed revision, sources, or resources."""
        builder, source = source_builder()
        check_output(
            self,
            EXPECTED,
            "argo-empty",
            kr.import_argo_item,
            builder,
            source,
            {
                "kind": "ApplicationSet",
                "metadata": {"name": "app", "namespace": "example"},
            },
            0,
        )

    @staticmethod
    def argo_multi_source_item() -> Record:
        """Describe an application with observed sources, images, and API resources."""
        return {
            "kind": "Application",
            "metadata": {
                "name": "app",
                "namespace": "example",
                "uid": "fixture-id",
                "resourceVersion": "42",
            },
            "status": {
                "sync": {"status": "Synced"},
                "health": {"status": "Healthy"},
                "reconciledAt": OBSERVED,
                "operationState": {
                    "phase": "Succeeded",
                    "startedAt": OBSERVED,
                    "finishedAt": LATER,
                    "syncResult": {
                        "revisions": ["b" * 40, "2.0.1"],
                        "images": ["registry.example.org/example/app@" + DIGEST],
                    },
                },
                "summary": {
                    "images": [
                        "registry.example.org/example/app@" + "sha256:" + "b" * 64,
                        "{{ .Values.image }}",
                        42,
                    ]
                },
                "resources": [
                    False,
                    {
                        "group": "apps",
                        "version": "v1",
                        "kind": "Deployment",
                        "name": "app",
                        "namespace": "example",
                        "status": "Synced",
                    },
                    {},
                ],
            },
            "spec": {
                "sources": [
                    {
                        "repoURL": "https://git.example.org/example/app.git",
                        "path": "app",
                        "targetRevision": "main",
                    },
                    {
                        "repoURL": "https://charts.example.org",
                        "chart": "app",
                        "targetRevision": "2.0.0",
                    },
                ]
            },
        }

    def test_argo_status_and_multiple_sources(self) -> None:
        """Capture deployment metadata, observed images, Git paths, and API resources."""
        builder, source = source_builder()
        check_output(
            self,
            EXPECTED,
            "argo-observed-sources",
            kr.import_argo_item,
            builder,
            source,
            self.argo_multi_source_item(),
            1,
        )

    def test_argo_git_target_without_observed_revision(self) -> None:
        """Retain a Git target and repository-name fallback without sync evidence."""
        builder, source = source_builder()
        item = {
            "metadata": {"name": "app"},
            "spec": {
                "sources": [
                    False,
                    {
                        "repoURL": "https://git.example.org/example/app.git",
                        "targetRevision": "main",
                    },
                ]
            },
        }
        check_output(
            self,
            EXPECTED,
            "argo-git-target",
            kr.import_argo_item,
            builder,
            source,
            item,
            0,
        )

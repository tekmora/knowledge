# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

import errno
import io
import json
import os
import sys
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

# Resolve sibling fixtures in this checkout even when another net was loaded earlier.
fixture_dir = Path(__file__).resolve().parent
with patch.dict(sys.modules):
    for sibling in (
        "test_registry_function_net",
        "test_registry_function_net_channels",
    ):
        cached_path = getattr(sys.modules.get(sibling), "__file__", None)
        if cached_path is None or Path(cached_path).resolve().parent != fixture_dir:
            sys.modules.pop(sibling, None)
    with patch.object(sys, "path", [str(fixture_dir), *sys.path]):
        from test_registry_function_net import (
            CHANNEL_URI,
            DIGEST,
            LATER,
            OBSERVED,
            FilesTestCase,
            Record,
            check_output,
            kr,
            live,
            local_builder,
        )
        from test_registry_function_net_channels import (
            ManifestFixtureTestCase,
            package_builder,
            policy_entry,
        )


EXPECTED: dict[str, str] = {
    "chart-lock-missing-entry": r"""(None,
 {'sources': [('src-1572cd6aa962300e1955906a', {'content_hash': 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'evidence_uri': 'Chart.lock', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-1572cd6aa962300e1955906a', 'source_type': 'helm-chart-lock'}),
              ('src-87186594c915fffba221ed49', {'content_hash': 'sha256:7bbded9435491a9c17f3fa146298f93c0a46ac616fe517a71dfe3f7eb373ea3f', 'evidence_uri': 'Chart.yaml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-87186594c915fffba221ed49', 'source_type': 'helm-chart-metadata'})],
  'components': [('cmp-10e5b92b9c672353486d6b0d', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-6512cc76719e470e437585ca', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'component_version_id': 'ver-6512cc76719e470e437585ca', 'evidence': ['Chart.yaml'], 'resolution_state': 'resolved', 'resolved_version': '2.0.0', 'source_ref': 'sha256:7bbded9435491a9c17f3fa146298f93c0a46ac616fe517a71dfe3f7eb373ea3f'})],
  'occurrences': [],
  'edges': [],
  'extra_gaps': [('gap-cb02cd97a73d6f8549514d9d', {'component_id': 'cmp-10e5b92b9c672353486d6b0d', 'component_version_id': 'ver-6512cc76719e470e437585ca', 'evidence': ['Chart.lock#L4'], 'gap_id': 'gap-cb02cd97a73d6f8549514d9d', 'gap_type': 'helm-lock-entry-missing', 'message': "Chart.lock does not lock declared dependency 'child'", 'source_id': 'src-1572cd6aa962300e1955906a'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "chart-lock-no-sibling": r"""(None,
 {'sources': [('src-40f7b9bd89a2d31c49d1c1a7', {'content_hash': 'sha256:1aa3dc798aac40bd127a805756f38f6de566a48919d6efe1b529fc80faaa1fb9', 'evidence_uri': 'Chart.lock', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-40f7b9bd89a2d31c49d1c1a7', 'source_type': 'helm-chart-lock'})],
  'components': [('cmp-faeaf465b92612d22be57e87', {'component_id': 'cmp-faeaf465b92612d22be57e87', 'ecosystem': 'local', 'kind': 'helm-lock', 'lifecycles': ['repository-used'], 'name': 'Chart.lock', 'namespace': '', 'official_channel_required': False, 'official_channels': []}), ('cmp-d3f8451d31a4b4ccfb96ae72', {'component_id': 'cmp-d3f8451d31a4b4ccfb96ae72', 'ecosystem': 'helm', 'kind': 'helm-chart', 'lifecycles': ['repository-used'], 'name': 'child', 'namespace': '', 'official_channel_required': True, 'official_channels': []})],
  'versions': [('ver-42c362d89b652c638e19b99e', {'component_id': 'cmp-faeaf465b92612d22be57e87', 'component_version_id': 'ver-42c362d89b652c638e19b99e', 'evidence': ['Chart.lock'], 'resolution_state': 'resolved', 'source_ref': 'sha256:1aa3dc798aac40bd127a805756f38f6de566a48919d6efe1b529fc80faaa1fb9'}), ('ver-3587c5ed82ee40f5e0569085', {'component_id': 'cmp-d3f8451d31a4b4ccfb96ae72', 'component_version_id': 'ver-3587c5ed82ee40f5e0569085', 'evidence': ['Chart.lock#L2'], 'resolution_state': 'unresolved'})],
  'occurrences': [('occ-eb512a14a03d13d10f03ee0f', {'component_id': 'cmp-d3f8451d31a4b4ccfb96ae72', 'component_version_id': 'ver-3587c5ed82ee40f5e0569085', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': 'line:2:lock:0', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-eb512a14a03d13d10f03ee0f', 'optional': False, 'raw_value': 'child@', 'role': 'helm-locked-dependency', 'root_id': 'cmp-faeaf465b92612d22be57e87', 'source_id': 'src-40f7b9bd89a2d31c49d1c1a7'})],
  'edges': [('edge-77eb406383602528a7d33ce4', {'edge_id': 'edge-77eb406383602528a7d33ce4', 'from_component_version_id': 'ver-42c362d89b652c638e19b99e', 'optional': False, 'relationship': 'locks', 'resolver': 'helm-lock', 'scope': 'runtime', 'source_occurrence_id': 'occ-eb512a14a03d13d10f03ee0f', 'to_component_version_id': 'ver-3587c5ed82ee40f5e0569085'})],
  'extra_gaps': [('gap-79502360d7377c7c49740429', {'component_id': 'cmp-faeaf465b92612d22be57e87', 'component_version_id': 'ver-42c362d89b652c638e19b99e', 'evidence': ['Chart.lock'], 'gap_id': 'gap-79502360d7377c7c49740429', 'gap_type': 'helm-chart-root-missing', 'message': 'Chart.lock has no sibling Chart.yaml to own its locked dependencies', 'source_id': 'src-40f7b9bd89a2d31c49d1c1a7'}),
                 ('gap-0470daea2d9091c84c034558', {'component_id': 'cmp-faeaf465b92612d22be57e87', 'component_version_id': 'ver-42c362d89b652c638e19b99e', 'evidence': ['Chart.lock'], 'gap_id': 'gap-0470daea2d9091c84c034558', 'gap_type': 'helm-lock-untracked', 'message': 'Chart.lock supplies exact dependency versions but is ignored/untracked', 'source_id': 'src-40f7b9bd89a2d31c49d1c1a7'}),
                 ('gap-aa15ec6adbf48a444e6566ff', {'component_id': 'cmp-faeaf465b92612d22be57e87', 'component_version_id': 'ver-42c362d89b652c638e19b99e', 'evidence': ['Chart.lock#L2'], 'gap_id': 'gap-aa15ec6adbf48a444e6566ff', 'gap_type': 'helm-lock-dependency-undeclared', 'message': "Chart.lock locks undeclared dependency 'child'", 'source_id': 'src-40f7b9bd89a2d31c49d1c1a7'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "codex-missing": "(None, {'sources': [], 'components': [], 'versions': [], 'occurrences': [], 'edges': [], 'extra_gaps': [], 'discovery_inputs': [], 'node_platforms': []})",
    "codex-empty": r"""(None,
 {'sources': [('src-37d1d97c5ba0caa2519e09ba', {'content_hash': 'sha256:e11d8f2c76c401cfee5870c24e805d1745ca0c1ef4beb525b9258faece8dc9ae', 'evidence_uri': 'config.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-37d1d97c5ba0caa2519e09ba', 'source_type': 'codex-config'})],
  'components': [('cmp-0e2047679351ff658356304a', {'component_id': 'cmp-0e2047679351ff658356304a', 'ecosystem': 'local', 'kind': 'codex-config', 'lifecycles': ['repository-used'], 'name': 'config.toml', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-3b773ac41cc12bc88741fcb0', {'component_id': 'cmp-0e2047679351ff658356304a', 'component_version_id': 'ver-3b773ac41cc12bc88741fcb0', 'evidence': ['config.toml'], 'resolution_state': 'resolved', 'source_ref': 'sha256:e11d8f2c76c401cfee5870c24e805d1745ca0c1ef4beb525b9258faece8dc9ae'})],
  'occurrences': [],
  'edges': [],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "codex-non-table-entry": r"""(None,
 {'sources': [('src-de779db89e5e65b360cd3856', {'content_hash': 'sha256:99d773d95e68b6a3c84790cff06827e4899cf695a9196f84c46c430b76d96e26', 'evidence_uri': 'config.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-de779db89e5e65b360cd3856', 'source_type': 'codex-config'})],
  'components': [('cmp-0e2047679351ff658356304a', {'component_id': 'cmp-0e2047679351ff658356304a', 'ecosystem': 'local', 'kind': 'codex-config', 'lifecycles': ['repository-used'], 'name': 'config.toml', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-3d43fce0d3a249227c657630', {'component_id': 'cmp-0e2047679351ff658356304a', 'component_version_id': 'ver-3d43fce0d3a249227c657630', 'evidence': ['config.toml'], 'resolution_state': 'resolved', 'source_ref': 'sha256:99d773d95e68b6a3c84790cff06827e4899cf695a9196f84c46c430b76d96e26'})],
  'occurrences': [],
  'edges': [],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "containerd-no-endpoints": "(None, {'sources': [], 'components': [], 'versions': [], 'occurrences': [], 'edges': [], 'extra_gaps': [], 'discovery_inputs': [], 'node_platforms': []})",
    "containerd-bare-mirror": r"""(None,
 {'sources': [('src-a269f7570ea690bc3b7103db', {'content_hash': 'sha256:942754740c07ed8d53e4c2a42558d7260eb11d71b4b8b02edc085a1eff611c05', 'evidence_uri': 'hosts.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-a269f7570ea690bc3b7103db', 'source_type': 'containerd-hosts'})],
  'components': [('cmp-bf447d20dea721e92f1f0db9', {'component_id': 'cmp-bf447d20dea721e92f1f0db9', 'ecosystem': 'local', 'kind': 'containerd-hosts', 'lifecycles': ['repository-used'], 'name': 'hosts.toml', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-1ceabc92035cd5e96035d3c2', {'component_id': 'cmp-1ceabc92035cd5e96035d3c2', 'ecosystem': 'oci-registry', 'kind': 'registry-endpoint', 'lifecycles': ['repository-used'], 'metadata': {'endpoint': 'https://mirror.example.org'}, 'name': 'https://mirror.example.org', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-7b71971e750bdf1821280167', {'component_id': 'cmp-bf447d20dea721e92f1f0db9', 'component_version_id': 'ver-7b71971e750bdf1821280167', 'evidence': ['hosts.toml'], 'resolution_state': 'resolved', 'source_ref': 'sha256:942754740c07ed8d53e4c2a42558d7260eb11d71b4b8b02edc085a1eff611c05'}),
               ('ver-1531f7c8af214e2f02ffd4cf', {'component_id': 'cmp-1ceabc92035cd5e96035d3c2', 'component_version_id': 'ver-1531f7c8af214e2f02ffd4cf', 'evidence': ['hosts.toml#L1'], 'resolution_state': 'resolved', 'source_ref': 'sha256:942754740c07ed8d53e4c2a42558d7260eb11d71b4b8b02edc085a1eff611c05'})],
  'occurrences': [('occ-e6c50923a39c998c5b176143', {'component_id': 'cmp-1ceabc92035cd5e96035d3c2', 'component_version_id': 'ver-1531f7c8af214e2f02ffd4cf', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': 'line:1', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-e6c50923a39c998c5b176143', 'optional': False, 'raw_value': 'https://mirror.example.org', 'role': 'containerd-registry-mirror', 'root_id': 'cmp-bf447d20dea721e92f1f0db9', 'source_id': 'src-a269f7570ea690bc3b7103db'})],
  'edges': [('edge-4076c6e36232d1e602b5977a', {'edge_id': 'edge-4076c6e36232d1e602b5977a', 'from_component_version_id': 'ver-7b71971e750bdf1821280167', 'optional': False, 'relationship': 'routes-through', 'resolver': 'containerd-hosts', 'scope': 'deployment', 'source_occurrence_id': 'occ-e6c50923a39c998c5b176143', 'to_component_version_id': 'ver-1531f7c8af214e2f02ffd4cf'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "containerd-server-only": r"""(None,
 {'sources': [('src-e236ea4b52b29f4dfb218701', {'content_hash': 'sha256:b6d2095ab3fbd9c1adcdd8e5891c7357c87e085f52572e066b59f479b896c22f', 'evidence_uri': 'hosts.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-e236ea4b52b29f4dfb218701', 'source_type': 'containerd-hosts'})],
  'components': [('cmp-bf447d20dea721e92f1f0db9', {'component_id': 'cmp-bf447d20dea721e92f1f0db9', 'ecosystem': 'local', 'kind': 'containerd-hosts', 'lifecycles': ['repository-used'], 'name': 'hosts.toml', 'namespace': '', 'official_channel_required': False, 'official_channels': []}),
                 ('cmp-46b2866a7f560d01e5a21285', {'component_id': 'cmp-46b2866a7f560d01e5a21285', 'ecosystem': 'oci-registry', 'kind': 'registry-endpoint', 'lifecycles': ['repository-used'], 'metadata': {'endpoint': 'https://registry.example.org'}, 'name': 'https://registry.example.org', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-a9f50b9927ceb502d1946eb8', {'component_id': 'cmp-bf447d20dea721e92f1f0db9', 'component_version_id': 'ver-a9f50b9927ceb502d1946eb8', 'evidence': ['hosts.toml'], 'resolution_state': 'resolved', 'source_ref': 'sha256:b6d2095ab3fbd9c1adcdd8e5891c7357c87e085f52572e066b59f479b896c22f'}),
               ('ver-407b65231685a56385635d01', {'component_id': 'cmp-46b2866a7f560d01e5a21285', 'component_version_id': 'ver-407b65231685a56385635d01', 'evidence': ['hosts.toml#L2'], 'resolution_state': 'resolved', 'source_ref': 'sha256:b6d2095ab3fbd9c1adcdd8e5891c7357c87e085f52572e066b59f479b896c22f'})],
  'occurrences': [('occ-05ff7cca6dbca118ef11d758', {'component_id': 'cmp-46b2866a7f560d01e5a21285', 'component_version_id': 'ver-407b65231685a56385635d01', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': 'line:2', 'lifecycle': 'repository-used', 'metadata': {'registry_server': True}, 'occurrence_id': 'occ-05ff7cca6dbca118ef11d758', 'optional': False, 'raw_value': 'https://registry.example.org', 'role': 'containerd-registry-server', 'root_id': 'cmp-bf447d20dea721e92f1f0db9', 'source_id': 'src-e236ea4b52b29f4dfb218701'})],
  'edges': [('edge-90ec13e22aed359243a152dd', {'edge_id': 'edge-90ec13e22aed359243a152dd', 'from_component_version_id': 'ver-a9f50b9927ceb502d1946eb8', 'metadata': {'registry_server': True}, 'optional': False, 'relationship': 'configures', 'resolver': 'containerd-hosts', 'scope': 'deployment', 'source_occurrence_id': 'occ-05ff7cca6dbca118ef11d758', 'to_component_version_id': 'ver-407b65231685a56385635d01'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "containerd-empty-hosts": r"""(None,
 {'sources': [('src-480411c63379051b3963ae00', {'content_hash': 'sha256:68a47e0c62f73bd218aa5b090bc1477912cbd9d24ce0d19b62ff105e7f92c463', 'evidence_uri': 'hosts.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-480411c63379051b3963ae00', 'source_type': 'containerd-hosts'})],
  'components': [('cmp-bf447d20dea721e92f1f0db9', {'component_id': 'cmp-bf447d20dea721e92f1f0db9', 'ecosystem': 'local', 'kind': 'containerd-hosts', 'lifecycles': ['repository-used'], 'name': 'hosts.toml', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-a75d432643edde5efeb1f217', {'component_id': 'cmp-bf447d20dea721e92f1f0db9', 'component_version_id': 'ver-a75d432643edde5efeb1f217', 'evidence': ['hosts.toml'], 'resolution_state': 'resolved', 'source_ref': 'sha256:68a47e0c62f73bd218aa5b090bc1477912cbd9d24ce0d19b62ff105e7f92c463'})],
  'occurrences': [],
  'edges': [],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "pyproject-defaults": r"""(None,
 {'sources': [('src-4c677a33f142585f412bd332', {'content_hash': 'sha256:b9ffb22a624a641e612694b272f124324ec0f7892988ce2b1fbd552239ea8c45', 'evidence_uri': 'app/pyproject.toml', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-4c677a33f142585f412bd332', 'source_type': 'python-pyproject'})],
  'components': [('cmp-05eda4d7a3fe7d6f7761cd4a', {'component_id': 'cmp-05eda4d7a3fe7d6f7761cd4a', 'ecosystem': 'pypi', 'kind': 'python-project', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': [], 'purl': 'pkg:pypi/app'}),
                 ('cmp-257fc68c98b4e395108581b2', {'component_id': 'cmp-257fc68c98b4e395108581b2', 'ecosystem': 'pypi', 'kind': 'library', 'lifecycles': ['repository-used'], 'name': 'example-dep', 'namespace': '', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:pypi/example-dep'}),
                 ('cmp-6a8a2cf681f7297195a653fc', {'component_id': 'cmp-6a8a2cf681f7297195a653fc', 'ecosystem': 'pypi', 'kind': 'library', 'lifecycles': ['repository-used'], 'name': 'other', 'namespace': '', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:pypi/other'})],
  'versions': [('ver-45e5c3cd0ec04cedd2a6c9ff', {'component_id': 'cmp-05eda4d7a3fe7d6f7761cd4a', 'component_version_id': 'ver-45e5c3cd0ec04cedd2a6c9ff', 'evidence': ['app/pyproject.toml'], 'resolution_state': 'resolved', 'source_ref': 'sha256:b9ffb22a624a641e612694b272f124324ec0f7892988ce2b1fbd552239ea8c45'}), ('ver-5a2258d36e1f956f0c7bbad3', {'component_id': 'cmp-257fc68c98b4e395108581b2', 'component_version_id': 'ver-5a2258d36e1f956f0c7bbad3', 'evidence': ['app/pyproject.toml#line:2:column:17'], 'resolution_state': 'unresolved'}),
               ('ver-c25c205dec3e1c5f0566706f', {'component_id': 'cmp-6a8a2cf681f7297195a653fc', 'component_version_id': 'ver-c25c205dec3e1c5f0566706f', 'evidence': ['app/pyproject.toml#line:2:column:39'], 'metadata': {'marker': 'python_version < 3.15'}, 'resolution_state': 'unresolved'})],
  'occurrences': [('occ-1bce1232778eebbe80ba4783', {'component_id': 'cmp-257fc68c98b4e395108581b2', 'component_version_id': 'ver-5a2258d36e1f956f0c7bbad3', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': 'line:2:column:17', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-1bce1232778eebbe80ba4783', 'optional': True, 'raw_value': 'Example_Dep', 'role': 'pyproject-dependency', 'root_id': 'cmp-05eda4d7a3fe7d6f7761cd4a', 'source_id': 'src-4c677a33f142585f412bd332'}),
                  ('occ-bac5af596371ff67bbb98d78', {'component_id': 'cmp-6a8a2cf681f7297195a653fc', 'component_version_id': 'ver-c25c205dec3e1c5f0566706f', 'dependency_scope': 'runtime', 'directness': 'direct', 'evidence_locator': 'line:2:column:39', 'lifecycle': 'repository-used', 'metadata': {'marker': 'python_version < 3.15'}, 'occurrence_id': 'occ-bac5af596371ff67bbb98d78', 'optional': False, 'raw_value': 'other', 'role': 'pyproject-dependency', 'root_id': 'cmp-05eda4d7a3fe7d6f7761cd4a', 'source_id': 'src-4c677a33f142585f412bd332'})],
  'edges': [('edge-eb17ed8b418e07675647f859', {'edge_id': 'edge-eb17ed8b418e07675647f859', 'from_component_version_id': 'ver-45e5c3cd0ec04cedd2a6c9ff', 'optional': True, 'relationship': 'depends-on', 'resolver': 'python-manifest', 'scope': 'runtime', 'source_occurrence_id': 'occ-1bce1232778eebbe80ba4783', 'to_component_version_id': 'ver-5a2258d36e1f956f0c7bbad3'}),
            ('edge-a13c4175a16beff87fab0f85', {'edge_id': 'edge-a13c4175a16beff87fab0f85', 'from_component_version_id': 'ver-45e5c3cd0ec04cedd2a6c9ff', 'metadata': {'marker': 'python_version < 3.15'}, 'optional': False, 'relationship': 'depends-on', 'resolver': 'python-manifest', 'scope': 'runtime', 'source_occurrence_id': 'occ-bac5af596371ff67bbb98d78', 'to_component_version_id': 'ver-c25c205dec3e1c5f0566706f'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "script-empty": "(None, {'sources': [], 'components': [], 'versions': [], 'occurrences': [], 'edges': [], 'extra_gaps': [], 'discovery_inputs': [], 'node_platforms': []})",
    "script-ranged-pin": r"""(None,
 {'sources': [('src-53a424fea65348bdb2b7a9e2', {'content_hash': 'sha256:d22d7204efefc07781701766eb556bda918c85f7e033c3fb0f71e64e266fd8cb', 'evidence_uri': 'app.py', 'metadata': {'evidence_class': 'repository'}, 'source_id': 'src-53a424fea65348bdb2b7a9e2', 'source_type': 'script-dependencies'})],
  'components': [('cmp-573ec625b75de401a754c4db', {'component_id': 'cmp-573ec625b75de401a754c4db', 'ecosystem': 'local', 'kind': 'automation-script', 'lifecycles': ['repository-used'], 'name': 'app.py', 'namespace': '', 'official_channel_required': False, 'official_channels': []}), ('cmp-d80183028eb6e50b2f53021e', {'component_id': 'cmp-d80183028eb6e50b2f53021e', 'ecosystem': 'pypi', 'kind': 'library', 'lifecycles': ['repository-used'], 'name': 'pyyaml', 'namespace': '', 'official_channel_required': True, 'official_channels': [], 'purl': 'pkg:pypi/pyyaml'})],
  'versions': [('ver-29b1104305b017ea4508138a', {'component_id': 'cmp-573ec625b75de401a754c4db', 'component_version_id': 'ver-29b1104305b017ea4508138a', 'evidence': ['app.py'], 'resolution_state': 'resolved', 'source_ref': 'sha256:d22d7204efefc07781701766eb556bda918c85f7e033c3fb0f71e64e266fd8cb'}), ('ver-24ad8a8117694318538f56d4', {'component_id': 'cmp-d80183028eb6e50b2f53021e', 'component_version_id': 'ver-24ad8a8117694318538f56d4', 'constraint': '>=1.2.3', 'evidence': ['app.py#L1', 'app.py#line:1', 'requirements.txt#L1'], 'resolution_state': 'unresolved'})],
  'occurrences': [('occ-c995e71ae306b599a3aadeb9', {'component_id': 'cmp-d80183028eb6e50b2f53021e', 'component_version_id': 'ver-24ad8a8117694318538f56d4', 'dependency_scope': 'automation', 'directness': 'direct', 'evidence_locator': 'line:1', 'lifecycle': 'repository-used', 'metadata': {'distribution': 'PyYAML'}, 'occurrence_id': 'occ-c995e71ae306b599a3aadeb9', 'optional': False, 'raw_value': 'PyYAML>=1.2.3', 'role': 'script-direct-dependency', 'root_id': 'cmp-573ec625b75de401a754c4db', 'source_id': 'src-53a424fea65348bdb2b7a9e2'})],
  'edges': [('edge-c592494a40415813e7330b19', {'constraint': '>=1.2.3', 'edge_id': 'edge-c592494a40415813e7330b19', 'from_component_version_id': 'ver-29b1104305b017ea4508138a', 'metadata': {'distribution': 'PyYAML'}, 'optional': False, 'relationship': 'depends-on', 'resolver': 'sibling-python-requirements', 'scope': 'automation', 'source_occurrence_id': 'occ-c995e71ae306b599a3aadeb9', 'to_component_version_id': 'ver-24ad8a8117694318538f56d4'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "workflow-defaults": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-96798a62afd2f5a456064757', {'component_id': 'cmp-96798a62afd2f5a456064757', 'ecosystem': 'local', 'kind': 'fixture', 'lifecycles': ['repository-used'], 'name': 'input.json', 'namespace': '', 'official_channel_required': False, 'official_channels': []}), ('cmp-9c5c40f09cf1dd84c78a24ef', {'component_id': 'cmp-9c5c40f09cf1dd84c78a24ef', 'ecosystem': 'npm', 'kind': 'node-project', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-b5e5f51f6ef2c47aceaed9ef', {'component_id': 'cmp-96798a62afd2f5a456064757', 'component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'evidence': ['input.json'], 'resolution_state': 'resolved', 'source_ref': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}),
               ('ver-3df8ba0617b209e917509c74', {'component_id': 'cmp-9c5c40f09cf1dd84c78a24ef', 'component_version_id': 'ver-3df8ba0617b209e917509c74', 'evidence': ['package.json'], 'resolution_state': 'resolved', 'source_ref': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'})],
  'occurrences': [('occ-517fd4f5effa81db9952a75c', {'component_id': 'cmp-9c5c40f09cf1dd84c78a24ef', 'component_version_id': 'ver-3df8ba0617b209e917509c74', 'dependency_scope': 'ci', 'directness': 'direct', 'evidence_locator': '/steps/0', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-517fd4f5effa81db9952a75c', 'optional': False, 'raw_value': 'npm install:./package.json', 'role': 'github-actions-manifest-install', 'root_id': 'cmp-96798a62afd2f5a456064757', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-975960de7c4b360eedcfd9cc', {'edge_id': 'edge-975960de7c4b360eedcfd9cc', 'from_component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'optional': False, 'relationship': 'installs-manifest', 'resolver': 'github-actions', 'scope': 'ci', 'source_occurrence_id': 'occ-517fd4f5effa81db9952a75c', 'to_component_version_id': 'ver-3df8ba0617b209e917509c74'})],
  'extra_gaps': [],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "workflow-bad-json": r"""(None,
 {'sources': [('src-98a53e0ca7d133d11ccc09e7', {'content_hash': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'evidence_uri': 'input.json', 'source_id': 'src-98a53e0ca7d133d11ccc09e7', 'source_type': 'fixture'})],
  'components': [('cmp-96798a62afd2f5a456064757', {'component_id': 'cmp-96798a62afd2f5a456064757', 'ecosystem': 'local', 'kind': 'fixture', 'lifecycles': ['repository-used'], 'name': 'input.json', 'namespace': '', 'official_channel_required': False, 'official_channels': []}), ('cmp-9c5c40f09cf1dd84c78a24ef', {'component_id': 'cmp-9c5c40f09cf1dd84c78a24ef', 'ecosystem': 'npm', 'kind': 'node-project', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': []})],
  'versions': [('ver-b5e5f51f6ef2c47aceaed9ef', {'component_id': 'cmp-96798a62afd2f5a456064757', 'component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'evidence': ['input.json'], 'resolution_state': 'resolved', 'source_ref': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}),
               ('ver-3df8ba0617b209e917509c74', {'component_id': 'cmp-9c5c40f09cf1dd84c78a24ef', 'component_version_id': 'ver-3df8ba0617b209e917509c74', 'evidence': ['package.json'], 'resolution_state': 'resolved', 'source_ref': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'})],
  'occurrences': [('occ-517fd4f5effa81db9952a75c', {'component_id': 'cmp-9c5c40f09cf1dd84c78a24ef', 'component_version_id': 'ver-3df8ba0617b209e917509c74', 'dependency_scope': 'ci', 'directness': 'direct', 'evidence_locator': '/steps/0', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-517fd4f5effa81db9952a75c', 'optional': False, 'raw_value': 'npm install:./package.json', 'role': 'github-actions-manifest-install', 'root_id': 'cmp-96798a62afd2f5a456064757', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'edges': [('edge-975960de7c4b360eedcfd9cc', {'edge_id': 'edge-975960de7c4b360eedcfd9cc', 'from_component_version_id': 'ver-b5e5f51f6ef2c47aceaed9ef', 'optional': False, 'relationship': 'installs-manifest', 'resolver': 'github-actions', 'scope': 'ci', 'source_occurrence_id': 'occ-517fd4f5effa81db9952a75c', 'to_component_version_id': 'ver-3df8ba0617b209e917509c74'})],
  'extra_gaps': [('gap-8e05074c2205cda994d10665', {'evidence': ['input.json#/steps/1'], 'gap_id': 'gap-8e05074c2205cda994d10665', 'gap_type': 'github-actions-install-manifest-unresolved', 'message': 'npm install at /steps/1 has no readable package.json in bad', 'source_id': 'src-98a53e0ca7d133d11ccc09e7'})],
  'discovery_inputs': [],
  'node_platforms': []})""",
    "test_component_table_channel.1": r"""{'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
 'schema_version': '1.1.0',
 'record_kind': 'reviewed_component',
 'record_id': 'record:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9',
 'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:baseline', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
 'component': {'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'kind': 'library', 'ecosystem': 'pypi', 'namespace': None, 'name': 'app', 'aliases': [], 'purl': 'pkg:pypi/app', 'cpe': None, 'oci_repository': None, 'chart_repository': None, 'chart_name': None, 'api_group': None, 'gvk': [], 'source_repo': None, 'lifecycle': 'deployed', 'disposition': 'selected', 'owners': [], 'topics': [], 'authority_policy': 'channel-policy-delegated-acceptance', 'created_at': '2026-01-02T03:04:05Z', 'registry_kind': 'library', 'registry_identity': 'pkg:pypi/app'},
 'versions': [],
 'occurrences': [],
 'dependencies': [],
 'channels': [{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs',
               'component_id': 'cmp-d25fa9e80d6b87b69c53aed9',
               'channel_type': 'docs',
               'publisher': None,
               'access': 'public',
               'rights': None,
               'refresh_policy': 'on-version-change',
               'discovery_method': 'inferred',
               'confidence': 'medium',
               'review_state': 'accepted',
               'evidence': ['https://example.net/catalog', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'probe:200:https://example.org/app', 'research-pass:2'],
               'availability_state': 'available',
               'canonical_uri': 'https://example.org/app',
               'version_strategy': 'catalog-only',
               'gap': None}],
 'snapshots': [],
 'gaps': []}""",
    "test_component_table_channel.2": r"""{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs',
 'component_id': 'cmp-d25fa9e80d6b87b69c53aed9',
 'channel_type': 'docs',
 'publisher': None,
 'access': 'unknown',
 'rights': None,
 'refresh_policy': 'policy-static',
 'discovery_method': 'inferred',
 'confidence': 'medium',
 'review_state': 'accepted',
 'evidence': ['https://example.net/catalog', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'probe:200:https://example.org/app', 'research-pass:2'],
 'availability_state': 'unresolved',
 'canonical_uri': None,
 'version_strategy': 'unresolved',
 'gap': {'state': 'unresolved', 'reason': 'catalog unavailable', 'blocking': False, 'evidence': ['https://example.net/catalog', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'probe:200:https://example.org/app', 'research-pass:2'], 'next_action': 'probe-wave'}}""",
    "test_component_table_channel.3": r"""{'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
 'schema_version': '1.1.0',
 'record_kind': 'reviewed_component',
 'record_id': 'record:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9',
 'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:baseline', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
 'component': {'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'kind': 'library', 'ecosystem': 'pypi', 'namespace': None, 'name': 'app', 'aliases': [], 'purl': 'pkg:pypi/app', 'cpe': None, 'oci_repository': None, 'chart_repository': None, 'chart_name': None, 'api_group': None, 'gvk': [], 'source_repo': None, 'lifecycle': 'deployed', 'disposition': 'selected', 'owners': [], 'topics': [], 'authority_policy': 'channel-policy-delegated-acceptance', 'created_at': '2026-01-02T03:04:05Z', 'registry_kind': 'library', 'registry_identity': 'pkg:pypi/app'},
 'versions': [],
 'occurrences': [],
 'dependencies': [],
 'channels': [{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs',
               'component_id': 'cmp-d25fa9e80d6b87b69c53aed9',
               'channel_type': 'docs',
               'publisher': None,
               'access': 'unknown',
               'rights': None,
               'refresh_policy': 'policy-static',
               'discovery_method': 'inferred',
               'confidence': 'medium',
               'review_state': 'accepted',
               'evidence': ['https://example.net/catalog', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'probe:200:https://example.org/app', 'research-pass:2'],
               'availability_state': 'unresolved',
               'canonical_uri': None,
               'version_strategy': 'unresolved',
               'gap': {'state': 'unresolved', 'reason': 'catalog unavailable', 'blocking': False, 'evidence': ['https://example.net/catalog', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'probe:200:https://example.org/app', 'research-pass:2'], 'next_action': 'probe-wave'}}],
 'snapshots': [],
 'gaps': []}""",
    "table-unavailable": r"""{'channel_id': 'chn:fixture-policy:cmp-fixture:docs',
 'component_id': 'cmp-fixture',
 'channel_type': 'docs',
 'publisher': None,
 'access': 'unknown',
 'rights': None,
 'refresh_policy': 'policy-static',
 'discovery_method': 'inferred',
 'confidence': 'medium',
 'review_state': 'accepted',
 'evidence': ['research-pass:None'],
 'availability_state': 'unavailable',
 'canonical_uri': None,
 'version_strategy': 'unresolved',
 'gap': {'state': 'unavailable', 'reason': '', 'blocking': False, 'evidence': ['policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'research-pass:None'], 'next_action': None}}""",
    "table-explicit": "{'channel_id': 'chn:fixture-policy:cmp-fixture:docs', 'component_id': 'cmp-fixture', 'channel_type': 'docs', 'publisher': 'Example', 'access': 'restricted', 'rights': 'example terms', 'refresh_policy': 'on-version-change', 'discovery_method': 'inferred', 'confidence': 'high', 'review_state': 'accepted', 'evidence': ['fixture.json', 'probe:200:https://example.org/app', 'research-pass:3'], 'availability_state': 'available', 'canonical_uri': 'https://example.org/app', 'version_strategy': 'catalog-only', 'gap': None}",
    "test_derived_channel.1": r"""{'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
 'schema_version': '1.1.0',
 'record_kind': 'reviewed_component',
 'record_id': 'record:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9',
 'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:baseline', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
 'component': {'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'kind': 'library', 'ecosystem': 'pypi', 'namespace': None, 'name': 'app', 'aliases': [], 'purl': 'pkg:pypi/app', 'cpe': None, 'oci_repository': None, 'chart_repository': None, 'chart_name': None, 'api_group': None, 'gvk': [], 'source_repo': None, 'lifecycle': 'deployed', 'disposition': 'selected', 'owners': [], 'topics': [], 'authority_policy': 'channel-policy-delegated-acceptance', 'created_at': '2026-01-02T03:04:05Z', 'registry_kind': 'library', 'registry_identity': 'pkg:pypi/app'},
 'versions': [],
 'occurrences': [],
 'dependencies': [],
 'channels': [{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs',
               'component_id': 'cmp-d25fa9e80d6b87b69c53aed9',
               'channel_type': 'docs',
               'publisher': None,
               'access': 'public',
               'rights': None,
               'refresh_policy': 'on-version-change',
               'discovery_method': 'generated',
               'confidence': 'medium',
               'review_state': 'accepted',
               'evidence': ['pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
               'availability_state': 'available',
               'canonical_uri': 'https://example.org/app',
               'version_strategy': 'per-version',
               'gap': None}],
 'snapshots': [],
 'gaps': []}""",
    "test_derived_channel.2": r"""{'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
 'schema_version': '1.1.0',
 'record_kind': 'reviewed_component',
 'record_id': 'record:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9',
 'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:baseline', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
 'component': {'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'kind': 'library', 'ecosystem': 'pypi', 'namespace': None, 'name': 'app', 'aliases': [], 'purl': 'pkg:pypi/app', 'cpe': None, 'oci_repository': None, 'chart_repository': None, 'chart_name': None, 'api_group': None, 'gvk': [], 'source_repo': None, 'lifecycle': 'deployed', 'disposition': 'selected', 'owners': [], 'topics': [], 'authority_policy': 'channel-policy-delegated-acceptance', 'created_at': '2026-01-02T03:04:05Z', 'registry_kind': 'library', 'registry_identity': 'pkg:pypi/app'},
 'versions': [],
 'occurrences': [],
 'dependencies': [],
 'channels': [{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs',
               'component_id': 'cmp-d25fa9e80d6b87b69c53aed9',
               'channel_type': 'docs',
               'publisher': None,
               'access': 'public',
               'rights': None,
               'refresh_policy': 'on-version-change',
               'discovery_method': 'generated',
               'confidence': 'medium',
               'review_state': 'accepted',
               'evidence': ['pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
               'availability_state': 'unresolved',
               'canonical_uri': None,
               'version_strategy': 'unresolved',
               'gap': {'state': 'unresolved', 'reason': 'uri-template-unrenderable: https://example.org/{missing}', 'blocking': False, 'evidence': ['policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], 'next_action': 'probe-wave'}}],
 'snapshots': [],
 'gaps': []}""",
    "test_derived_channel_cites_rendered_uri_in_gap.1": r"""{'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
 'schema_version': '1.1.0',
 'record_kind': 'reviewed_component',
 'record_id': 'record:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9',
 'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:baseline', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
 'component': {'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'kind': 'library', 'ecosystem': 'pypi', 'namespace': None, 'name': 'app', 'aliases': [], 'purl': 'pkg:pypi/app', 'cpe': None, 'oci_repository': None, 'chart_repository': None, 'chart_name': None, 'api_group': None, 'gvk': [], 'source_repo': None, 'lifecycle': 'deployed', 'disposition': 'selected', 'owners': [], 'topics': [], 'authority_policy': 'channel-policy-delegated-acceptance', 'created_at': '2026-01-02T03:04:05Z', 'registry_kind': 'library', 'registry_identity': 'pkg:pypi/app'},
 'versions': [],
 'occurrences': [],
 'dependencies': [],
 'channels': [{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs',
               'component_id': 'cmp-d25fa9e80d6b87b69c53aed9',
               'channel_type': 'docs',
               'publisher': None,
               'access': 'unknown',
               'rights': None,
               'refresh_policy': 'policy-static',
               'discovery_method': 'generated',
               'confidence': 'medium',
               'review_state': 'accepted',
               'evidence': ['pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
               'availability_state': 'unresolved',
               'canonical_uri': None,
               'version_strategy': 'unresolved',
               'gap': {'state': 'unresolved', 'reason': 'pending verification', 'blocking': False, 'evidence': ['derived-uri:https://example.org/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], 'next_action': 'probe-wave'}}],
 'snapshots': [],
 'gaps': []}""",
    "derived-default": r"""{'channel_id': 'chn:fixture-policy:cmp-fixture:docs',
 'component_id': 'cmp-fixture',
 'channel_type': 'docs',
 'publisher': None,
 'access': 'unknown',
 'rights': None,
 'refresh_policy': 'policy-static',
 'discovery_method': 'generated',
 'confidence': 'high',
 'review_state': 'accepted',
 'evidence': ['a', 'z'],
 'availability_state': 'unresolved',
 'canonical_uri': None,
 'version_strategy': 'unresolved',
 'gap': {'state': 'unresolved', 'reason': '', 'blocking': False, 'evidence': ['policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], 'next_action': None}}""",
    "derived-explicit": r"""{'channel_id': 'chn:fixture-policy:cmp-fixture:docs',
 'component_id': 'cmp-fixture',
 'channel_type': 'docs',
 'publisher': 'Example',
 'access': 'restricted',
 'rights': 'example terms',
 'refresh_policy': 'on-version-change',
 'discovery_method': 'reviewed',
 'confidence': 'high',
 'review_state': 'accepted',
 'evidence': ['a', 'z'],
 'availability_state': 'unresolved',
 'canonical_uri': None,
 'version_strategy': 'catalog-only',
 'gap': {'state': 'unresolved', 'reason': 'pending', 'blocking': False, 'evidence': ['derived-uri:https://example.org/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], 'next_action': 'review'}}""",
    "derived-explicit-available": "{'channel_id': 'chn:fixture-policy:cmp-fixture:docs', 'component_id': 'cmp-fixture', 'channel_type': 'docs', 'publisher': None, 'access': 'public', 'rights': None, 'refresh_policy': 'on-version-change', 'discovery_method': 'generated', 'confidence': 'high', 'review_state': 'accepted', 'evidence': ['a', 'z'], 'availability_state': 'available', 'canonical_uri': 'https://example.org/app', 'version_strategy': 'catalog-only', 'gap': None}",
    "test_derived_component_record.1": r"""{'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
 'schema_version': '1.1.0',
 'record_kind': 'reviewed_component',
 'record_id': 'record:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9',
 'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:baseline', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
 'component': {'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'kind': 'library', 'ecosystem': 'pypi', 'namespace': 'example', 'name': 'app', 'aliases': [], 'purl': 'pkg:pypi/app', 'cpe': None, 'oci_repository': None, 'chart_repository': None, 'chart_name': None, 'api_group': 'widgets.example.org', 'gvk': [], 'source_repo': None, 'lifecycle': 'deployed', 'disposition': 'selected', 'owners': [], 'topics': [], 'authority_policy': 'channel-policy-delegated-acceptance', 'created_at': '2026-01-02T03:04:05Z', 'registry_kind': 'library', 'registry_identity': 'pkg:pypi/app'},
 'versions': [],
 'occurrences': [],
 'dependencies': [],
 'channels': [{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs',
               'component_id': 'cmp-d25fa9e80d6b87b69c53aed9',
               'channel_type': 'docs',
               'publisher': None,
               'access': 'public',
               'rights': None,
               'refresh_policy': 'on-version-change',
               'discovery_method': 'generated',
               'confidence': 'medium',
               'review_state': 'accepted',
               'evidence': ['input.json', 'live-export:fixture.json#/items/0', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
               'availability_state': 'available',
               'canonical_uri': 'live-export:fixture.json#/items/0',
               'version_strategy': 'per-version',
               'gap': None}],
 'snapshots': [],
 'gaps': []}""",
    "derived-component-defaults": r"""{'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
 'schema_version': '1.1.0',
 'record_kind': 'reviewed_component',
 'record_id': 'record:fixture-policy:cmp-fixture',
 'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:baseline', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
 'component': {'component_id': 'cmp-fixture', 'kind': 'package', 'ecosystem': 'unknown', 'namespace': None, 'name': 'cmp-fixture', 'aliases': [], 'purl': None, 'cpe': None, 'oci_repository': None, 'chart_repository': None, 'chart_name': None, 'api_group': None, 'gvk': [], 'source_repo': None, 'lifecycle': 'deployed', 'disposition': 'selected', 'owners': [], 'topics': [], 'authority_policy': 'channel-policy-delegated-acceptance', 'created_at': '2026-01-02T03:04:05Z', 'registry_kind': '', 'registry_identity': 'example/app'},
 'versions': [],
 'occurrences': [],
 'dependencies': [],
 'channels': [],
 'snapshots': [],
 'gaps': []}""",
    "derived-component-oci": r"""{'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
 'schema_version': '1.1.0',
 'record_kind': 'reviewed_component',
 'record_id': 'record:fixture-policy:cmp-fixture',
 'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:baseline', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
 'component': {'component_id': 'cmp-fixture', 'kind': 'image', 'ecosystem': 'oci', 'namespace': None, 'name': 'cmp-fixture', 'aliases': [], 'purl': None, 'cpe': None, 'oci_repository': 'example/app', 'chart_repository': None, 'chart_name': None, 'api_group': None, 'gvk': [], 'source_repo': None, 'lifecycle': 'deployed', 'disposition': 'selected', 'owners': [], 'topics': [], 'authority_policy': 'channel-policy-delegated-acceptance', 'created_at': '2026-01-02T03:04:05Z', 'registry_kind': 'image', 'registry_identity': 'example/app'},
 'versions': [],
 'occurrences': [],
 'dependencies': [],
 'channels': [{'channel_id': 'chn:fixture-policy:cmp-fixture:docs', 'component_id': 'cmp-fixture', 'channel_type': 'docs', 'publisher': None, 'access': 'public', 'rights': None, 'refresh_policy': 'on-version-change', 'discovery_method': 'generated', 'confidence': 'medium', 'review_state': 'accepted', 'evidence': ['policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], 'availability_state': 'available', 'canonical_uri': 'https://example.org/app', 'version_strategy': 'per-version', 'gap': None}],
 'snapshots': [],
 'gaps': []}""",
    "test_snapshot_reviewed_version_entry.1": "{'component_version_id': 'ver-fixture', 'component_id': 'cmp-fixture', 'purl': None, 'constraint': '^1.2.0', 'resolved_version': '1.2.3', 'source_ref': None, 'artifact_digest': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'platform': 'linux/amd64', 'build_metadata': {}, 'release_time': None, 'observed_at': '2026-01-02T03:04:05Z', 'valid_from': None, 'valid_to': None, 'resolution_state': 'resolved', 'evidence': ['a.json', 'z.json']}",
    "test_snapshot_reviewed_version_entry.2": "None",
    "snapshot-missing-version": "None",
    "snapshot-invalid-state": "None",
    "snapshot-no-evidence": "None",
    "snapshot-no-time": "None",
    "snapshot-mutable-only": "None",
    "snapshot-mutable-version": "None",
    "snapshot-mutable-source": "None",
    "snapshot-invalid-digest": "None",
    "snapshot-invalid-platform": "{'component_version_id': 'ver-example', 'component_id': 'cmp-fixture', 'purl': None, 'constraint': None, 'resolved_version': '1.2.3', 'source_ref': None, 'artifact_digest': None, 'platform': 'linux/unknown', 'build_metadata': {}, 'release_time': None, 'observed_at': '2026-01-02T03:04:05Z', 'valid_from': None, 'valid_to': None, 'resolution_state': 'resolved', 'evidence': ['input.json']}",
    "snapshot-nonstr-platform": "None",
    "snapshot-ref-only": "{'component_version_id': 'ver-example', 'component_id': 'cmp-fixture', 'purl': None, 'constraint': None, 'resolved_version': None, 'source_ref': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'artifact_digest': None, 'platform': None, 'build_metadata': {}, 'release_time': None, 'observed_at': '2026-01-02T03:04:05Z', 'valid_from': None, 'valid_to': None, 'resolution_state': 'resolved', 'evidence': ['input.json']}",
    "snapshot-partial": "{'component_version_id': 'ver-example', 'component_id': 'cmp-fixture', 'purl': None, 'constraint': '>=1.2.3', 'resolved_version': None, 'source_ref': None, 'artifact_digest': None, 'platform': None, 'build_metadata': {}, 'release_time': None, 'observed_at': '2026-01-02T03:04:05Z', 'valid_from': None, 'valid_to': None, 'resolution_state': 'partial', 'evidence': ['input.json']}",
    "test_merge_manifests.1": r"""{'$schema': 'https://json-schema.org/draft/2020-12/schema',
 'authority_boundary': {'review_state': 'unreviewed', 'authoritative': False, 'compile_eligible': False, 'promote_eligible': False, 'source_admission': False, 'retrieval_release': False, 'production_mutation': False},
 'base_manifest_id': 'mft-564b17732570c05c12a354b74b50759db334055f472df198bd3f05c96f742667',
 'bounds': {'components': 100000, 'dependency_edges': 700000, 'discovery_file_bytes': 8388608, 'discovery_files': 10000, 'discovery_total_bytes': 134217728, 'gaps': 400000, 'json_depth': 128, 'json_input_bytes': 805306368, 'json_nodes': 20000000, 'occurrences': 400000, 'serialized_output_bytes': 805306368, 'sources': 100000, 'tracked_files': 20000, 'versions': 200000},
 'completeness': {'input': {'state': 'unknown', 'input_count': 0, 'blocking_input_ids': []}, 'enumeration': {'state': 'unknown'}, 'closure': {'state': 'unknown', 'blocking_gap_ids': []}, 'identity': {'state': 'complete', 'blocking_gap_ids': []}, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots': {'state': 'unknown', 'accepted_available_channels': 0, 'immutable_verified_channels': 0, 'missing_channel_ids': []}, 'all_axes_complete': False},
 'components': [{'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'ecosystem': 'pypi', 'kind': 'library', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': [], 'purl': 'pkg:pypi/app'}],
 'counts': {'sources': 0, 'components': 1, 'versions': 1, 'occurrences': 0, 'dependency_edges': 0, 'gaps': 0},
 'dependency_edges': [],
 'gaps': [],
 'generation_state': 'candidate',
 'generator': {'name': 'knowledge-registry', 'ruleset_hash': 'sha256:e49f3c59e9a4f697b953166bd42e04ef0cf1a9838299fc2fd7168dc4418aa909', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'source_ref': 'tools/knowledge-registry/knowledge_registry.py#sha256:932e46cc7a68437ad6cb5eba1c8609a78d800806d8a082771807c124b2bdb6bc', 'version': '2'},
 'input_set': {'entries': [], 'required_source_classes': []},
 'integrity': {'canonicalization': 'archeion-canonical-json-v1', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'deterministic_order': True, 'exact_counts': {'sources': 0, 'components': 1, 'versions': 1, 'occurrences': 0, 'dependency_edges': 0, 'gaps': 0}, 'manifest_hash': 'sha256:0b65a7435fc8cba72650ef237a38d77c439dfa6a4539e2bdc2dfae47b233e5d8'},
 'manifest_version': 2,
 'merge_lineage': {'current_manifest_id': 'mft-8a9d3794734c151de06d1d385556317501e6b79489abed0c902e49ecf764688c', 'input_manifest_ids': ['mft-564b17732570c05c12a354b74b50759db334055f472df198bd3f05c96f742667', 'mft-8a9d3794734c151de06d1d385556317501e6b79489abed0c902e49ecf764688c'], 'previous_manifest_id': 'mft-564b17732570c05c12a354b74b50759db334055f472df198bd3f05c96f742667', 'selection_policy': 'latest-observed-at-then-manifest-id-v1'},
 'observation': {'observed_at': '2026-01-02T03:04:06Z', 'source_valid_at': '2026-01-02T03:04:05Z', 'source_valid_time_basis': 'git-commit-committer-time'},
 'occurrences': [],
 'reconciliation': {'previous_manifest_id': 'mft-564b17732570c05c12a354b74b50759db334055f472df198bd3f05c96f742667', 'complete_mark': False, 'removal_allowed': False, 'added': [], 'changed': [], 'missing': [], 'removed': []},
 'record_kind': 'generated_discovery_manifest',
 'schema_version': '2.0.0',
 'sources': [],
 'versions': [{'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'component_version_id': 'ver-30de7421b28e93364d3ed079', 'evidence': ['input.json', 'other.json'], 'resolution_state': 'resolved', 'resolved_version': '1.2.3'}],
 'manifest_id': 'mft-0b65a7435fc8cba72650ef237a38d77c439dfa6a4539e2bdc2dfae47b233e5d8'}""",
    "test_merge_manifests.2": r"""{'$schema': 'https://json-schema.org/draft/2020-12/schema',
 'authority_boundary': {'review_state': 'unreviewed', 'authoritative': False, 'compile_eligible': False, 'promote_eligible': False, 'source_admission': False, 'retrieval_release': False, 'production_mutation': False},
 'base_manifest_id': 'mft-564b17732570c05c12a354b74b50759db334055f472df198bd3f05c96f742667',
 'bounds': {'components': 100000, 'dependency_edges': 700000, 'discovery_file_bytes': 8388608, 'discovery_files': 10000, 'discovery_total_bytes': 134217728, 'gaps': 400000, 'json_depth': 128, 'json_input_bytes': 805306368, 'json_nodes': 20000000, 'occurrences': 400000, 'serialized_output_bytes': 805306368, 'sources': 100000, 'tracked_files': 20000, 'versions': 200000},
 'completeness': {'input': {'state': 'unknown', 'input_count': 0, 'blocking_input_ids': []}, 'enumeration': {'state': 'unknown'}, 'closure': {'state': 'unknown', 'blocking_gap_ids': []}, 'identity': {'state': 'complete', 'blocking_gap_ids': []}, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots': {'state': 'unknown', 'accepted_available_channels': 0, 'immutable_verified_channels': 0, 'missing_channel_ids': []}, 'all_axes_complete': False},
 'components': [{'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'ecosystem': 'pypi', 'kind': 'library', 'lifecycles': ['repository-used'], 'name': 'app', 'namespace': '', 'official_channel_required': False, 'official_channels': [], 'purl': 'pkg:pypi/app'}],
 'counts': {'sources': 0, 'components': 1, 'versions': 1, 'occurrences': 0, 'dependency_edges': 0, 'gaps': 0},
 'dependency_edges': [],
 'gaps': [],
 'generation_state': 'candidate',
 'generator': {'name': 'knowledge-registry', 'ruleset_hash': 'sha256:e49f3c59e9a4f697b953166bd42e04ef0cf1a9838299fc2fd7168dc4418aa909', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'source_ref': 'tools/knowledge-registry/knowledge_registry.py#sha256:932e46cc7a68437ad6cb5eba1c8609a78d800806d8a082771807c124b2bdb6bc', 'version': '2'},
 'input_set': {'entries': [], 'required_source_classes': []},
 'integrity': {'canonicalization': 'archeion-canonical-json-v1', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'deterministic_order': True, 'exact_counts': {'sources': 0, 'components': 1, 'versions': 1, 'occurrences': 0, 'dependency_edges': 0, 'gaps': 0}, 'manifest_hash': 'sha256:0b65a7435fc8cba72650ef237a38d77c439dfa6a4539e2bdc2dfae47b233e5d8'},
 'manifest_version': 2,
 'merge_lineage': {'current_manifest_id': 'mft-8a9d3794734c151de06d1d385556317501e6b79489abed0c902e49ecf764688c', 'input_manifest_ids': ['mft-564b17732570c05c12a354b74b50759db334055f472df198bd3f05c96f742667', 'mft-8a9d3794734c151de06d1d385556317501e6b79489abed0c902e49ecf764688c'], 'previous_manifest_id': 'mft-564b17732570c05c12a354b74b50759db334055f472df198bd3f05c96f742667', 'selection_policy': 'latest-observed-at-then-manifest-id-v1'},
 'observation': {'observed_at': '2026-01-02T03:04:06Z', 'source_valid_at': '2026-01-02T03:04:05Z', 'source_valid_time_basis': 'git-commit-committer-time'},
 'occurrences': [],
 'reconciliation': {'previous_manifest_id': 'mft-564b17732570c05c12a354b74b50759db334055f472df198bd3f05c96f742667', 'complete_mark': False, 'removal_allowed': False, 'added': [], 'changed': [], 'missing': [], 'removed': []},
 'record_kind': 'generated_discovery_manifest',
 'schema_version': '2.0.0',
 'sources': [],
 'versions': [{'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'component_version_id': 'ver-30de7421b28e93364d3ed079', 'evidence': ['input.json', 'other.json'], 'resolution_state': 'resolved', 'resolved_version': '1.2.3'}],
 'manifest_id': 'mft-0b65a7435fc8cba72650ef237a38d77c439dfa6a4539e2bdc2dfae47b233e5d8'}""",
    "test_merge_manifests.3": "('RegistryInputError', 'merge requires at least one candidate manifest')",
    "test_merge_manifests.4": "('RegistryInputError', 'merge input 1 is invalid: schema_version must equal 2.0.0')",
    "test_strict_merge_candidate_record_combines_lifecycles.1": "{'lifecycles': ['deployed', 'repository-used']}",
    "test_strict_merge_candidate_value.1": "{'evidence': ['a.json', 'b.json', 'z.json'], 'metadata': {'observed_at': '2026-01-02T03:04:06Z'}, 'source_ref': '1.2.3'}",
    "test_strict_merge_candidate_value.2": "{'evidence': ['a.json', 'b.json', 'z.json'], 'metadata': {'observed_at': '2026-01-02T03:04:06Z'}, 'source_ref': '1.2.3'}",
    "test_strict_merge_candidate_value.3": "('RegistryInputError', 'merge conflict for versions record ver-fixture at /source_ref')",
}


class ChannelRecordTests(unittest.TestCase):
    """Build reviewed channel and version records from in-memory policies."""

    def test_derived_channel(self) -> None:
        """Render available template channels and degrade unresolved templates."""
        builder, component, _ = package_builder()
        entry = policy_entry("https://example.org/{name}")
        check_output(
            self,
            EXPECTED,
            "test_derived_channel.1",
            kr.derived_component_record,
            entry,
            builder.components[component],
            "pkg:pypi/app",
            "baseline",
            None,
        )

        entry["record"]["channels"][0]["uri_template"] = "https://example.org/{missing}"
        check_output(
            self,
            EXPECTED,
            "test_derived_channel.2",
            kr.derived_component_record,
            entry,
            builder.components[component],
            "pkg:pypi/app",
            "baseline",
            None,
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
        check_output(
            self,
            EXPECTED,
            "test_derived_channel_cites_rendered_uri_in_gap.1",
            kr.derived_component_record,
            entry,
            builder.components[component],
            "pkg:pypi/app",
            "baseline",
            None,
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
        check_output(
            self,
            EXPECTED,
            "test_component_table_channel.1",
            kr.derived_component_record,
            entry,
            builder.components[component],
            "pkg:pypi/app",
            "baseline",
            None,
            row_set={"channels": [row]},
        )

        row.update(disposition="unresolved", reason="catalog unavailable")
        check_output(
            self,
            EXPECTED,
            "test_component_table_channel.2",
            kr._component_table_channel,
            entry,
            row,
            component,
            [entry["citation"]],
        )
        check_output(
            self,
            EXPECTED,
            "test_component_table_channel.3",
            kr.derived_component_record,
            entry,
            builder.components[component],
            "pkg:pypi/app",
            "baseline",
            None,
            row_set={"channels": [row]},
        )

    def test_derived_component_record(self) -> None:
        """Stamp the policy and preserve the exact pointer in evidence templates."""
        builder, component, _ = package_builder()
        entry = policy_entry("{evidence}")
        live_pointer = "live-export:fixture.json#/items/0"
        component_row = {
            **builder.components[component],
            "namespace": "example",
            "metadata": {"api_group": "widgets.example.org"},
        }
        check_output(
            self,
            EXPECTED,
            "test_derived_component_record.1",
            kr.derived_component_record,
            entry,
            component_row,
            "pkg:pypi/app",
            "baseline",
            "input.json",
            live_pointer,
        )

    def test_snapshot_reviewed_version_entry(self) -> None:
        """Skip digestless resolved images and select the next expressible version."""
        component = "cmp-fixture"
        version = {
            "component_version_id": "ver-fixture",
            "resolution_state": "resolved",
            "resolved_version": "1.2.3",
            "constraint": "^1.2.0",
            "artifact_digest": DIGEST,
            "platform": "linux/amd64",
            "evidence": ["z.json", "a.json", "a.json"],
            "metadata": {"observed_at": "invalid"},
        }
        check_output(
            self,
            EXPECTED,
            "test_snapshot_reviewed_version_entry.1",
            kr.snapshot_reviewed_version_entry,
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
        check_output(
            self,
            EXPECTED,
            "test_snapshot_reviewed_version_entry.2",
            kr.snapshot_reviewed_version_entry,
            component,
            [{**version, "artifact_digest": None}],
            OBSERVED,
            ecosystem="oci",
            kind="image",
        )

    def test_derived_channel_explicit_and_unresolved_specs(self) -> None:
        """Retain explicit policy settings and apply defaults for unresolved channels."""
        entry = policy_entry()
        base = entry["record"]["channels"][0]
        for label, spec in (
            (
                "derived-default",
                {"channel_type": base["channel_type"], "disposition": "unresolved"},
            ),
            (
                "derived-explicit",
                {
                    **base,
                    "access": "restricted",
                    "publisher": "Example",
                    "rights": "example terms",
                    "refresh_policy": "on-version-change",
                    "discovery_method": "reviewed",
                    "confidence": "high",
                    "version_strategy": "catalog-only",
                    "next_action": "review",
                    "disposition": "derived-unverified",
                    "gap_reason": "pending",
                },
            ),
            (
                "derived-explicit-available",
                {
                    **base,
                    "version_strategy": "catalog-only",
                    "confidence": "high",
                },
            ),
        ):
            check_output(
                self,
                EXPECTED,
                label,
                kr._derived_channel,
                entry,
                spec,
                "cmp-fixture",
                {},
                ["z", "a", "a"],
            )

    def test_component_table_channel_defaults_and_overrides(self) -> None:
        """Handle missing provenance, explicit fields, and unavailable rows."""
        entry = policy_entry()
        row = {
            "channel_type": kr.OFFICIAL_CHANNEL_TYPES[0],
            "disposition": "unavailable",
        }
        check_output(
            self,
            EXPECTED,
            "table-unavailable",
            kr._component_table_channel,
            entry,
            row,
            "cmp-fixture",
            [],
        )
        row.update(
            disposition="available",
            canonical_uri=CHANNEL_URI,
            access="restricted",
            publisher="Example",
            rights="example terms",
            confidence="high",
            provenance={"pass": 3, "refs": []},
            probe={"status": 200, "final_url": CHANNEL_URI},
        )
        check_output(
            self,
            EXPECTED,
            "table-explicit",
            kr._component_table_channel,
            entry,
            row,
            "cmp-fixture",
            ["fixture.json"],
        )

    def test_derived_component_record_defaults(self) -> None:
        """Use the component ID and unknown ecosystem when optional fields are absent."""
        entry = policy_entry()
        entry["record"]["channels"] = []
        check_output(
            self,
            EXPECTED,
            "derived-component-defaults",
            kr.derived_component_record,
            entry,
            {"component_id": "cmp-fixture"},
            "example/app",
            "baseline",
            None,
        )
        entry["record"]["channels"] = policy_entry()["record"]["channels"]
        check_output(
            self,
            EXPECTED,
            "derived-component-oci",
            kr.derived_component_record,
            entry,
            {
                "component_id": "cmp-fixture",
                "kind": "image",
                "ecosystem": "oci",
                "metadata": {"oci_repository": "example/app"},
            },
            "example/app",
            "baseline",
            None,
        )

    def test_snapshot_reviewed_version_entry_rejects_unexpressible_rows(self) -> None:
        """Skip versions that lack valid identity, time, digest, or platform."""
        row = {
            "component_version_id": "ver-example",
            "resolution_state": "resolved",
            "resolved_version": "1.2.3",
            "evidence": ["input.json"],
            "metadata": {"observed_at": OBSERVED},
        }
        for label, invalid in (
            ("snapshot-missing-version", {**row, "component_version_id": ""}),
            ("snapshot-invalid-state", {**row, "resolution_state": "invalid"}),
            ("snapshot-no-evidence", {**row, "evidence": [None, ""]}),
            ("snapshot-no-time", {**row, "metadata": None}),
            (
                "snapshot-mutable-only",
                {**row, "resolved_version": None, "source_ref": "main"},
            ),
            ("snapshot-mutable-version", {**row, "resolved_version": "main"}),
            ("snapshot-mutable-source", {**row, "source_ref": "main"}),
            ("snapshot-invalid-digest", {**row, "artifact_digest": "invalid"}),
            ("snapshot-invalid-platform", {**row, "platform": "linux/unknown"}),
            ("snapshot-nonstr-platform", {**row, "platform": 42}),
        ):
            check_output(
                self,
                EXPECTED,
                label,
                kr.snapshot_reviewed_version_entry,
                "cmp-fixture",
                [None, invalid],
                None,
                ecosystem="pypi",
                kind="library",
            )

    def test_snapshot_reviewed_version_entry_supports_ref_and_partial(self) -> None:
        """Copy an immutable source ref or an explicitly unresolved constraint."""
        row = {
            "component_version_id": "ver-example",
            "resolution_state": "resolved",
            "source_ref": "b" * 40,
            "evidence": ["input.json"],
            "metadata": {"observed_at": OBSERVED},
        }
        check_output(
            self,
            EXPECTED,
            "snapshot-ref-only",
            kr.snapshot_reviewed_version_entry,
            "cmp-fixture",
            [row],
            LATER,
            ecosystem="git",
            kind="git-repository",
        )
        row.update(resolution_state="partial", constraint=">=1.2.3", source_ref=None)
        check_output(
            self,
            EXPECTED,
            "snapshot-partial",
            kr.snapshot_reviewed_version_entry,
            "cmp-fixture",
            [row],
            LATER,
            ecosystem="pypi",
            kind="library",
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
        check_output(
            self,
            EXPECTED,
            "test_strict_merge_candidate_value.1",
            kr.strict_merge_candidate_record,
            "versions",
            "ver-fixture",
            left,
            right,
        )
        check_output(
            self,
            EXPECTED,
            "test_strict_merge_candidate_value.2",
            kr.strict_merge_candidate_record,
            "versions",
            "ver-fixture",
            right,
            left,
        )
        with self.assertRaisesRegex(
            kr.RegistryInputError,
            "merge conflict for versions record ver-fixture at /source_ref",
        ):
            check_output(
                self,
                EXPECTED,
                "test_strict_merge_candidate_value.3",
                kr.strict_merge_candidate_record,
                "versions",
                "ver-fixture",
                left,
                {**right, "source_ref": "1.2.4"},
            )

    def test_strict_merge_candidate_record_combines_lifecycles(self) -> None:
        """Union distinct lifecycle entries for the same component."""
        check_output(
            self,
            EXPECTED,
            "test_strict_merge_candidate_record_combines_lifecycles.1",
            kr.strict_merge_candidate_record,
            "components",
            "cmp-fixture",
            {"lifecycles": ["repository-used"]},
            {"lifecycles": ["deployed"]},
        )

    def test_merge_manifests(self) -> None:
        """Produce deterministic merged evidence and lineage from temporal candidates."""
        builder, component, _version = package_builder(required=False)
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
        check_output(
            self, EXPECTED, "test_merge_manifests.1", kr.merge_manifests, [newer, older]
        )
        check_output(
            self, EXPECTED, "test_merge_manifests.2", kr.merge_manifests, [older, newer]
        )
        with self.assertRaisesRegex(
            kr.RegistryInputError, "merge requires at least one candidate manifest"
        ):
            check_output(
                self, EXPECTED, "test_merge_manifests.3", kr.merge_manifests, []
            )
        with self.assertRaisesRegex(
            kr.RegistryInputError, "merge input 1 is invalid: schema_version must equal"
        ):
            check_output(
                self,
                EXPECTED,
                "test_merge_manifests.4",
                kr.merge_manifests,
                [older, {**newer, "schema_version": "invalid"}],
            )


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
            result = live.main(args)
        self.assertEqual(
            (result, stdout.getvalue(), stderr.getvalue(), list(self.root.iterdir())),
            (2, "", "capture failed: observed-at must be an exact UTC second\n", []),
        )

    def test_capture_live_main_result_states(self) -> None:
        """Report incomplete capture with exit one and complete capture with exit zero."""
        args = [
            "--output-dir",
            str(self.root / "capture"),
            "--kubeconfig",
            str(self.root / "unused.yaml"),
            "--git-commit",
            "a" * 40,
            "--observed-at",
            OBSERVED,
        ]
        for state, code in (("complete", 0), ("incomplete", 1)):
            with (
                patch.object(live, "capture", return_value={"state": state}),
                redirect_stdout(io.StringIO()) as stdout,
                redirect_stderr(io.StringIO()) as stderr,
            ):
                result = live.main(args)
            self.assertEqual(
                (
                    result,
                    stdout.getvalue(),
                    stderr.getvalue(),
                    list(self.root.iterdir()),
                ),
                (code, f'{{\n  "state": "{state}"\n}}\n', "", []),
            )

    def run_registry(
        self, args: list[str], output: Path | None = None
    ) -> tuple[int, str, str, Record | None]:
        """Read complete CLI streams and the parsed output document."""
        raw_stdout = io.BytesIO()
        with (
            redirect_stdout(
                io.TextIOWrapper(raw_stdout, encoding="utf-8", write_through=True)
            ) as stdout,
            redirect_stderr(io.StringIO()) as stderr,
        ):
            result = kr.main(args)
            stdout.flush()
            text = raw_stdout.getvalue().decode()
        written = (
            json.loads(output.read_text())
            if output is not None and output.is_file()
            else None
        )
        return result, text, stderr.getvalue(), written

    def test_main_gaps(self) -> None:
        """Return success with the complete printed gap report."""
        input_path = self.write("manifest.json", '{"gaps":[{"gap_id":"example"}]}')
        with (
            patch.object(kr, "registry_generator_source_binding", return_value={}),
            patch.object(kr, "validate_manifest", return_value=[]),
        ):
            self.assertEqual(
                self.run_registry(["gaps", str(input_path)]),
                (0, '{"count":1,"gaps":[{"gap_id":"example"}]}\n', "", None),
            )

    def test_main(self) -> None:
        """Write canonical capabilities once and refuse an existing output file."""
        output = self.root / "capabilities.json"
        args = ["capabilities", "--output", str(output)]
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
        self.assertEqual(self.run_registry(args, output), (0, "", "", expected))
        error = FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(output))
        self.assertEqual(
            self.run_registry(args, output),
            (
                2,
                "",
                f"knowledge-registry: output must be a fresh non-symlink file: {output}: {error}\n",
                expected,
            ),
        )

    def test_main_report_dispatch(self) -> None:
        """Write either a complete summary or the coverage result from its offline handler."""
        manifest = {"manifest_id": "example", "authority_boundary": {"network": False}}
        input_path = self.write("manifest.json", json.dumps(manifest))
        with (
            patch.object(kr, "registry_generator_source_binding", return_value={}),
            patch.object(kr, "validate_manifest", return_value=[]),
            patch.object(kr, "manifest_is_complete", return_value=True),
            patch.object(kr, "summarize_manifest", return_value={"kind": "summary"}),
            patch.object(kr, "coverage_manifest", return_value={"kind": "coverage"}),
        ):
            self.assertEqual(
                self.run_registry(["summarize", str(input_path)]),
                (
                    0,
                    '{"authority_boundary":{"network":false},"complete":true,"kind":"summary","manifest_id":"example"}\n',
                    "",
                    None,
                ),
            )
            self.assertEqual(
                self.run_registry(["coverage", str(input_path)]),
                (
                    0,
                    '{"kind":"coverage"}\n',
                    "",
                    None,
                ),
            )

    def test_main_validate_reports_incomplete_and_invalid(self) -> None:
        """Return the validation report and a failure exit for an incomplete manifest."""
        input_path = self.write("manifest.json", "{}")
        output = self.root / "validate.json"
        with (
            patch.object(kr, "registry_generator_source_binding", return_value={}),
            patch.object(kr, "validate_manifest", return_value=["fixture error"]),
            patch.object(kr, "manifest_is_complete", return_value=False),
            patch.object(kr, "counts_for", return_value={"components": 0}),
        ):
            self.assertEqual(
                self.run_registry(
                    [
                        "validate",
                        str(input_path),
                        "--require-complete",
                        "--allow-unsorted",
                        "-o",
                        str(output),
                    ],
                    output,
                ),
                (
                    1,
                    "",
                    "",
                    {
                        "valid": False,
                        "complete": False,
                        "counts": {"components": 0},
                        "errors": [
                            "candidate is explicitly incomplete",
                            "fixture error",
                        ],
                    },
                ),
            )

    def test_main_rejects_multiple_stdin_inputs(self) -> None:
        """Refuse duplicate stdin before calling any import handler."""
        refused = AssertionError("duplicate stdin reached the import handler")
        with (
            patch.object(kr, "registry_generator_source_binding", return_value={}),
            patch.object(kr, "import_live", side_effect=refused),
            patch.object(kr, "import_reviewed", side_effect=refused),
            patch.object(kr, "merge_input_files", side_effect=refused),
        ):
            for args in (
                ["import-live", "-", "--capture-manifest", "-"],
                ["import-reviewed", "-", "-"],
                ["merge", "-", "-"],
            ):
                self.assertEqual(
                    self.run_registry(args),
                    (
                        2,
                        "",
                        "knowledge-registry: stdin may only be specified once\n",
                        None,
                    ),
                )

    def test_main_candidate_dispatch(self) -> None:
        """Dispatch each candidate command offline and preserve its complete result."""
        manifest = {"manifest_id": "example"}
        path = str(self.root)
        commands = (
            (["discover-repo", path, "--observed-at", OBSERVED], "discover_repo"),
            (["import-live", path], "import_live"),
            (["import-reviewed", path], "import_reviewed"),
            (["merge", path], "merge_input_files"),
        )
        with (
            patch.object(kr, "registry_generator_source_binding", return_value={}),
            patch.object(kr, "validate_manifest", return_value=[]),
            patch.object(kr, "manifest_is_complete", return_value=False),
            ExitStack() as stack,
        ):
            for _, handler in commands:
                stack.enter_context(patch.object(kr, handler, return_value=manifest))
            for args, handler in commands:
                with self.subTest(handler=handler):
                    expected = '{"manifest_id":"example"}\n'
                    self.assertEqual(self.run_registry(args), (0, expected, "", None))
                    self.assertEqual(
                        self.run_registry([*args, "--require-complete"]),
                        (1, expected, "", None),
                    )

    def test_main_gate_dispatch(self) -> None:
        """Map complete gate reports to exit status and preserve the output."""
        path = str(self.write("manifest.json", "{}"))
        directory = str(self.root)
        cases = (
            (["wave-gate", path, path, "--policies", directory], "channel_wave_gate"),
            (
                ["snapshot-gate", path, path, "--receipts", directory],
                "channel_snapshot_gate",
            ),
            (["identity-gate", path, path, "--receipts", directory], "identity_gate"),
        )
        with (
            patch.object(kr, "registry_generator_source_binding", return_value={}),
            patch.object(kr, "load_channel_policies", return_value=[]),
            ExitStack() as stack,
        ):
            gates = {
                handler: stack.enter_context(patch.object(kr, handler))
                for _, handler in cases
            }
            for args, handler in cases:
                with self.subTest(handler=handler):
                    gates[handler].return_value = {"pass": True}
                    self.assertEqual(
                        self.run_registry(args), (0, '{"pass":true}\n', "", None)
                    )
                    gates[handler].return_value = {"pass": False}
                    self.assertEqual(
                        self.run_registry(args), (1, '{"pass":false}\n', "", None)
                    )

    def test_main_binds_identity_and_plans_oci(self) -> None:
        """Write every identity binding output and the unbound OCI plan."""
        path = str(self.write("manifest.json", '{"manifest_id":"example"}'))
        report = self.root / "identity.json"
        arguments = [path, "--receipts", str(self.root), "--output", str(report)]
        fragment = {"manifest_id": "fixture-fragment"}
        with (
            patch.object(kr, "registry_generator_source_binding", return_value={}),
            patch.object(kr, "validate_manifest", return_value=[]),
            patch.object(
                kr, "bind_gitops_identity", return_value=(fragment, {"kind": "git"})
            ),
            patch.object(
                kr, "bind_oci_identity", return_value=(fragment, {"kind": "oci"})
            ),
            patch.object(
                kr,
                "oci_identity_plan",
                return_value=([{"reference": "example/app"}], [{"reason": "missing"}]),
            ),
        ):
            self.assertEqual(
                self.run_registry(["bind-identity", *arguments], report),
                (
                    0,
                    '{"kind":"git"}\n',
                    "",
                    {"manifest_id": "fixture-fragment"},
                ),
            )
            report.unlink()
            self.assertEqual(
                self.run_registry(["bind-oci-identity", *arguments], report),
                (
                    0,
                    '{"kind":"oci"}\n',
                    "",
                    {"manifest_id": "fixture-fragment"},
                ),
            )
            report.unlink()
            self.assertEqual(
                self.run_registry(
                    ["bind-oci-identity", "--plan-only", *arguments], report
                ),
                (
                    0,
                    "",
                    "",
                    {
                        "record_kind": "oci_identity_fetch_plan",
                        "baseline_manifest_id": "example",
                        "plan": [{"reference": "example/app"}],
                        "unfetchable_version_ids": [{"reason": "missing"}],
                    },
                ),
            )

    def test_main_derives_channels_and_checks_source_binding(self) -> None:
        """Publish the derivation summary only when its source binding stays stable."""
        path = str(self.write("manifest.json", "{}"))
        output = self.root / "channels"
        args = [
            "derive-channels",
            path,
            "--policies",
            str(self.root),
            "-o",
            str(output),
        ]
        with (
            patch.object(
                kr, "derive_channels_command", return_value={"records_emitted": 1}
            ),
            patch.object(
                kr, "registry_generator_source_binding", return_value={"source": 1}
            ) as binding,
        ):
            self.assertEqual(
                self.run_registry(args, output),
                (0, '{"records_emitted":1}\n', "", None),
            )
            binding.side_effect = [{"source": 1}, {"source": 2}]
            self.assertEqual(
                self.run_registry(args, output),
                (
                    2,
                    "",
                    "knowledge-registry: registry generator source changed during channel derivation\n",
                    None,
                ),
            )


class ScannerBranchTests(FilesTestCase):
    """Exercise scanner defaults and early exits with temporary fixtures."""

    def test_normalization_empty_and_unusable_arguments(self) -> None:
        """Preserve configurations with no eligible argument spans."""
        data = (
            b"mcp_servers.plain = 1\n"
            b'mcp_servers.no_args.command = "example"\n'
            b'mcp_servers.other.args = ["--projection", 1]\n'
        )
        self.assertEqual(kr.normalize_codex_projection_references(data), data)
        self.assertEqual(kr.normalize_codex_projection_references(b"["), b"[")
        canonical = (
            b'[mcp_servers.app]\nargs = ["--projection", "'
            + kr.CODEX_CANONICAL_PROJECTION_REF
            + b'"]\n'
        )
        self.assertEqual(kr.normalize_codex_projection_references(canonical), canonical)

    def test_chart_lock_without_sibling_or_tracking(self) -> None:
        """Record a root-missing lock and its undeclared dependency."""
        text = "dependencies:\n  - name: child\n"
        path = self.write("Chart.lock", text)
        self.track()
        check_output(
            self,
            EXPECTED,
            "chart-lock-no-sibling",
            kr.scan_chart_lock,
            kr.Builder(),
            self.root,
            path,
            text.encode(),
            text,
        )

    def test_chart_lock_missing_declared_entry(self) -> None:
        """Report tracked locks with no entry for a declared dependency."""
        self.write(
            "Chart.yaml", "name: app\nversion: 2.0.0\ndependencies:\n  - name: child\n"
        )
        self.track("Chart.lock")
        path = self.write("Chart.lock", "")
        check_output(
            self,
            EXPECTED,
            "chart-lock-missing-entry",
            kr.scan_chart_lock,
            kr.Builder(),
            self.root,
            path,
            b"",
            "",
        )

    def test_pyproject_omitted_metadata_and_optional_requirements(self) -> None:
        """Use the project path and keep extras and markers without version constraints."""
        text = '[project]\ndependencies = ["Example_Dep[extra]", "other; python_version < 3.15", "@ invalid"]\n'
        path = self.write("app/pyproject.toml", text)
        check_output(
            self,
            EXPECTED,
            "pyproject-defaults",
            kr.scan_pyproject,
            kr.Builder(),
            self.root,
            path,
            text.encode(),
            text,
        )

    def test_containerd_hosts_empty_and_single_endpoint(self) -> None:
        """Distinguish missing endpoints, a bare mirror, and a single server."""
        path = self.write("hosts.toml", "")
        for label, text in (
            ("containerd-no-endpoints", 'other = "example"'),
            ("containerd-bare-mirror", '[host]\n"https://mirror.example.org" = true'),
            ("containerd-server-only", '\nserver = "https://registry.example.org"'),
            ("containerd-empty-hosts", "[host]"),
        ):
            check_output(
                self,
                EXPECTED,
                label,
                kr.scan_containerd_hosts,
                kr.Builder(),
                self.root,
                path,
                text.encode(),
                text,
            )

    def test_codex_config_empty_servers(self) -> None:
        """Distinguish missing servers, empty servers, and an invalid server entry."""
        path = self.write("config.toml", "")
        for label, text in (
            ("codex-missing", ""),
            ("codex-empty", "[mcp_servers]"),
            ("codex-non-table-entry", "[mcp_servers]\napp = true"),
        ):
            check_output(
                self,
                EXPECTED,
                label,
                kr.scan_codex_config,
                kr.Builder(),
                self.root,
                path,
                text.encode(),
                text,
            )

    def test_script_dependencies_empty_and_unresolved_pin(self) -> None:
        """Skip unrelated imports and preserve an unresolved sibling constraint."""
        path = self.write("app.py", "")
        self.write("requirements.txt", "PyYAML>=1.2.3\n")
        self.track("app.py", "requirements.txt")
        for label, text in (
            ("script-empty", "# import yaml\nimport pathlib\n"),
            ("script-ranged-pin", "import yaml\n"),
        ):
            check_output(
                self,
                EXPECTED,
                label,
                kr.scan_script_dependencies,
                kr.Builder(),
                self.root,
                path,
                text.encode(),
                text,
            )

    def test_workflow_install_defaults_and_invalid_json(self) -> None:
        """Use the directory fallback and report malformed tracked JSON."""
        builder, source, component, version = local_builder()
        self.root /= "app"
        self.write("package.json", "{}")
        self.write("bad/package.json", "{")
        self.track("package.json", "bad/package.json")
        check_output(
            self,
            EXPECTED,
            "workflow-defaults",
            kr.add_workflow_manifest_install,
            builder,
            self.root,
            source,
            component,
            version,
            working_directory=None,
            locator="/steps/0",
        )
        check_output(
            self,
            EXPECTED,
            "workflow-bad-json",
            kr.add_workflow_manifest_install,
            builder,
            self.root,
            source,
            component,
            version,
            working_directory="bad",
            locator="/steps/1",
        )

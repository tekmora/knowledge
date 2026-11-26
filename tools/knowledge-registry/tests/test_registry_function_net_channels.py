# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Resolve sibling fixtures in this checkout even when another net was loaded earlier.
fixture_dir = Path(__file__).resolve().parent
with patch.dict(sys.modules):
    for sibling in ("test_registry_function_net",):
        cached_path = getattr(sys.modules.get(sibling), "__file__", None)
        if cached_path is None or Path(cached_path).resolve().parent != fixture_dir:
            sys.modules.pop(sibling, None)
    with patch.object(sys, "path", [str(fixture_dir), *sys.path]):
        from test_registry_function_net import (
            CHANNEL_URI,
            DIGEST,
            LATER,
            MAX_FIXTURE_ROWS,
            OBSERVED,
            OCI_MEDIA,
            OCI_REGISTRY,
            OCI_REPOSITORY,
            OCI_URI,
            FilesTestCase,
            Record,
            check_output,
            kr,
            only,
            source_builder,
        )

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


EXPECTED: dict[str, str] = {
    "snapshot-mismatched-and-failed": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'zero-new-versions': {'pass': True, 'versions': 1, 'new_version_ids': [], 'removed_version_ids': []},
            'slots-unchanged': {'pass': True, 'required_slots': 16, 'required_slots_baseline': 16, 'accepted_slots': 1, 'accepted_slots_baseline': 1},
            'receipts-verify': {'pass': True, 'rows': 3, 'rejected': [], 'cas_errors': []},
            'receipt-channel-binding': {'pass': False,
                                        'violations': ['input.jsonl:1: chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs canonical_uri mismatch',
                                                       'input.jsonl:2: chn:other is not accepted-available']},
            'snapshot-arithmetic': {'pass': True,
                                    'baseline_immutable_verified_channels': 0,
                                    'merged_immutable_verified_channels': 0,
                                    'credited_channels': 0,
                                    'expected_channels': 0,
                                    'already_satisfied_channels': 0,
                                    'unbindable_channels': 0,
                                    'unbindable_channel_ids': [],
                                    'unexplained_credit': [],
                                    'uncredited_expected': []},
            'snapshot-channel-validity': {'pass': True, 'violations': []},
            'added-snapshots-trace': {'pass': True, 'added_snapshots': 0, 'violations': []},
            'no-silent-drop': {'pass': False,
                               'dropped_verified_channels': [],
                               'dropped_failure_channels': ['chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs']}}}""",
    "wave-unaccepted-bad-bindings": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'required-slots': {'pass': True,
                               'baseline': 16,
                               'merged': 16,
                               'expected': 16,
                               'reclassified_components': 0,
                               'reclassified_component_ids': [],
                               'unexplained_flag_changes': []},
            'accepted-slots': {'pass': False,
                               'baseline': 1,
                               'merged': 0,
                               'delta': -1,
                               'expected_delta': 16,
                               'policy_stamped_components': 1,
                               'baseline_policy_stamped_components': 0,
                               'wave_policy_stamped_components': 1,
                               'reclassified_accepted_slots': 0,
                               'expected_matched': None},
            'gap-arithmetic': {'pass': True,
                               'baseline_official_channel_unresolved': 0,
                               'merged_official_channel_unresolved': 0,
                               'components_gained_available_channel': 0,
                               'reclassified_components': 0},
            'available-implies-accepted': {'pass': False, 'violations': ['chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs']},
            'policy-bindings': {'pass': False,
                                'violations': ['cmp-d25fa9e80d6b87b69c53aed9: '
                                               'channel-policy:fixture-policy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                                               'cmp-d25fa9e80d6b87b69c53aed9: '
                                               'policy.json@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                                               'cmp-d25fa9e80d6b87b69c53aed9: '
                                               'policy.json@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']}}}""",
    "test_bind_channel_snapshot_receipts.1": r"""({'receipts_dir': '/__fixture_root__', 'receipt_rows': 2, 'receipt_rows_rejected': 0, 'rejected_receipts': [], 'channels_receipted': 2, 'channels_bound': 1, 'bound_channel_ids_digest': 'sha256:4432f7747c85b594f5d8ebb8a04ac6a5e41984b935bd80e0a04036be0862cb50', 'channels_unbound': [{'channel_id': 'chn:other', 'reason': 'input.jsonl:2: receipt does not match a derived available channel'}]},
 [('cmp-d25fa9e80d6b87b69c53aed9',
   {'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
    'schema_version': '1.1.0',
    'record_kind': 'reviewed_component',
    'record_id': 'record:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9',
    'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:baseline', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
    'component': {'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'kind': 'library', 'ecosystem': 'pypi', 'namespace': None, 'name': 'app', 'aliases': [], 'purl': 'pkg:pypi/app', 'cpe': None, 'oci_repository': None, 'chart_repository': None, 'chart_name': None, 'api_group': None, 'gvk': [], 'source_repo': None, 'lifecycle': 'deployed', 'disposition': 'selected', 'owners': [], 'topics': [], 'authority_policy': 'channel-policy-delegated-acceptance', 'created_at': '2026-01-02T03:04:05Z', 'registry_kind': 'library', 'registry_identity': 'pkg:pypi/app'},
    'versions': [{'component_version_id': 'ver-30de7421b28e93364d3ed079', 'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'purl': None, 'constraint': None, 'resolved_version': '1.2.3', 'source_ref': None, 'artifact_digest': None, 'platform': None, 'build_metadata': {}, 'release_time': None, 'observed_at': '2026-01-02T03:04:05Z', 'valid_from': None, 'valid_to': None, 'resolution_state': 'resolved', 'evidence': ['input.json']}],
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
                  'evidence': ['input.json', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                  'availability_state': 'available',
                  'canonical_uri': 'https://example.org/app',
                  'version_strategy': 'per-version',
                  'gap': None}],
    'snapshots': [{'snapshot_id': 'snap:chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs:05a3c373de52',
                   'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs',
                   'component_version_id': 'ver-30de7421b28e93364d3ed079',
                   'resolved_uri': 'https://example.org/app',
                   'upstream_ref': None,
                   'fetched_at': '2026-01-02T03:04:05Z',
                   'observed_at': '2026-01-02T03:04:05Z',
                   'etag': None,
                   'last_modified': None,
                   'content_hash': 'sha256:05a3c373de526a514e6548109ca53980136d5577709e7d76e925243c34e30f05',
                   'media_type': None,
                   'language': None,
                   'coordinates': {},
                   'status': 'verified',
                   'supersedes': [],
                   'error_state': None}],
    'gaps': []})])""",
    "test_bind_channel_snapshot_receipts_conflict.1": r"""({'receipts_dir': '/__fixture_root__', 'receipt_rows': 3, 'receipt_rows_rejected': 0, 'rejected_receipts': [], 'channels_receipted': 1, 'channels_bound': 0, 'bound_channel_ids_digest': 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945', 'channels_unbound': [{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs', 'reason': 'conflicting receipts for one channel'}]},
 [('cmp-d25fa9e80d6b87b69c53aed9',
   {'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
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
                  'evidence': ['input.json', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                  'availability_state': 'available',
                  'canonical_uri': 'https://example.org/app',
                  'version_strategy': 'per-version',
                  'gap': None}],
    'snapshots': [],
    'gaps': []})])""",
    "test_bind_channel_snapshot_receipts_rejects_uri_mismatch.1": r"""({'receipts_dir': '/__fixture_root__', 'receipt_rows': 1, 'receipt_rows_rejected': 0, 'rejected_receipts': [], 'channels_receipted': 1, 'channels_bound': 0, 'bound_channel_ids_digest': 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945', 'channels_unbound': [{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs', 'reason': 'input.jsonl:1: receipt canonical_uri does not match the channel'}]},
 [('cmp-d25fa9e80d6b87b69c53aed9',
   {'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
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
                  'evidence': ['input.json', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                  'availability_state': 'available',
                  'canonical_uri': 'https://example.org/app',
                  'version_strategy': 'per-version',
                  'gap': None}],
    'snapshots': [],
    'gaps': []})])""",
    "derive-empty": "([], [], {'record_kind': 'channel_policy_derivation_summary', 'baseline_manifest_id': 'mft-fce475094eadc4363ae774df9c8867d690376c40cbee429786017b1a7560738e', 'policies': [], 'components_considered': 0, 'records_emitted': 0, 'expected_accepted_slots_delta': 0, 'skipped': {}})",
    "derive-no-policy": "([], [], {'record_kind': 'channel_policy_derivation_summary', 'baseline_manifest_id': 'mft-7e5f45218e6a9ac8f1504b280eb7b21db470d8ede7f0e5a79a8f921db4f1a16b', 'policies': [], 'components_considered': 1, 'records_emitted': 0, 'expected_accepted_slots_delta': 0, 'skipped': {'no-policy': 1}})",
    "derive-not-required": r"""([], [('sample-pypi.json', {'record_kind': 'channel_policy_sample_audit', 'policy_record_id': 'fixture-policy', 'policy_sha256': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'policy_path': 'policy.json', 'sample_size': 0, 'total_matched': 0, 'entries': []})],
 {'record_kind': 'channel_policy_derivation_summary', 'baseline_manifest_id': 'mft-d8b890fff3c75ad5f7405c558935f120895b5cb74d53dd912273b9d14331ce22', 'policies': [{'record_id': 'fixture-policy', 'path': 'policy.json', 'sha256': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ecosystem': 'pypi', 'matched': 0, 'expected_accepted_slots_delta': 0, 'sample_artifact': 'sample-pypi.json', 'sample_component_ids': []}], 'components_considered': 1, 'records_emitted': 0, 'expected_accepted_slots_delta': 0, 'skipped': {'not-required': 1}})""",
    "derive-matching": r"""([('cmp-d25fa9e80d6b87b69c53aed9',
   {'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
    'schema_version': '1.1.0',
    'record_kind': 'reviewed_component',
    'record_id': 'record:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9',
    'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:mft-2145f05f3522aada3fade0689b75ad7a0d1304dbbb383296376b210cc4b623dc', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
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
                  'evidence': ['input.json', 'live-export:widgets.json#/a', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                  'availability_state': 'available',
                  'canonical_uri': 'live-export:widgets.json',
                  'version_strategy': 'per-version',
                  'gap': None}],
    'snapshots': [],
    'gaps': []})],
 [('sample-pypi.json', {'record_kind': 'channel_policy_sample_audit', 'policy_record_id': 'fixture-policy', 'policy_sha256': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'policy_path': 'policy.json', 'sample_size': 1, 'total_matched': 1, 'entries': [{'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'name': 'app', 'purl': 'pkg:pypi/app', 'channels': [{'channel_type': 'docs', 'availability_state': 'available', 'canonical_uri': 'live-export:widgets.json'}]}]})],
 {'record_kind': 'channel_policy_derivation_summary', 'baseline_manifest_id': 'mft-2145f05f3522aada3fade0689b75ad7a0d1304dbbb383296376b210cc4b623dc', 'policies': [{'record_id': 'fixture-policy', 'path': 'policy.json', 'sha256': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ecosystem': 'pypi', 'matched': 1, 'expected_accepted_slots_delta': 16, 'sample_artifact': 'sample-pypi.json', 'sample_component_ids': ['cmp-d25fa9e80d6b87b69c53aed9']}], 'components_considered': 1, 'records_emitted': 1, 'expected_accepted_slots_delta': 16, 'skipped': {}})""",
    "wave-invalid": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': False,
                             'errors': ['$schema does not match the canonical v2 envelope', 'authority_boundary does not match the canonical v2 envelope', 'authority_boundary must remain unreviewed and deny admission, release, and mutation', 'bounds does not match the canonical v2 envelope', 'completeness does not match the canonical v2 envelope', 'components must be an array', 'counts must equal {"components":0,"dependency_edges":0,"gaps":0,"occurrences":0,"sources":0,"versions":0}', 'dependency_edges must be an array', 'gaps must be an array',
                                        'generation_state must equal candidate', 'generator does not match the canonical v2 envelope', 'generator must be an object', 'input_set does not match the canonical v2 envelope', 'input_set must be an object', 'integrity does not match the canonical v2 envelope', 'manifest_id does not match the canonical v2 envelope', 'manifest_version must equal 2', 'occurrences must be an array', 'reconciliation does not match the canonical v2 envelope', 'record_kind must equal generated_discovery_manifest']},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'required-slots': {'pass': True, 'baseline': 0, 'merged': 0, 'expected': 0, 'reclassified_components': 0, 'reclassified_component_ids': [], 'unexplained_flag_changes': []},
            'accepted-slots': {'pass': True, 'baseline': 0, 'merged': 0, 'delta': 0, 'expected_delta': 0, 'policy_stamped_components': 0, 'baseline_policy_stamped_components': 0, 'wave_policy_stamped_components': 0, 'reclassified_accepted_slots': 0, 'expected_matched': None},
            'gap-arithmetic': {'pass': True, 'baseline_official_channel_unresolved': 0, 'merged_official_channel_unresolved': 0, 'components_gained_available_channel': 0, 'reclassified_components': 0},
            'available-implies-accepted': {'pass': True, 'violations': []},
            'policy-bindings': {'pass': True, 'violations': []}}}""",
    "snapshot-invalid": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': False,
                             'errors': ['$schema does not match the canonical v2 envelope', 'authority_boundary does not match the canonical v2 envelope', 'authority_boundary must remain unreviewed and deny admission, release, and mutation', 'bounds does not match the canonical v2 envelope', 'completeness does not match the canonical v2 envelope', 'components must be an array', 'counts must equal {"components":0,"dependency_edges":0,"gaps":0,"occurrences":0,"sources":0,"versions":0}', 'dependency_edges must be an array', 'gaps must be an array',
                                        'generation_state must equal candidate', 'generator does not match the canonical v2 envelope', 'generator must be an object', 'input_set does not match the canonical v2 envelope', 'input_set must be an object', 'integrity does not match the canonical v2 envelope', 'manifest_id does not match the canonical v2 envelope', 'manifest_version must equal 2', 'occurrences must be an array', 'reconciliation does not match the canonical v2 envelope', 'record_kind must equal generated_discovery_manifest']},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'zero-new-versions': {'pass': True, 'versions': 0, 'new_version_ids': [], 'removed_version_ids': []},
            'slots-unchanged': {'pass': True, 'required_slots': 0, 'required_slots_baseline': 0, 'accepted_slots': 0, 'accepted_slots_baseline': 0},
            'receipts-verify': {'pass': True, 'rows': 0, 'rejected': [], 'cas_errors': []},
            'receipt-channel-binding': {'pass': True, 'violations': []},
            'snapshot-arithmetic': {'pass': True, 'baseline_immutable_verified_channels': 0, 'merged_immutable_verified_channels': 0, 'credited_channels': 0, 'expected_channels': 0, 'already_satisfied_channels': 0, 'unbindable_channels': 0, 'unbindable_channel_ids': [], 'unexplained_credit': [], 'uncredited_expected': []},
            'snapshot-channel-validity': {'pass': True, 'violations': []},
            'added-snapshots-trace': {'pass': True, 'added_snapshots': 0, 'violations': []},
            'no-silent-drop': {'pass': True, 'dropped_verified_channels': [], 'dropped_failure_channels': []}}}""",
    "test_channel_snapshot_gate.1": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'zero-new-versions': {'pass': True, 'versions': 1, 'new_version_ids': [], 'removed_version_ids': []},
            'slots-unchanged': {'pass': True, 'required_slots': 16, 'required_slots_baseline': 16, 'accepted_slots': 1, 'accepted_slots_baseline': 1},
            'receipts-verify': {'pass': True, 'rows': 1, 'rejected': [], 'cas_errors': []},
            'receipt-channel-binding': {'pass': True, 'violations': []},
            'snapshot-arithmetic': {'pass': False, 'baseline_immutable_verified_channels': 0, 'merged_immutable_verified_channels': 0, 'credited_channels': 0, 'expected_channels': 1, 'already_satisfied_channels': 0, 'unbindable_channels': 0, 'unbindable_channel_ids': [], 'unexplained_credit': [], 'uncredited_expected': ['chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs']},
            'snapshot-channel-validity': {'pass': True, 'violations': []},
            'added-snapshots-trace': {'pass': True, 'added_snapshots': 0, 'violations': []},
            'no-silent-drop': {'pass': False, 'dropped_verified_channels': ['chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs'], 'dropped_failure_channels': []}}}""",
    "test_channel_snapshot_gate.2": r"""({'receipts_dir': '/__fixture_root__', 'receipt_rows': 1, 'receipt_rows_rejected': 0, 'rejected_receipts': [], 'channels_receipted': 1, 'channels_bound': 1, 'bound_channel_ids_digest': 'sha256:4432f7747c85b594f5d8ebb8a04ac6a5e41984b935bd80e0a04036be0862cb50', 'channels_unbound': []},
 [('cmp-d25fa9e80d6b87b69c53aed9',
   {'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
    'schema_version': '1.1.0',
    'record_kind': 'reviewed_component',
    'record_id': 'record:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9',
    'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:baseline', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
    'component': {'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'kind': 'library', 'ecosystem': 'pypi', 'namespace': None, 'name': 'app', 'aliases': [], 'purl': 'pkg:pypi/app', 'cpe': None, 'oci_repository': None, 'chart_repository': None, 'chart_name': None, 'api_group': None, 'gvk': [], 'source_repo': None, 'lifecycle': 'deployed', 'disposition': 'selected', 'owners': [], 'topics': [], 'authority_policy': 'channel-policy-delegated-acceptance', 'created_at': '2026-01-02T03:04:05Z', 'registry_kind': 'library', 'registry_identity': 'pkg:pypi/app'},
    'versions': [{'component_version_id': 'ver-30de7421b28e93364d3ed079', 'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'purl': None, 'constraint': None, 'resolved_version': '1.2.3', 'source_ref': None, 'artifact_digest': None, 'platform': None, 'build_metadata': {}, 'release_time': None, 'observed_at': '2026-01-02T03:04:05Z', 'valid_from': None, 'valid_to': None, 'resolution_state': 'resolved', 'evidence': ['input.json']}],
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
                  'evidence': ['input.json', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                  'availability_state': 'available',
                  'canonical_uri': 'https://example.org/app',
                  'version_strategy': 'per-version',
                  'gap': None}],
    'snapshots': [{'snapshot_id': 'snap:chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs:05a3c373de52',
                   'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs',
                   'component_version_id': 'ver-30de7421b28e93364d3ed079',
                   'resolved_uri': 'https://example.org/app',
                   'upstream_ref': None,
                   'fetched_at': '2026-01-02T03:04:05Z',
                   'observed_at': '2026-01-02T03:04:05Z',
                   'etag': None,
                   'last_modified': None,
                   'content_hash': 'sha256:05a3c373de526a514e6548109ca53980136d5577709e7d76e925243c34e30f05',
                   'media_type': None,
                   'language': None,
                   'coordinates': {},
                   'status': 'verified',
                   'supersedes': [],
                   'error_state': None}],
    'gaps': []})])""",
    "test_channel_snapshot_gate.3": r"""{'pass': True,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'zero-new-versions': {'pass': True, 'versions': 1, 'new_version_ids': [], 'removed_version_ids': []},
            'slots-unchanged': {'pass': True, 'required_slots': 16, 'required_slots_baseline': 16, 'accepted_slots': 1, 'accepted_slots_baseline': 1},
            'receipts-verify': {'pass': True, 'rows': 1, 'rejected': [], 'cas_errors': []},
            'receipt-channel-binding': {'pass': True, 'violations': []},
            'snapshot-arithmetic': {'pass': True, 'baseline_immutable_verified_channels': 0, 'merged_immutable_verified_channels': 1, 'credited_channels': 1, 'expected_channels': 1, 'already_satisfied_channels': 0, 'unbindable_channels': 0, 'unbindable_channel_ids': [], 'unexplained_credit': [], 'uncredited_expected': []},
            'snapshot-channel-validity': {'pass': True, 'violations': []},
            'added-snapshots-trace': {'pass': True, 'added_snapshots': 1, 'violations': []},
            'no-silent-drop': {'pass': True, 'dropped_verified_channels': [], 'dropped_failure_channels': []}}}""",
    "test_channel_snapshot_gate.4": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'zero-new-versions': {'pass': False, 'versions': 2, 'new_version_ids': ['ver-932a9ce54053fd475f9927cb'], 'removed_version_ids': []},
            'slots-unchanged': {'pass': True, 'required_slots': 16, 'required_slots_baseline': 16, 'accepted_slots': 1, 'accepted_slots_baseline': 1},
            'receipts-verify': {'pass': True, 'rows': 1, 'rejected': [], 'cas_errors': []},
            'receipt-channel-binding': {'pass': True, 'violations': []},
            'snapshot-arithmetic': {'pass': True, 'baseline_immutable_verified_channels': 0, 'merged_immutable_verified_channels': 1, 'credited_channels': 1, 'expected_channels': 1, 'already_satisfied_channels': 0, 'unbindable_channels': 0, 'unbindable_channel_ids': [], 'unexplained_credit': [], 'uncredited_expected': []},
            'snapshot-channel-validity': {'pass': True, 'violations': []},
            'added-snapshots-trace': {'pass': True, 'added_snapshots': 1, 'violations': []},
            'no-silent-drop': {'pass': True, 'dropped_verified_channels': [], 'dropped_failure_channels': []}}}""",
    "test_channel_snapshot_gate_detects_corrupt_cas.1": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'zero-new-versions': {'pass': True, 'versions': 1, 'new_version_ids': [], 'removed_version_ids': []},
            'slots-unchanged': {'pass': True, 'required_slots': 16, 'required_slots_baseline': 16, 'accepted_slots': 1, 'accepted_slots_baseline': 1},
            'receipts-verify': {'pass': False, 'rows': 1, 'rejected': [], 'cas_errors': ['input.jsonl:1: CAS artifact hash does not match the receipt content_hash']},
            'receipt-channel-binding': {'pass': True, 'violations': []},
            'snapshot-arithmetic': {'pass': False, 'baseline_immutable_verified_channels': 0, 'merged_immutable_verified_channels': 0, 'credited_channels': 0, 'expected_channels': 1, 'already_satisfied_channels': 0, 'unbindable_channels': 0, 'unbindable_channel_ids': [], 'unexplained_credit': [], 'uncredited_expected': ['chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs']},
            'snapshot-channel-validity': {'pass': True, 'violations': []},
            'added-snapshots-trace': {'pass': True, 'added_snapshots': 0, 'violations': []},
            'no-silent-drop': {'pass': False, 'dropped_verified_channels': ['chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs'], 'dropped_failure_channels': []}}}""",
    "snapshot-cas-corrupt": r"""({'receipts_dir': '/__fixture_root__', 'receipt_rows': 1, 'receipt_rows_rejected': 0, 'rejected_receipts': [], 'channels_receipted': 1, 'channels_bound': 0, 'bound_channel_ids_digest': 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945', 'channels_unbound': [{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs', 'reason': 'input.jsonl:1: CAS artifact hash does not match the receipt content_hash'}]},
 [('cmp-d25fa9e80d6b87b69c53aed9',
   {'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
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
                  'evidence': ['input.json', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                  'availability_state': 'available',
                  'canonical_uri': 'https://example.org/app',
                  'version_strategy': 'per-version',
                  'gap': None}],
    'snapshots': [],
    'gaps': []})])""",
    "snapshot-no-receipts": "({'receipts_dir': '/__fixture_root__', 'receipt_rows': 0, 'receipt_rows_rejected': 0, 'rejected_receipts': [], 'channels_receipted': 0, 'channels_bound': 0, 'bound_channel_ids_digest': 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945', 'channels_unbound': []}, [])",
    "snapshot-no-bindable": r"""({'receipts_dir': '/__fixture_root__', 'receipt_rows': 1, 'receipt_rows_rejected': 0, 'rejected_receipts': [], 'channels_receipted': 1, 'channels_bound': 0, 'bound_channel_ids_digest': 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945', 'channels_unbound': [{'channel_id': 'chn:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9:docs', 'reason': 'no baseline version is expressible as a reviewed version'}]},
 [('cmp-d25fa9e80d6b87b69c53aed9',
   {'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
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
                  'evidence': ['input.json', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                  'availability_state': 'available',
                  'canonical_uri': 'https://example.org/app',
                  'version_strategy': 'per-version',
                  'gap': None}],
    'snapshots': [],
    'gaps': []})])""",
    "test_channel_wave_gate.1": r"""{'pass': True,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'required-slots': {'pass': True, 'baseline': 16, 'merged': 16, 'expected': 16, 'reclassified_components': 0, 'reclassified_component_ids': [], 'unexplained_flag_changes': []},
            'accepted-slots': {'pass': True, 'baseline': 0, 'merged': 0, 'delta': 0, 'expected_delta': 0, 'policy_stamped_components': 0, 'baseline_policy_stamped_components': 0, 'wave_policy_stamped_components': 0, 'reclassified_accepted_slots': 0, 'expected_matched': 0},
            'gap-arithmetic': {'pass': True, 'baseline_official_channel_unresolved': 1, 'merged_official_channel_unresolved': 1, 'components_gained_available_channel': 0, 'reclassified_components': 0},
            'available-implies-accepted': {'pass': True, 'violations': []},
            'policy-bindings': {'pass': True, 'violations': []}}}""",
    "test_channel_wave_gate.2": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'required-slots': {'pass': True, 'baseline': 16, 'merged': 16, 'expected': 16, 'reclassified_components': 0, 'reclassified_component_ids': [], 'unexplained_flag_changes': []},
            'accepted-slots': {'pass': False, 'baseline': 0, 'merged': 0, 'delta': 0, 'expected_delta': 0, 'policy_stamped_components': 0, 'baseline_policy_stamped_components': 0, 'wave_policy_stamped_components': 0, 'reclassified_accepted_slots': 0, 'expected_matched': 1},
            'gap-arithmetic': {'pass': True, 'baseline_official_channel_unresolved': 1, 'merged_official_channel_unresolved': 1, 'components_gained_available_channel': 0, 'reclassified_components': 0},
            'available-implies-accepted': {'pass': True, 'violations': []},
            'policy-bindings': {'pass': True, 'violations': []}}}""",
    "test_channel_wave_gate.3": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'zero-new-components': {'pass': False, 'new_component_ids': [], 'removed_component_ids': ['cmp-d25fa9e80d6b87b69c53aed9']},
            'required-slots': {'pass': False, 'baseline': 16, 'merged': 0, 'expected': 16, 'reclassified_components': 0, 'reclassified_component_ids': [], 'unexplained_flag_changes': []},
            'accepted-slots': {'pass': True, 'baseline': 0, 'merged': 0, 'delta': 0, 'expected_delta': 0, 'policy_stamped_components': 0, 'baseline_policy_stamped_components': 0, 'wave_policy_stamped_components': 0, 'reclassified_accepted_slots': 0, 'expected_matched': 0},
            'gap-arithmetic': {'pass': False, 'baseline_official_channel_unresolved': 1, 'merged_official_channel_unresolved': 0, 'components_gained_available_channel': 0, 'reclassified_components': 0},
            'available-implies-accepted': {'pass': True, 'violations': []},
            'policy-bindings': {'pass': True, 'violations': []}}}""",
    "test_channel_wave_gate.4": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'zero-new-components': {'pass': False, 'new_component_ids': ['cmp-6a8a2cf681f7297195a653fc'], 'removed_component_ids': []},
            'required-slots': {'pass': True, 'baseline': 16, 'merged': 16, 'expected': 16, 'reclassified_components': 0, 'reclassified_component_ids': [], 'unexplained_flag_changes': []},
            'accepted-slots': {'pass': True, 'baseline': 0, 'merged': 0, 'delta': 0, 'expected_delta': 0, 'policy_stamped_components': 0, 'baseline_policy_stamped_components': 0, 'wave_policy_stamped_components': 0, 'reclassified_accepted_slots': 0, 'expected_matched': 0},
            'gap-arithmetic': {'pass': True, 'baseline_official_channel_unresolved': 1, 'merged_official_channel_unresolved': 1, 'components_gained_available_channel': 0, 'reclassified_components': 0},
            'available-implies-accepted': {'pass': True, 'violations': []},
            'policy-bindings': {'pass': True, 'violations': []}}}""",
    "test_derive_channel_records.1": r"""([], [('sample-pypi.json', {'record_kind': 'channel_policy_sample_audit', 'policy_record_id': 'fixture-policy', 'policy_sha256': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'policy_path': 'policy.json', 'sample_size': 0, 'total_matched': 0, 'entries': []})],
 {'record_kind': 'channel_policy_derivation_summary', 'baseline_manifest_id': 'mft-8e230c2c9cafcb86c71f0b541cdf3703b89701ee5ecf61d14ef771d25f283cfb', 'policies': [{'record_id': 'fixture-policy', 'path': 'policy.json', 'sha256': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ecosystem': 'pypi', 'matched': 0, 'expected_accepted_slots_delta': 0, 'sample_artifact': 'sample-pypi.json', 'sample_component_ids': []}], 'components_considered': 1, 'records_emitted': 0, 'expected_accepted_slots_delta': 0, 'skipped': {'already-closed': 1}})""",
    "test_derive_channel_records.2": r"""([('cmp-d25fa9e80d6b87b69c53aed9',
   {'$schema': 'https://github.com/cordanaLLM/knowledge/schemas/registry/component-record-v1.1.schema.json',
    'schema_version': '1.1.0',
    'record_kind': 'reviewed_component',
    'record_id': 'record:fixture-policy:cmp-d25fa9e80d6b87b69c53aed9',
    'review': {'status': 'accepted', 'reviewed_by': 'channel-policy:fixture-policy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'reviewed_at': '2026-01-02T03:04:05Z', 'evidence': ['baseline:mft-7e5f45218e6a9ac8f1504b280eb7b21db470d8ede7f0e5a79a8f921db4f1a16b', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']},
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
                  'evidence': ['input.json', 'pkg:pypi/app', 'policy.json@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                  'availability_state': 'available',
                  'canonical_uri': 'https://example.org/app',
                  'version_strategy': 'per-version',
                  'gap': None}],
    'snapshots': [],
    'gaps': []})],
 [('sample-pypi.json', {'record_kind': 'channel_policy_sample_audit', 'policy_record_id': 'fixture-policy', 'policy_sha256': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'policy_path': 'policy.json', 'sample_size': 1, 'total_matched': 1, 'entries': [{'component_id': 'cmp-d25fa9e80d6b87b69c53aed9', 'name': 'app', 'purl': 'pkg:pypi/app', 'channels': [{'channel_type': 'docs', 'availability_state': 'available', 'canonical_uri': 'https://example.org/app'}]}]})],
 {'record_kind': 'channel_policy_derivation_summary', 'baseline_manifest_id': 'mft-7e5f45218e6a9ac8f1504b280eb7b21db470d8ede7f0e5a79a8f921db4f1a16b', 'policies': [{'record_id': 'fixture-policy', 'path': 'policy.json', 'sha256': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ecosystem': 'pypi', 'matched': 1, 'expected_accepted_slots_delta': 16, 'sample_artifact': 'sample-pypi.json', 'sample_component_ids': ['cmp-d25fa9e80d6b87b69c53aed9']}], 'components_considered': 1, 'records_emitted': 1, 'expected_accepted_slots_delta': 16, 'skipped': {}})""",
    "test_derive_channel_records.3": r"""([], [('sample-pypi.json', {'record_kind': 'channel_policy_sample_audit', 'policy_record_id': 'fixture-policy', 'policy_sha256': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'policy_path': 'policy.json', 'sample_size': 0, 'total_matched': 0, 'entries': []})],
 {'record_kind': 'channel_policy_derivation_summary', 'baseline_manifest_id': 'mft-7e5f45218e6a9ac8f1504b280eb7b21db470d8ede7f0e5a79a8f921db4f1a16b', 'policies': [{'record_id': 'fixture-policy', 'path': 'policy.json', 'sha256': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ecosystem': 'pypi', 'matched': 0, 'expected_accepted_slots_delta': 0, 'sample_artifact': 'sample-pypi.json', 'sample_component_ids': []}], 'components_considered': 1, 'records_emitted': 0, 'expected_accepted_slots_delta': 0, 'skipped': {'precondition-mismatch': 1}})""",
    "test_derive_channel_records.4": r"""('RegistryInputError',
 'derive-channels baseline is invalid: $schema does not match the canonical v2 envelope; authority_boundary does not match the canonical v2 envelope; authority_boundary must remain unreviewed and deny admission, release, and mutation; bounds does not match the canonical v2 envelope; completeness does not match the canonical v2 envelope; components must be an array; counts must equal {"components":0,"dependency_edges":0,"gaps":0,"occurrences":0,"sources":0,"versions":0}; dependency_edges must be an array; gaps must be an array; generation_state must equal candidate; '
 'generator does not match the canonical v2 envelope; generator must be an object; input_set does not match the canonical v2 envelope; input_set must be an object; integrity does not match the canonical v2 envelope; manifest_id does not match the canonical v2 envelope; manifest_version must equal 2; occurrences must be an array; reconciliation does not match the canonical v2 envelope; record_kind must equal generated_discovery_manifest')""",
    "test_bind_gitops_identity.1": r"""({'$schema': 'https://json-schema.org/draft/2020-12/schema',
  'authority_boundary': {'review_state': 'unreviewed', 'authoritative': False, 'compile_eligible': False, 'promote_eligible': False, 'source_admission': False, 'retrieval_release': False, 'production_mutation': False},
  'base_manifest_id': None,
  'components': [{'component_id': 'cmp-14e0ecfc9e990dbf5fb73775', 'ecosystem': 'git', 'kind': 'git-repository', 'lifecycles': ['repository-used'], 'metadata': {'self_repository': True}, 'name': 'self', 'namespace': '', 'official_channel_required': False, 'official_channels': []}],
  'dependency_edges': [],
  'gaps': [{'component_id': 'cmp-14e0ecfc9e990dbf5fb73775', 'component_version_id': 'ver-1dee7cb3d8731625f94ecbf3', 'evidence': ['input.json', 'sha256:72ffc047a71d84ec79551dab3dc1ad4c44c10c8d4385df7c22b9c66fb7741199'], 'gap_id': 'gap-0e03d5a360258807c3b7cc49', 'gap_type': 'gitops-self-reference-observed', 'message': "Self-repository GitOps ref 'main' deliberately tracks this repository at observed commit e3dfffb93b53a5fce9a50466315151c11fedc9f1"}],
  'generation_state': 'candidate',
  'generator': {'name': 'knowledge-registry', 'ruleset_hash': 'sha256:e49f3c59e9a4f697b953166bd42e04ef0cf1a9838299fc2fd7168dc4418aa909', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'source_ref': 'tools/knowledge-registry/knowledge_registry.py#sha256:932e46cc7a68437ad6cb5eba1c8609a78d800806d8a082771807c124b2bdb6bc', 'version': '2'},
  'input_set': {'entries': [], 'required_source_classes': []},
  'manifest_version': 2,
  'occurrences': [{'component_id': 'cmp-14e0ecfc9e990dbf5fb73775', 'component_version_id': 'ver-1dee7cb3d8731625f94ecbf3', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': '/receipts/input.jsonl:1', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-27065bf0d61cf256dbd9c96a', 'optional': False, 'raw_value': 'e3dfffb93b53a5fce9a50466315151c11fedc9f1', 'role': 'gitops-source-observation', 'source_id': 'src-7ec3bd847e8d52ce12f92c0f'}],
  'record_kind': 'generated_discovery_manifest',
  'schema_version': '2.0.0',
  'sources': [{'content_hash': 'sha256:72ffc047a71d84ec79551dab3dc1ad4c44c10c8d4385df7c22b9c66fb7741199',
               'evidence_uri': 'gitops-observation:sha256:72ffc047a71d84ec79551dab3dc1ad4c44c10c8d4385df7c22b9c66fb7741199',
               'metadata': {'evidence_class': 'repository', 'receipt': {'canonical_uri': 'https://git.example.org/example/app', 'cas_path': 'cas/72ffc047a71d84ec79551dab3dc1ad4c44c10c8d4385df7c22b9c66fb7741199', 'observed_at': '2026-01-02T03:04:05Z', 'runner_version': '', 'upstream_ref': 'e3dfffb93b53a5fce9a50466315151c11fedc9f1'}},
               'source_id': 'src-7ec3bd847e8d52ce12f92c0f',
               'source_type': 'gitops-source-observation'}],
  'versions': [{'component_id': 'cmp-14e0ecfc9e990dbf5fb73775',
                'component_version_id': 'ver-1dee7cb3d8731625f94ecbf3',
                'evidence': ['input.json'],
                'metadata': {'gitops_source_observation': {'evidence_cas_path': 'cas/72ffc047a71d84ec79551dab3dc1ad4c44c10c8d4385df7c22b9c66fb7741199', 'evidence_content_hash': 'sha256:72ffc047a71d84ec79551dab3dc1ad4c44c10c8d4385df7c22b9c66fb7741199', 'observed_at': '2026-01-02T03:04:05Z', 'observed_commit': 'e3dfffb93b53a5fce9a50466315151c11fedc9f1', 'observed_ref': 'main', 'receipt_canonical_uri': 'https://git.example.org/example/app', 'resolver': 'git-commit-object-receipt'}},
                'resolution_state': 'unresolved',
                'source_ref': 'main'}],
  'bounds': {'tracked_files': 20000, 'discovery_files': 10000, 'discovery_file_bytes': 8388608, 'discovery_total_bytes': 134217728, 'json_input_bytes': 805306368, 'json_depth': 128, 'json_nodes': 20000000, 'serialized_output_bytes': 805306368, 'sources': 100000, 'components': 100000, 'versions': 200000, 'occurrences': 400000, 'dependency_edges': 700000, 'gaps': 400000},
  'counts': {'sources': 1, 'components': 1, 'versions': 1, 'occurrences': 1, 'dependency_edges': 0, 'gaps': 1},
  'completeness': {'input': {'state': 'unknown', 'input_count': 0, 'blocking_input_ids': []}, 'enumeration': {'state': 'unknown'}, 'closure': {'state': 'unknown', 'blocking_gap_ids': []}, 'identity': {'state': 'complete', 'blocking_gap_ids': []}, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots': {'state': 'unknown', 'accepted_available_channels': 0, 'immutable_verified_channels': 0, 'missing_channel_ids': []}, 'all_axes_complete': False},
  'reconciliation': {'previous_manifest_id': None, 'complete_mark': False, 'removal_allowed': False, 'added': [], 'changed': [], 'missing': [], 'removed': []},
  'integrity': {'canonicalization': 'archeion-canonical-json-v1', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'deterministic_order': True, 'exact_counts': {'sources': 1, 'components': 1, 'versions': 1, 'occurrences': 1, 'dependency_edges': 0, 'gaps': 1}, 'manifest_hash': 'sha256:43889582ac4b64d360a0a2fefbd52524359ebb41a63fd1327abdb59c3ca7772b'},
  'manifest_id': 'mft-43889582ac4b64d360a0a2fefbd52524359ebb41a63fd1327abdb59c3ca7772b'},
 {'record_kind': 'gitops_identity_binding_summary',
  'baseline_manifest_id': 'mft-2682b55a12b68257ba316a3ee9db824e48a6c1a769737fe25f42baf64de52ed4',
  'observed_ref': 'main',
  'receipts_dir': '/__fixture_root__',
  'receipts_verified': 1,
  'receipts_refused': 0,
  'refused_receipts': [],
  'commits': ['e3dfffb93b53a5fce9a50466315151c11fedc9f1'],
  'components_bound': 1,
  'versions_bound': 1,
  'bound_version_ids_digest': 'sha256:f6a3535dc6ca5d3ac78dab7479616eb4a6ae34224057b4a3fa0a1155fab4b988',
  'skipped': {'not-a-self-repository-component': 1},
  'fragment_manifest_id': 'mft-43889582ac4b64d360a0a2fefbd52524359ebb41a63fd1327abdb59c3ca7772b'})""",
    "test_bind_gitops_identity.2": "('RegistryInputError', \"--observed-ref 'e3dfffb93b53a5fce9a50466315151c11fedc9f1' is not a mutable ref\")",
    "test_bind_oci_identity.1": r"""({'$schema': 'https://json-schema.org/draft/2020-12/schema',
  'authority_boundary': {'review_state': 'unreviewed', 'authoritative': False, 'compile_eligible': False, 'promote_eligible': False, 'source_admission': False, 'retrieval_release': False, 'production_mutation': False},
  'base_manifest_id': None,
  'components': [{'component_id': 'cmp-e3a2012f0f8df626445ba38f',
                  'ecosystem': 'oci',
                  'kind': 'oci-image',
                  'lifecycles': ['repository-used'],
                  'metadata': {'oci_repository': 'registry.example.org/example/app'},
                  'name': 'app',
                  'namespace': 'registry.example.org/example',
                  'official_channel_required': True,
                  'official_channels': [{'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-ad0da62272c2de3333729d74', 'channel_type': 'advisory', 'review_state': 'needs-review'}, {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-f02241319fa6113219eed50d', 'channel_type': 'api', 'review_state': 'needs-review'},
                                        {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-9a494e8be9de2e0cb1e569ba', 'channel_type': 'artifact', 'review_state': 'needs-review'}, {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-f91f1e1d2adfebd3c34f6246', 'channel_type': 'changelog', 'review_state': 'needs-review'},
                                        {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-d59ba1617dcf395f4a240fba', 'channel_type': 'config', 'review_state': 'needs-review'}, {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-36fd154b8aa5add9ce09bebb', 'channel_type': 'deprecation', 'review_state': 'needs-review'},
                                        {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-a622383815ecf47ae7ee1a44', 'channel_type': 'docs', 'review_state': 'needs-review'}, {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-a6e69fc2eabc3da75f65b34c', 'channel_type': 'license', 'review_state': 'needs-review'},
                                        {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-795e7caf35d1fd702ccee92a', 'channel_type': 'migration', 'review_state': 'needs-review'}, {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-423a924ca4392931e50e5577', 'channel_type': 'package', 'review_state': 'needs-review'},
                                        {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-c103d8f3e18f1e7b846b124a', 'channel_type': 'provenance', 'review_state': 'needs-review'}, {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-bb457539242b70d504591857', 'channel_type': 'reference', 'review_state': 'needs-review'},
                                        {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-49d36662d2737f58dbf980f9', 'channel_type': 'release', 'review_state': 'needs-review'}, {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-b2836709d69a700fa8444b91', 'channel_type': 'sbom', 'review_state': 'needs-review'},
                                        {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-99bc2ce5c67352c0ffdf914e', 'channel_type': 'schema', 'review_state': 'needs-review'}, {'authority_state': 'non-authoritative', 'availability_state': 'unresolved', 'channel_id': 'chn-29e00417fc32b43cfa9efea2', 'channel_type': 'source', 'review_state': 'needs-review'}],
                  'purl': 'pkg:oci/app?repository_url=registry.example.org/example/app'}],
  'dependency_edges': [],
  'gaps': [{'component_id': 'cmp-e3a2012f0f8df626445ba38f', 'component_version_id': 'ver-860ce11e99543b91d2aec1a6', 'evidence': ['input.json#/image', 'sha256:e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a'], 'gap_id': 'gap-179ad5948ae29021f6fd71d3', 'gap_type': 'oci-artifact-version-observed', 'message': 'OCI artifact version is bound to the receipt-verified registry manifest sha256:e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a'},
           {'component_id': 'cmp-e3a2012f0f8df626445ba38f', 'evidence': [], 'gap_id': 'gap-9cf29ed78a2eea6b41401a72', 'gap_type': 'transitive-inventory-unavailable', 'message': 'No authoritative lockfile or SBOM exposes transitive packages for cmp-e3a2012f0f8df626445ba38f'}, {'component_id': 'cmp-e3a2012f0f8df626445ba38f', 'evidence': [], 'gap_id': 'gap-d2ae83510e5143436b95568d', 'gap_type': 'official-channel-unresolved', 'message': 'No reviewed official channel is registered for cmp-e3a2012f0f8df626445ba38f'},
           {'component_id': 'cmp-e3a2012f0f8df626445ba38f', 'component_version_id': 'ver-860ce11e99543b91d2aec1a6', 'evidence': ['input.json#/image', 'sha256:e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a'], 'gap_id': 'gap-df38f1e0569e553224f39c2d', 'gap_type': 'oci-platform-observed', 'message': 'OCI artifact platform linux/amd64 is bound to the receipt-verified registry image config'}],
  'generation_state': 'candidate',
  'generator': {'name': 'knowledge-registry', 'ruleset_hash': 'sha256:e49f3c59e9a4f697b953166bd42e04ef0cf1a9838299fc2fd7168dc4418aa909', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'source_ref': 'tools/knowledge-registry/knowledge_registry.py#sha256:932e46cc7a68437ad6cb5eba1c8609a78d800806d8a082771807c124b2bdb6bc', 'version': '2'},
  'input_set': {'entries': [], 'required_source_classes': []},
  'manifest_version': 2,
  'occurrences': [{'component_id': 'cmp-e3a2012f0f8df626445ba38f', 'component_version_id': 'ver-860ce11e99543b91d2aec1a6', 'dependency_scope': 'deployment', 'directness': 'direct', 'evidence_locator': '/receipts/input.jsonl:1', 'lifecycle': 'repository-used', 'occurrence_id': 'occ-995f8358720fada88c27e03b', 'optional': False, 'raw_value': 'sha256:e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a', 'role': 'oci-artifact-observation', 'source_id': 'src-1248bd1500389ab27883b02a'}],
  'record_kind': 'generated_discovery_manifest',
  'schema_version': '2.0.0',
  'sources': [{'content_hash': 'sha256:e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a',
               'evidence_uri': 'oci-observation:sha256:e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a',
               'metadata': {'evidence_class': 'reference', 'receipt': {'canonical_uri': 'oci://registry.example.org/example/app:1.2.3', 'cas_path': 'cas/e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a', 'observed_at': '2026-01-02T03:04:06Z', 'runner_version': '', 'upstream_ref': 'sha256:e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a'}},
               'source_id': 'src-1248bd1500389ab27883b02a',
               'source_type': 'oci-artifact-observation'}],
  'versions': [{'component_id': 'cmp-e3a2012f0f8df626445ba38f',
                'component_version_id': 'ver-860ce11e99543b91d2aec1a6',
                'evidence': ['input.json#/image'],
                'metadata': {'oci_artifact_observation': {'evidence_cas_path': 'cas/e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a',
                                                          'evidence_content_hash': 'sha256:e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a',
                                                          'manifest_kind': 'manifest',
                                                          'manifest_media_type': 'application/vnd.oci.image.manifest.v1+json',
                                                          'observed_at': '2026-01-02T03:04:06Z',
                                                          'platform': 'linux/amd64',
                                                          'platforms': ['linux/amd64'],
                                                          'receipt_canonical_uri': 'oci://registry.example.org/example/app:1.2.3',
                                                          'reference': '1.2.3',
                                                          'reference_kind': 'tag',
                                                          'registry': 'registry.example.org',
                                                          'repository': 'example/app',
                                                          'resolved_digest': 'sha256:e08f004de94b7ea0bf4838e17f856272e014d3ef5913a31b826a0b4d85b2b53a',
                                                          'resolver': 'oci-registry-manifest'}},
                'resolution_state': 'unresolved',
                'resolved_version': '1.2.3'}],
  'bounds': {'tracked_files': 20000, 'discovery_files': 10000, 'discovery_file_bytes': 8388608, 'discovery_total_bytes': 134217728, 'json_input_bytes': 805306368, 'json_depth': 128, 'json_nodes': 20000000, 'serialized_output_bytes': 805306368, 'sources': 100000, 'components': 100000, 'versions': 200000, 'occurrences': 400000, 'dependency_edges': 700000, 'gaps': 400000},
  'counts': {'sources': 1, 'components': 1, 'versions': 1, 'occurrences': 1, 'dependency_edges': 0, 'gaps': 4},
  'completeness': {'input': {'state': 'unknown', 'input_count': 0, 'blocking_input_ids': []}, 'enumeration': {'state': 'unknown'}, 'closure': {'state': 'gapped', 'blocking_gap_ids': ['gap-9cf29ed78a2eea6b41401a72']}, 'identity': {'state': 'complete', 'blocking_gap_ids': []}, 'channel_review': {'state': 'gapped', 'required_slots': 16, 'accepted_slots': 0}, 'snapshots': {'state': 'unknown', 'accepted_available_channels': 0, 'immutable_verified_channels': 0, 'missing_channel_ids': []}, 'all_axes_complete': False},
  'reconciliation': {'previous_manifest_id': None, 'complete_mark': False, 'removal_allowed': False, 'added': [], 'changed': [], 'missing': [], 'removed': []},
  'integrity': {'canonicalization': 'archeion-canonical-json-v1', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'deterministic_order': True, 'exact_counts': {'sources': 1, 'components': 1, 'versions': 1, 'occurrences': 1, 'dependency_edges': 0, 'gaps': 4}, 'manifest_hash': 'sha256:6a228c1b3140537b56086e366023e0c5da9867cdaf5010c3a9da0d3e6660dd6f'},
  'manifest_id': 'mft-6a228c1b3140537b56086e366023e0c5da9867cdaf5010c3a9da0d3e6660dd6f'},
 {'record_kind': 'oci_identity_binding_summary',
  'baseline_manifest_id': 'mft-28a93fda3248b550960a3b3cd27aaee4d4be06af7bfb0bef02a627fe95426c7f',
  'receipts_dir': '/__fixture_root__',
  'receipts_verified': 1,
  'receipts_typed_failures': 0,
  'typed_failures': [],
  'receipts_refused': 0,
  'refused_receipts': [],
  'planned_refs': 1,
  'planned_refs_unreceipted': [],
  'planned_versions': 1,
  'unfetchable_version_ids': [],
  'components_bound': 1,
  'versions_bound': 1,
  'bound_version_ids_digest': 'sha256:4d37cd1bc45cecec00a7017d4f0e62cf095203d5914721ba121153f22d80707e',
  'skipped': {},
  'fragment_manifest_id': 'mft-6a228c1b3140537b56086e366023e0c5da9867cdaf5010c3a9da0d3e6660dd6f'})""",
    "test_bind_oci_identity.2": "('RegistryInputError', 'OCI receipts disagree on the identity of oci://registry.example.org/example/app:1.2.3: 2 distinct manifests across 2 receipts')",
    "test_identity_gate.1": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'generation-anchored': {'pass': True, 'anchor_manifest_id': 'mft-d8b890fff3c75ad5f7405c558935f120895b5cb74d53dd912273b9d14331ce22', 'control_identity_blocking': 0, 'violations': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'version-delta-justified': {'pass': False, 'versions': 2, 'declared_new': 0, 'declared_removed': 0, 'undeclared_new_version_ids': ['ver-932a9ce54053fd475f9927cb'], 'undeclared_removed_version_ids': []},
            'reviewed-version-generation': {'pass': True, 'stale_reviewed_version_ids': []},
            'platform-multi-zero': {'pass': True, 'control': 0, 'treatment': 0},
            'no-unknown-platform': {'pass': True, 'violations': []},
            'gap-arithmetic-identity': {'pass': True, 'control_identity_blocking': 0, 'treatment_identity_blocking': 0, 'closed': 0, 'closed_by_gap_type': {}, 'expected_closed_by_gap_type': {}, 'explained_by': {}, 'unexplained_closures': [], 'opened_gap_ids': []},
            'non-blocking-types-declared': {'pass': True, 'new_gap_types': [], 'blocking_new_gap_types': [], 'declared_non_blocking_types': ['gitops-self-reference-observed', 'oci-artifact-version-observed', 'oci-platform-index', 'oci-platform-observed']},
            'receipt-coverage': {'pass': True, 'receipts_verified': 0, 'receipts_refused': 0, 'refused_receipts': [], 'unused_receipt_hashes': [], 'oci_planned_refs': 0, 'oci_typed_failures': 0, 'oci_unreceipted_refs': [], 'oci_unused_receipt_refs': []},
            'axis-isolation': {'pass': True, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots_immutable_verified_channels': 0, 'violations': []},
            'deviations-ratified': {'pass': True, 'declarations': [], 'exempted_by_gap_type': {}, 'expected_exempted_by_gap_type': {}, 'violations': []},
            'closure-delta-evidenced': {'pass': True, 'reference_closure_blocking': 0, 'treatment_closure_blocking': 0, 'closed_by_gap_type': {}, 'sbom_inventory_subjects': 0, 'unexplained_closures': [], 'opened_gap_ids': []},
            'bounds': {'pass': True, 'versions': 2, 'bound': 200000}}}""",
    "test_identity_gate.2": r"""{'pass': True,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'generation-anchored': {'pass': True, 'anchor_manifest_id': 'mft-d8b890fff3c75ad5f7405c558935f120895b5cb74d53dd912273b9d14331ce22', 'control_identity_blocking': 0, 'violations': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'version-delta-justified': {'pass': True, 'versions': 2, 'declared_new': 1, 'declared_removed': 0, 'undeclared_new_version_ids': [], 'undeclared_removed_version_ids': []},
            'reviewed-version-generation': {'pass': True, 'stale_reviewed_version_ids': []},
            'platform-multi-zero': {'pass': True, 'control': 0, 'treatment': 0},
            'no-unknown-platform': {'pass': True, 'violations': []},
            'gap-arithmetic-identity': {'pass': True, 'control_identity_blocking': 0, 'treatment_identity_blocking': 0, 'closed': 0, 'closed_by_gap_type': {}, 'expected_closed_by_gap_type': {}, 'explained_by': {}, 'unexplained_closures': [], 'opened_gap_ids': []},
            'non-blocking-types-declared': {'pass': True, 'new_gap_types': [], 'blocking_new_gap_types': [], 'declared_non_blocking_types': ['gitops-self-reference-observed', 'oci-artifact-version-observed', 'oci-platform-index', 'oci-platform-observed']},
            'receipt-coverage': {'pass': True, 'receipts_verified': 0, 'receipts_refused': 0, 'refused_receipts': [], 'unused_receipt_hashes': [], 'oci_planned_refs': 0, 'oci_typed_failures': 0, 'oci_unreceipted_refs': [], 'oci_unused_receipt_refs': []},
            'axis-isolation': {'pass': True, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots_immutable_verified_channels': 0, 'violations': []},
            'deviations-ratified': {'pass': True, 'declarations': [], 'exempted_by_gap_type': {}, 'expected_exempted_by_gap_type': {}, 'violations': []},
            'closure-delta-evidenced': {'pass': True, 'reference_closure_blocking': 0, 'treatment_closure_blocking': 0, 'closed_by_gap_type': {}, 'sbom_inventory_subjects': 0, 'unexplained_closures': [], 'opened_gap_ids': []},
            'bounds': {'pass': True, 'versions': 2, 'bound': 200000}}}""",
    "test_identity_gate.3": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'generation-anchored': {'pass': True, 'anchor_manifest_id': 'mft-d8b890fff3c75ad5f7405c558935f120895b5cb74d53dd912273b9d14331ce22', 'control_identity_blocking': 0, 'violations': []},
            'zero-new-components': {'pass': False, 'new_component_ids': [], 'removed_component_ids': ['cmp-d25fa9e80d6b87b69c53aed9']},
            'version-delta-justified': {'pass': False, 'versions': 0, 'declared_new': 0, 'declared_removed': 0, 'undeclared_new_version_ids': [], 'undeclared_removed_version_ids': ['ver-30de7421b28e93364d3ed079']},
            'reviewed-version-generation': {'pass': True, 'stale_reviewed_version_ids': []},
            'platform-multi-zero': {'pass': True, 'control': 0, 'treatment': 0},
            'no-unknown-platform': {'pass': True, 'violations': []},
            'gap-arithmetic-identity': {'pass': True, 'control_identity_blocking': 0, 'treatment_identity_blocking': 0, 'closed': 0, 'closed_by_gap_type': {}, 'expected_closed_by_gap_type': {}, 'explained_by': {}, 'unexplained_closures': [], 'opened_gap_ids': []},
            'non-blocking-types-declared': {'pass': True, 'new_gap_types': [], 'blocking_new_gap_types': [], 'declared_non_blocking_types': ['gitops-self-reference-observed', 'oci-artifact-version-observed', 'oci-platform-index', 'oci-platform-observed']},
            'receipt-coverage': {'pass': True, 'receipts_verified': 0, 'receipts_refused': 0, 'refused_receipts': [], 'unused_receipt_hashes': [], 'oci_planned_refs': 0, 'oci_typed_failures': 0, 'oci_unreceipted_refs': [], 'oci_unused_receipt_refs': []},
            'axis-isolation': {'pass': True, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots_immutable_verified_channels': 0, 'violations': []},
            'deviations-ratified': {'pass': True, 'declarations': [], 'exempted_by_gap_type': {}, 'expected_exempted_by_gap_type': {}, 'violations': []},
            'closure-delta-evidenced': {'pass': True, 'reference_closure_blocking': 0, 'treatment_closure_blocking': 0, 'closed_by_gap_type': {}, 'sbom_inventory_subjects': 0, 'unexplained_closures': [], 'opened_gap_ids': []},
            'bounds': {'pass': True, 'versions': 0, 'bound': 200000}}}""",
    "test_identity_gate.4": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'generation-anchored': {'pass': False, 'anchor_manifest_id': 'mft-fce475094eadc4363ae774df9c8867d690376c40cbee429786017b1a7560738e', 'control_identity_blocking': 0, 'violations': ['control components differ from the anchor generation']},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'version-delta-justified': {'pass': True, 'versions': 2, 'declared_new': 1, 'declared_removed': 0, 'undeclared_new_version_ids': [], 'undeclared_removed_version_ids': []},
            'reviewed-version-generation': {'pass': True, 'stale_reviewed_version_ids': []},
            'platform-multi-zero': {'pass': True, 'control': 0, 'treatment': 0},
            'no-unknown-platform': {'pass': True, 'violations': []},
            'gap-arithmetic-identity': {'pass': True, 'control_identity_blocking': 0, 'treatment_identity_blocking': 0, 'closed': 0, 'closed_by_gap_type': {}, 'expected_closed_by_gap_type': {}, 'explained_by': {}, 'unexplained_closures': [], 'opened_gap_ids': []},
            'non-blocking-types-declared': {'pass': True, 'new_gap_types': [], 'blocking_new_gap_types': [], 'declared_non_blocking_types': ['gitops-self-reference-observed', 'oci-artifact-version-observed', 'oci-platform-index', 'oci-platform-observed']},
            'receipt-coverage': {'pass': True, 'receipts_verified': 0, 'receipts_refused': 0, 'refused_receipts': [], 'unused_receipt_hashes': [], 'oci_planned_refs': 0, 'oci_typed_failures': 0, 'oci_unreceipted_refs': [], 'oci_unused_receipt_refs': []},
            'axis-isolation': {'pass': True, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots_immutable_verified_channels': 0, 'violations': []},
            'deviations-ratified': {'pass': True, 'declarations': [], 'exempted_by_gap_type': {}, 'expected_exempted_by_gap_type': {}, 'violations': []},
            'closure-delta-evidenced': {'pass': True, 'reference_closure_blocking': 0, 'treatment_closure_blocking': 0, 'closed_by_gap_type': {}, 'sbom_inventory_subjects': 0, 'unexplained_closures': [], 'opened_gap_ids': []},
            'bounds': {'pass': True, 'versions': 2, 'bound': 200000}}}""",
    "identity-empty": r"""{'pass': True,
 'checks': {'merged-valid': {'pass': True, 'errors': []},
            'generation-anchored': {'pass': True, 'anchor_manifest_id': None, 'control_identity_blocking': 0, 'violations': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'version-delta-justified': {'pass': True, 'versions': 0, 'declared_new': 0, 'declared_removed': 0, 'undeclared_new_version_ids': [], 'undeclared_removed_version_ids': []},
            'reviewed-version-generation': {'pass': True, 'stale_reviewed_version_ids': []},
            'platform-multi-zero': {'pass': True, 'control': 0, 'treatment': 0},
            'no-unknown-platform': {'pass': True, 'violations': []},
            'gap-arithmetic-identity': {'pass': True, 'control_identity_blocking': 0, 'treatment_identity_blocking': 0, 'closed': 0, 'closed_by_gap_type': {}, 'expected_closed_by_gap_type': {}, 'explained_by': {}, 'unexplained_closures': [], 'opened_gap_ids': []},
            'non-blocking-types-declared': {'pass': True, 'new_gap_types': [], 'blocking_new_gap_types': [], 'declared_non_blocking_types': ['gitops-self-reference-observed', 'oci-artifact-version-observed', 'oci-platform-index', 'oci-platform-observed']},
            'receipt-coverage': {'pass': True, 'receipts_verified': 0, 'receipts_refused': 0, 'refused_receipts': [], 'unused_receipt_hashes': [], 'oci_planned_refs': 0, 'oci_typed_failures': 0, 'oci_unreceipted_refs': [], 'oci_unused_receipt_refs': []},
            'axis-isolation': {'pass': True, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots_immutable_verified_channels': 0, 'violations': []},
            'deviations-ratified': {'pass': True, 'declarations': [], 'exempted_by_gap_type': {}, 'expected_exempted_by_gap_type': {}, 'violations': []},
            'closure-delta-evidenced': {'pass': True, 'reference_closure_blocking': 0, 'treatment_closure_blocking': 0, 'closed_by_gap_type': {}, 'sbom_inventory_subjects': 0, 'unexplained_closures': [], 'opened_gap_ids': []},
            'bounds': {'pass': True, 'versions': 0, 'bound': 200000}}}""",
    "identity-invalid": r"""{'pass': False,
 'checks': {'merged-valid': {'pass': False,
                             'errors': ['$schema does not match the canonical v2 envelope', 'authority_boundary does not match the canonical v2 envelope', 'authority_boundary must remain unreviewed and deny admission, release, and mutation', 'bounds does not match the canonical v2 envelope', 'completeness does not match the canonical v2 envelope', 'components must be an array', 'counts must equal {"components":0,"dependency_edges":0,"gaps":0,"occurrences":0,"sources":0,"versions":0}', 'dependency_edges must be an array', 'gaps must be an array',
                                        'generation_state must equal candidate', 'generator does not match the canonical v2 envelope', 'generator must be an object', 'input_set does not match the canonical v2 envelope', 'input_set must be an object', 'integrity does not match the canonical v2 envelope', 'manifest_id does not match the canonical v2 envelope', 'manifest_version must equal 2', 'occurrences must be an array', 'reconciliation does not match the canonical v2 envelope', 'record_kind must equal generated_discovery_manifest']},
            'generation-anchored': {'pass': True, 'anchor_manifest_id': None, 'control_identity_blocking': 0, 'violations': []},
            'zero-new-components': {'pass': True, 'new_component_ids': [], 'removed_component_ids': []},
            'version-delta-justified': {'pass': True, 'versions': 0, 'declared_new': 0, 'declared_removed': 0, 'undeclared_new_version_ids': [], 'undeclared_removed_version_ids': []},
            'reviewed-version-generation': {'pass': True, 'stale_reviewed_version_ids': []},
            'platform-multi-zero': {'pass': True, 'control': 0, 'treatment': 0},
            'no-unknown-platform': {'pass': True, 'violations': []},
            'gap-arithmetic-identity': {'pass': True, 'control_identity_blocking': 0, 'treatment_identity_blocking': 0, 'closed': 0, 'closed_by_gap_type': {}, 'expected_closed_by_gap_type': {}, 'explained_by': {}, 'unexplained_closures': [], 'opened_gap_ids': []},
            'non-blocking-types-declared': {'pass': True, 'new_gap_types': [], 'blocking_new_gap_types': [], 'declared_non_blocking_types': ['gitops-self-reference-observed', 'oci-artifact-version-observed', 'oci-platform-index', 'oci-platform-observed']},
            'receipt-coverage': {'pass': True, 'receipts_verified': 0, 'receipts_refused': 0, 'refused_receipts': [], 'unused_receipt_hashes': [], 'oci_planned_refs': 0, 'oci_typed_failures': 0, 'oci_unreceipted_refs': [], 'oci_unused_receipt_refs': []},
            'axis-isolation': {'pass': True, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots_immutable_verified_channels': 0, 'violations': []},
            'deviations-ratified': {'pass': True, 'declarations': [], 'exempted_by_gap_type': {}, 'expected_exempted_by_gap_type': {}, 'violations': []},
            'closure-delta-evidenced': {'pass': True, 'reference_closure_blocking': 0, 'treatment_closure_blocking': 0, 'closed_by_gap_type': {}, 'sbom_inventory_subjects': 0, 'unexplained_closures': [], 'opened_gap_ids': []},
            'bounds': {'pass': True, 'versions': 0, 'bound': 200000}}}""",
    "gitops-no-receipts": r"""({'$schema': 'https://json-schema.org/draft/2020-12/schema',
  'authority_boundary': {'review_state': 'unreviewed', 'authoritative': False, 'compile_eligible': False, 'promote_eligible': False, 'source_admission': False, 'retrieval_release': False, 'production_mutation': False},
  'base_manifest_id': None,
  'components': [],
  'dependency_edges': [],
  'gaps': [],
  'generation_state': 'candidate',
  'generator': {'name': 'knowledge-registry', 'ruleset_hash': 'sha256:e49f3c59e9a4f697b953166bd42e04ef0cf1a9838299fc2fd7168dc4418aa909', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'source_ref': 'tools/knowledge-registry/knowledge_registry.py#sha256:932e46cc7a68437ad6cb5eba1c8609a78d800806d8a082771807c124b2bdb6bc', 'version': '2'},
  'input_set': {'entries': [], 'required_source_classes': []},
  'manifest_version': 2,
  'occurrences': [],
  'record_kind': 'generated_discovery_manifest',
  'schema_version': '2.0.0',
  'sources': [],
  'versions': [],
  'bounds': {'tracked_files': 20000, 'discovery_files': 10000, 'discovery_file_bytes': 8388608, 'discovery_total_bytes': 134217728, 'json_input_bytes': 805306368, 'json_depth': 128, 'json_nodes': 20000000, 'serialized_output_bytes': 805306368, 'sources': 100000, 'components': 100000, 'versions': 200000, 'occurrences': 400000, 'dependency_edges': 700000, 'gaps': 400000},
  'counts': {'sources': 0, 'components': 0, 'versions': 0, 'occurrences': 0, 'dependency_edges': 0, 'gaps': 0},
  'completeness': {'input': {'state': 'unknown', 'input_count': 0, 'blocking_input_ids': []}, 'enumeration': {'state': 'unknown'}, 'closure': {'state': 'unknown', 'blocking_gap_ids': []}, 'identity': {'state': 'complete', 'blocking_gap_ids': []}, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots': {'state': 'unknown', 'accepted_available_channels': 0, 'immutable_verified_channels': 0, 'missing_channel_ids': []}, 'all_axes_complete': False},
  'reconciliation': {'previous_manifest_id': None, 'complete_mark': False, 'removal_allowed': False, 'added': [], 'changed': [], 'missing': [], 'removed': []},
  'integrity': {'canonicalization': 'archeion-canonical-json-v1', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'deterministic_order': True, 'exact_counts': {'sources': 0, 'components': 0, 'versions': 0, 'occurrences': 0, 'dependency_edges': 0, 'gaps': 0}, 'manifest_hash': 'sha256:fce475094eadc4363ae774df9c8867d690376c40cbee429786017b1a7560738e'},
  'manifest_id': 'mft-fce475094eadc4363ae774df9c8867d690376c40cbee429786017b1a7560738e'},
 {'record_kind': 'gitops_identity_binding_summary', 'baseline_manifest_id': 'mft-fce475094eadc4363ae774df9c8867d690376c40cbee429786017b1a7560738e', 'observed_ref': 'refs/heads/example', 'receipts_dir': '/__fixture_root__', 'receipts_verified': 0, 'receipts_refused': 0, 'refused_receipts': [], 'commits': [], 'components_bound': 0, 'versions_bound': 0, 'bound_version_ids_digest': 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945', 'skipped': {}, 'fragment_manifest_id': 'mft-fce475094eadc4363ae774df9c8867d690376c40cbee429786017b1a7560738e'})""",
    "oci-no-receipts": r"""({'$schema': 'https://json-schema.org/draft/2020-12/schema',
  'authority_boundary': {'review_state': 'unreviewed', 'authoritative': False, 'compile_eligible': False, 'promote_eligible': False, 'source_admission': False, 'retrieval_release': False, 'production_mutation': False},
  'base_manifest_id': None,
  'components': [],
  'dependency_edges': [],
  'gaps': [],
  'generation_state': 'candidate',
  'generator': {'name': 'knowledge-registry', 'ruleset_hash': 'sha256:e49f3c59e9a4f697b953166bd42e04ef0cf1a9838299fc2fd7168dc4418aa909', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'source_ref': 'tools/knowledge-registry/knowledge_registry.py#sha256:932e46cc7a68437ad6cb5eba1c8609a78d800806d8a082771807c124b2bdb6bc', 'version': '2'},
  'input_set': {'entries': [], 'required_source_classes': []},
  'manifest_version': 2,
  'occurrences': [],
  'record_kind': 'generated_discovery_manifest',
  'schema_version': '2.0.0',
  'sources': [],
  'versions': [],
  'bounds': {'tracked_files': 20000, 'discovery_files': 10000, 'discovery_file_bytes': 8388608, 'discovery_total_bytes': 134217728, 'json_input_bytes': 805306368, 'json_depth': 128, 'json_nodes': 20000000, 'serialized_output_bytes': 805306368, 'sources': 100000, 'components': 100000, 'versions': 200000, 'occurrences': 400000, 'dependency_edges': 700000, 'gaps': 400000},
  'counts': {'sources': 0, 'components': 0, 'versions': 0, 'occurrences': 0, 'dependency_edges': 0, 'gaps': 0},
  'completeness': {'input': {'state': 'unknown', 'input_count': 0, 'blocking_input_ids': []}, 'enumeration': {'state': 'unknown'}, 'closure': {'state': 'unknown', 'blocking_gap_ids': []}, 'identity': {'state': 'complete', 'blocking_gap_ids': []}, 'channel_review': {'state': 'complete', 'required_slots': 0, 'accepted_slots': 0}, 'snapshots': {'state': 'unknown', 'accepted_available_channels': 0, 'immutable_verified_channels': 0, 'missing_channel_ids': []}, 'all_axes_complete': False},
  'reconciliation': {'previous_manifest_id': None, 'complete_mark': False, 'removal_allowed': False, 'added': [], 'changed': [], 'missing': [], 'removed': []},
  'integrity': {'canonicalization': 'archeion-canonical-json-v1', 'schema_hash': 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', 'deterministic_order': True, 'exact_counts': {'sources': 0, 'components': 0, 'versions': 0, 'occurrences': 0, 'dependency_edges': 0, 'gaps': 0}, 'manifest_hash': 'sha256:fce475094eadc4363ae774df9c8867d690376c40cbee429786017b1a7560738e'},
  'manifest_id': 'mft-fce475094eadc4363ae774df9c8867d690376c40cbee429786017b1a7560738e'},
 {'record_kind': 'oci_identity_binding_summary',
  'baseline_manifest_id': 'mft-fce475094eadc4363ae774df9c8867d690376c40cbee429786017b1a7560738e',
  'receipts_dir': '/__fixture_root__',
  'receipts_verified': 0,
  'receipts_typed_failures': 0,
  'typed_failures': [],
  'receipts_refused': 0,
  'refused_receipts': [],
  'planned_refs': 0,
  'planned_refs_unreceipted': [],
  'planned_versions': 0,
  'unfetchable_version_ids': [],
  'components_bound': 0,
  'versions_bound': 0,
  'bound_version_ids_digest': 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
  'skipped': {},
  'fragment_manifest_id': 'mft-fce475094eadc4363ae774df9c8867d690376c40cbee429786017b1a7560738e'})""",
}


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
        builder, _component, _ = package_builder()
        baseline = builder.manifest()
        entry = policy_entry()
        closed, _, _, _ = self.snapshot_fixture()
        check_output(
            self,
            EXPECTED,
            "test_derive_channel_records.1",
            kr.derive_channel_records,
            closed,
            [entry],
        )
        check_output(
            self,
            EXPECTED,
            "test_derive_channel_records.2",
            kr.derive_channel_records,
            baseline,
            [entry],
        )

        entry["preconditions"] = [("name", re.compile("^other$"))]
        check_output(
            self,
            EXPECTED,
            "test_derive_channel_records.3",
            kr.derive_channel_records,
            baseline,
            [entry],
        )
        with self.assertRaisesRegex(
            kr.RegistryInputError, "derive-channels baseline is invalid"
        ):
            check_output(
                self,
                EXPECTED,
                "test_derive_channel_records.4",
                kr.derive_channel_records,
                {},
                [entry],
            )

    def test_channel_wave_gate(self) -> None:
        """Check the declared wave size and reject a component delta."""
        builder, _, _ = package_builder()
        baseline = builder.manifest()
        check_output(
            self,
            EXPECTED,
            "test_channel_wave_gate.1",
            kr.channel_wave_gate,
            baseline,
            baseline,
            policies=[],
            expected_matched=0,
        )
        check_output(
            self,
            EXPECTED,
            "test_channel_wave_gate.2",
            kr.channel_wave_gate,
            baseline,
            baseline,
            policies=[],
            expected_matched=1,
        )

        builder.add_component(
            kind="library",
            ecosystem="pypi",
            name="other",
            purl="pkg:pypi/other",
            official_channel_required=False,
        )
        check_output(
            self,
            EXPECTED,
            "test_channel_wave_gate.3",
            kr.channel_wave_gate,
            baseline,
            kr.Builder().manifest(),
            policies=[],
            expected_matched=0,
        )
        check_output(
            self,
            EXPECTED,
            "test_channel_wave_gate.4",
            kr.channel_wave_gate,
            baseline,
            builder.manifest(),
            policies=[],
            expected_matched=0,
        )

    def test_bind_channel_snapshot_receipts(self) -> None:
        """Bind verified CAS bytes and report receipts for unknown channels."""
        baseline, record, channel, _version = self.snapshot_fixture()
        component = record["component"]["component_id"]
        row = self.receipt(CHANNEL_URI, channel, b"fixture snapshot\n")
        other = {**row, "channel_ids": ["chn:other"]}
        self.write_receipts(row, other)
        check_output(
            self,
            EXPECTED,
            "test_bind_channel_snapshot_receipts.1",
            kr.bind_channel_snapshot_receipts,
            [(component, record)],
            baseline,
            str(self.root),
        )

    def test_bind_channel_snapshot_receipts_conflict(self) -> None:
        """Reject distinct verified bytes for the same available channel."""
        baseline, record, channel, _ = self.snapshot_fixture()
        component = record["component"]["component_id"]
        row = self.receipt(CHANNEL_URI, channel, b"fixture snapshot\n")
        other = self.receipt(CHANNEL_URI, channel, b"other fixture snapshot\n")
        existing = [(component, record)]
        third = self.receipt(CHANNEL_URI, channel, b"third fixture snapshot\n")
        self.write_receipts(row, other, third)
        check_output(
            self,
            EXPECTED,
            "test_bind_channel_snapshot_receipts_conflict.1",
            kr.bind_channel_snapshot_receipts,
            existing,
            baseline,
            str(self.root),
        )

    def test_bind_channel_snapshot_receipts_rejects_uri_mismatch(self) -> None:
        """Refuse a verified receipt with a known channel ID and a different URI."""
        baseline, record, channel, _ = self.snapshot_fixture()
        component = record["component"]["component_id"]
        row = self.receipt("https://example.net/app", channel, b"fixture snapshot\n")
        self.write_receipts(row)
        check_output(
            self,
            EXPECTED,
            "test_bind_channel_snapshot_receipts_rejects_uri_mismatch.1",
            kr.bind_channel_snapshot_receipts,
            [(component, record)],
            baseline,
            str(self.root),
        )

    def test_channel_snapshot_gate_detects_corrupt_cas(self) -> None:
        """Reject a verified receipt whose object no longer matches its digest."""
        baseline, _, channel, _ = self.snapshot_fixture()
        row = self.receipt(CHANNEL_URI, channel, b"fixture snapshot\n")
        self.write(row["cas_path"], b"corrupt bytes\n")
        self.write_receipts(row)
        check_output(
            self,
            EXPECTED,
            "test_channel_snapshot_gate_detects_corrupt_cas.1",
            kr.channel_snapshot_gate,
            baseline,
            baseline,
            receipts_dir=str(self.root),
        )

    def test_channel_snapshot_gate(self) -> None:
        """Require a traced snapshot for each bindable receipt."""
        baseline, record, channel, _ = self.snapshot_fixture()
        component = record["component"]["component_id"]
        row = self.receipt(CHANNEL_URI, channel, b"fixture snapshot\n")
        self.write_receipts(row)
        check_output(
            self,
            EXPECTED,
            "test_channel_snapshot_gate.1",
            kr.channel_snapshot_gate,
            baseline,
            baseline,
            receipts_dir=str(self.root),
        )

        check_output(
            self,
            EXPECTED,
            "test_channel_snapshot_gate.2",
            kr.bind_channel_snapshot_receipts,
            [(component, record)],
            baseline,
            str(self.root),
        )
        (original,) = baseline["components"]
        changed = {**original, "official_channel_snapshots": record["snapshots"]}
        merged = kr.seal_manifest({**baseline, "components": [changed]})
        check_output(
            self,
            EXPECTED,
            "test_channel_snapshot_gate.3",
            kr.channel_snapshot_gate,
            baseline,
            merged,
            receipts_dir=str(self.root),
        )

        added_builder, _, _added_id = package_builder(observed="1.2.4")
        added = only(added_builder.versions)
        changed = kr.seal_manifest({**merged, "versions": [*merged["versions"], added]})
        check_output(
            self,
            EXPECTED,
            "test_channel_snapshot_gate.4",
            kr.channel_snapshot_gate,
            baseline,
            changed,
            receipts_dir=str(self.root),
        )

    def test_channel_derivation_empty_and_no_policy(self) -> None:
        """Count no candidates or policies without emitting reviewed records."""
        check_output(
            self,
            EXPECTED,
            "derive-empty",
            kr.derive_channel_records,
            kr.Builder().manifest(),
            [],
        )
        builder, _, _ = package_builder()
        check_output(
            self,
            EXPECTED,
            "derive-no-policy",
            kr.derive_channel_records,
            builder.manifest(),
            [],
        )
        disabled, _, _ = package_builder(required=False)
        check_output(
            self,
            EXPECTED,
            "derive-not-required",
            kr.derive_channel_records,
            disabled.manifest(),
            [policy_entry()],
        )

    def test_channel_derivation_matching_precondition_and_live_pointer(self) -> None:
        """Match an explicit selector and prefer the earliest live evidence pointer."""
        builder, component, _ = package_builder()
        builder.add_version(
            component,
            resolved_version="1.2.3",
            evidence=("live-export:widgets.json#/b", "live-export:widgets.json#/a"),
        )
        entry = policy_entry("{evidence_document}")
        entry["preconditions"] = [("name", re.compile("^app$"))]
        check_output(
            self,
            EXPECTED,
            "derive-matching",
            kr.derive_channel_records,
            builder.manifest(),
            [entry],
        )

    def test_channel_snapshot_receipts_no_bindable_version(self) -> None:
        """Report a verified channel row when the reviewed schema cannot express a version."""
        baseline, record, channel, _ = self.snapshot_fixture()
        component = record["component"]["component_id"]
        row = self.receipt(CHANNEL_URI, channel, b"fixture snapshot\n")
        self.write_receipts(row)
        check_output(
            self,
            EXPECTED,
            "snapshot-no-bindable",
            kr.bind_channel_snapshot_receipts,
            [(component, record)],
            {**baseline, "versions": []},
            str(self.root),
        )

    def test_channel_snapshot_receipts_corrupt_and_empty(self) -> None:
        """Give corrupt content a refusal and keep an empty batch unbound."""
        baseline, record, channel, _ = self.snapshot_fixture()
        component = record["component"]["component_id"]
        row = self.receipt(CHANNEL_URI, channel, b"fixture snapshot\n")
        self.write(row["cas_path"], b"changed")
        self.write_receipts(row)
        check_output(
            self,
            EXPECTED,
            "snapshot-cas-corrupt",
            kr.bind_channel_snapshot_receipts,
            [(component, record)],
            baseline,
            str(self.root),
        )
        self.write_receipts()
        check_output(
            self,
            EXPECTED,
            "snapshot-no-receipts",
            kr.bind_channel_snapshot_receipts,
            [],
            baseline,
            str(self.root),
        )

    def test_channel_gates_invalid_treatment(self) -> None:
        """Report invalid merged manifests and allow absent expected wave size."""
        baseline = kr.Builder().manifest()
        self.write_receipts()
        check_output(
            self,
            EXPECTED,
            "wave-invalid",
            kr.channel_wave_gate,
            baseline,
            {},
            policies=[],
        )
        check_output(
            self,
            EXPECTED,
            "snapshot-invalid",
            kr.channel_snapshot_gate,
            baseline,
            {},
            receipts_dir=str(self.root),
        )

    def test_wave_detects_unaccepted_channel_and_bad_bindings(self) -> None:
        """Refuse an available proposal and mismatched stamps at both evidence sites."""
        baseline, record, _channel_id, _version = self.snapshot_fixture()
        (component,) = baseline["components"]
        (channel,) = record["channels"]
        invalid_hash = "sha256:" + "b" * 64
        reviewer = f"channel-policy:fixture-policy@{invalid_hash}"
        citation = f"policy.json@{invalid_hash}"
        merged = {
            **baseline,
            "components": [
                {
                    **component,
                    "metadata": {
                        "review": {"reviewed_by": reviewer, "evidence": [citation]}
                    },
                    "official_channels": [
                        {**channel, "review_state": "proposed", "evidence": [citation]}
                    ],
                }
            ],
        }
        with patch.object(kr, "validate_manifest", return_value=[]):
            report = kr.channel_wave_gate(baseline, merged, policies=[policy_entry()])
        self.assertEqual(
            report, ast.literal_eval(EXPECTED["wave-unaccepted-bad-bindings"])
        )

    def test_snapshot_gate_detects_mismatched_and_failure_receipts(self) -> None:
        """Report an unknown channel, wrong URI, and unrepresented failure."""
        baseline, _, channel, _ = self.snapshot_fixture()
        self.write_receipts(
            self.receipt("https://example.net/app", channel, b"fixture mismatch"),
            self.receipt(CHANNEL_URI, "chn:other", b"fixture unknown"),
            {
                **self.receipt(CHANNEL_URI, channel, b"fixture failure"),
                "status": "failed",
            },
        )
        report = kr.channel_snapshot_gate(
            baseline, baseline, receipts_dir=str(self.root)
        )
        self.assertEqual(
            report, ast.literal_eval(EXPECTED["snapshot-mismatched-and-failed"])
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
        builder.add_version(component, source_ref="main", evidence=("input.json",))
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
        check_output(
            self,
            EXPECTED,
            "test_bind_gitops_identity.1",
            kr.bind_gitops_identity,
            baseline,
            str(self.root),
            observed_ref="MAIN",
        )
        with self.assertRaisesRegex(kr.RegistryInputError, "is not a mutable ref"):
            check_output(
                self,
                EXPECTED,
                "test_bind_gitops_identity.2",
                kr.bind_gitops_identity,
                baseline,
                str(self.root),
                observed_ref=commit,
            )

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
        check_output(
            self,
            EXPECTED,
            "test_bind_oci_identity.1",
            kr.bind_oci_identity,
            baseline,
            str(self.root),
        )

        conflicting = self.oci_receipt(version, "arm64")
        self.write_receipts(row, conflicting)
        with self.assertRaisesRegex(
            kr.RegistryInputError, "disagree on the identity.*2 distinct manifests"
        ):
            check_output(
                self,
                EXPECTED,
                "test_bind_oci_identity.2",
                kr.bind_oci_identity,
                baseline,
                str(self.root),
            )

    def test_identity_gate(self) -> None:
        """Require every added version to appear in the expected plan."""
        builder, component, _ = package_builder(required=False)
        control = builder.manifest()
        new_version = builder.add_version(component, resolved_version="1.2.4")
        treatment = builder.manifest()
        self.write_receipts()
        check_output(
            self,
            EXPECTED,
            "test_identity_gate.1",
            kr.identity_gate,
            control,
            treatment,
            receipts_dir=str(self.root),
            anchor=control,
        )
        check_output(
            self,
            EXPECTED,
            "test_identity_gate.2",
            kr.identity_gate,
            control,
            treatment,
            receipts_dir=str(self.root),
            anchor=control,
            expected_plan={"expected_new_version_ids": [new_version]},
        )

        anchor = kr.Builder().manifest()
        check_output(
            self,
            EXPECTED,
            "test_identity_gate.3",
            kr.identity_gate,
            control,
            anchor,
            receipts_dir=str(self.root),
            anchor=control,
        )
        check_output(
            self,
            EXPECTED,
            "test_identity_gate.4",
            kr.identity_gate,
            control,
            treatment,
            receipts_dir=str(self.root),
            anchor=anchor,
            expected_plan={"expected_new_version_ids": [new_version]},
        )

    def test_identity_gates_empty_inputs(self) -> None:
        """Report empty receipt collections and invalid input manifests."""
        baseline = kr.Builder().manifest()
        self.write_receipts()
        check_output(
            self,
            EXPECTED,
            "identity-empty",
            kr.identity_gate,
            baseline,
            baseline,
            receipts_dir=str(self.root),
        )
        check_output(
            self,
            EXPECTED,
            "identity-invalid",
            kr.identity_gate,
            baseline,
            {},
            receipts_dir=str(self.root),
        )
        check_output(
            self,
            EXPECTED,
            "gitops-no-receipts",
            kr.bind_gitops_identity,
            baseline,
            str(self.root),
            observed_ref="refs/heads/example",
        )
        check_output(
            self,
            EXPECTED,
            "oci-no-receipts",
            kr.bind_oci_identity,
            baseline,
            str(self.root),
        )

    def test_identity_binders_reject_invalid_baseline(self) -> None:
        """Return the complete two-error message before opening any receipts."""
        with patch.object(
            kr, "validate_manifest", return_value=["fixture first", "fixture second"]
        ):
            for bind in (kr.bind_gitops_identity, kr.bind_oci_identity):
                with self.subTest(bind=bind.__name__):
                    with self.assertRaises(kr.RegistryInputError) as caught:
                        bind({}, str(self.root))
                    self.assertEqual(
                        (type(caught.exception), str(caught.exception)),
                        (
                            kr.RegistryInputError,
                            "baseline is invalid: fixture first; fixture second",
                        ),
                    )

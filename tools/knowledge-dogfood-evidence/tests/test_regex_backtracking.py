"""Check broker digest captures and the search deadline."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

COLLECTOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COLLECTOR_DIR))

import collect  # noqa: E402
from broker_image_digest import (  # noqa: E402
    BROKER_IMAGE_DIGEST_RE,
    find_broker_image_digest,
)


class TestBrokerImageDigest(unittest.TestCase):
    def test_preserves_legacy_captures(self) -> None:
        """The helper captures what the replaced inline pattern captured."""
        cases = (
            ('image:\n  digest: "sha256:first"\n', "sha256:first"),
            ('image:\n  nested:\n    digest: "sha256:nested"\n', "sha256:nested"),
            ("image:\n  repository: broker\n", None),
            ('image:\n  repository: broker\nother:\n  digest: "sha256:other"\n', None),
            ('image:\n\t\t\n\trepository: broker\n\tdigest:\t"sha256:tab"\n', "sha256:tab"),
            ("image:\n  digest: sha256:unquoted\n", None),
            (
                'other:\n  enabled: true\nimage:\n  digest: "sha256:first"\n'
                '  digest: "sha256:second"\n',
                "sha256:first",
            ),
            ('image:\n  digest: "across\nlines"\n', "across\nlines"),
        )
        for values, expected in cases:
            with self.subTest(values=values):
                match = find_broker_image_digest(values)
                self.assertEqual(match.group(1) if match else None, expected)

    def test_long_missing_digest_returns_within_deadline(self) -> None:
        """A long image block with no digest returns before the deadline."""
        self.assertIn(r"(?:[ \t][^\n]*\n)*?", BROKER_IMAGE_DIGEST_RE.pattern)
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys\n"
                "from broker_image_digest import find_broker_image_digest\n"
                "sys.exit(find_broker_image_digest(sys.stdin.read()) is not None)\n",
            ],
            cwd=COLLECTOR_DIR,
            input="image:\n" + "\t\t\n" * 5000 + "x",
            text=True,
            timeout=5,
            check=True,
        )

    def test_collector_uses_the_digest_helper(self) -> None:
        """The rollback probe reads the digest through the helper."""
        values = 'image:\n  digest: "sha256:first"\n'
        repo = Mock(spec=collect.Repo)
        repo.git.return_value = values
        cluster = Mock(spec=collect.Cluster)
        cluster.kubectl_json.return_value = {"spec": {}}

        self.assertIs(collect.find_broker_image_digest, find_broker_image_digest)
        with patch.object(
            collect, "find_broker_image_digest", wraps=find_broker_image_digest
        ) as search:
            rollback = collect.collect_rollback(cluster, repo, pod=None, pod_error=None)

        search.assert_called_once_with(values)
        self.assertEqual(rollback["signals"]["git_declared_image_digest"]["value"], "sha256:first")

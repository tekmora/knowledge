"""Find the broker image digest in chart values."""

from __future__ import annotations

import re

BROKER_IMAGE_DIGEST_RE = re.compile(
    r'^image:\n(?:[ \t][^\n]*\n)*?[ \t]+digest:[ \t]*"([^"]+)"',
    re.MULTILINE,
)


def find_broker_image_digest(text: str) -> re.Match[str] | None:
    """Return the first quoted digest under the top-level image key, or None."""
    return BROKER_IMAGE_DIGEST_RE.search(text)

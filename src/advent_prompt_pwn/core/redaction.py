"""Conservative secret redaction for stored evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s,;]+"),
    re.compile(
        r"(?i)((?:access[_-]?token|client[_-]?secret|credential|passwd|password|"
        r"refresh[_-]?token)\s*[=:]\s*)[^\s,;&]+"
    ),
)
_REDACTION_MARKER = "[REDACTED]"


def _replace_outside_markers(value: str, secret: str) -> str:
    return _REDACTION_MARKER.join(
        part.replace(secret, _REDACTION_MARKER) for part in value.split(_REDACTION_MARKER)
    )


def redact_text(value: str, secrets: Sequence[str] = ()) -> str:
    """Redact known token shapes and caller-supplied values."""

    redacted = value
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        redacted = _replace_outside_markers(redacted, secret)
    for pattern in _PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub(_REDACTION_MARKER, redacted)
    return redacted


def redact_value(value: Any, secrets: Sequence[str] = ()) -> Any:
    """Recursively redact serializable values."""

    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            selected = redact_text(str(key), secrets)
            candidate = selected
            suffix = 2
            while candidate in redacted:
                candidate = f"{selected}#{suffix}"
                suffix += 1
            redacted[candidate] = redact_value(item, secrets)
        return redacted
    if isinstance(value, tuple):
        return tuple(redact_value(item, secrets) for item in value)
    if isinstance(value, list):
        return [redact_value(item, secrets) for item in value]
    return value


def redact_endpoint(value: str, secrets: Sequence[str] = ()) -> str:
    """Redact opaque paths, all query values, and fragments from endpoint evidence."""

    parsed = urlsplit(value)
    query = urlencode(
        [
            (redact_text(name, secrets), "[REDACTED]")
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
        ],
        doseq=True,
    )
    fragment = "[REDACTED]" if parsed.fragment else ""
    path = "/[REDACTED]" if parsed.path and parsed.path != "/" else parsed.path
    return urlunsplit(
        (
            redact_text(parsed.scheme, secrets),
            redact_text(parsed.netloc, secrets),
            path,
            query,
            fragment,
        )
    )

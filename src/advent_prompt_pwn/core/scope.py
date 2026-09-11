"""Authorization scope and request-budget enforcement."""

from __future__ import annotations

import ipaddress
import math
import re
import threading
import time
from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qsl, urlparse

from advent_prompt_pwn.exceptions import BudgetExceeded, ScopeViolation

_SENSITIVE_QUERY_PARTS = {
    "access",
    "assertion",
    "auth",
    "authorization",
    "bearer",
    "code",
    "credential",
    "jwt",
    "key",
    "passwd",
    "password",
    "secret",
    "session",
    "sig",
    "signature",
    "token",
}
_SENSITIVE_QUERY_NAMES = {
    "accesskey",
    "accesskeyid",
    "accesstoken",
    "apikey",
    "clientassertion",
    "clientsecret",
    "idtoken",
    "refreshtoken",
    "xapikey",
}
_SENSITIVE_QUERY_FRAGMENTS = {
    "accesstoken",
    "apikey",
    "authorization",
    "bearer",
    "clientassertion",
    "clientsecret",
    "credential",
    "idtoken",
    "jwt",
    "passwd",
    "password",
    "refreshtoken",
    "session",
    "signature",
}


def _is_sensitive_query_name(name: str) -> bool:
    folded = name.casefold()
    parts = tuple(part for part in re.split(r"[^a-z0-9]+", folded) if part)
    collapsed = "".join(parts)
    return (
        collapsed in _SENSITIVE_QUERY_NAMES
        or any(fragment in collapsed for fragment in _SENSITIVE_QUERY_FRAGMENTS)
        or any(part in _SENSITIVE_QUERY_PARTS for part in parts)
        or collapsed.endswith(("secret", "token"))
    )


class ScopeMode(str, Enum):
    """Supported authorization modes."""

    LOCAL = "local"
    AUTHORIZED_REMOTE = "authorized_remote"


def _is_local_host(host: str) -> bool:
    normalized = host.lower().rstrip(".")
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class Scope:
    """Explicit authorization boundary for a run."""

    mode: ScopeMode
    allowed_hosts: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    authorization_reference: str | None = None
    max_requests: int = 100
    requests_per_minute: int = 60
    max_concurrency: int = 1
    allow_insecure_http: bool = False
    allowed_query_parameters: tuple[str, ...] = ()
    allow_unpinned_dns: bool = False

    def __post_init__(self) -> None:
        normalized_hosts = tuple(
            sorted({host.lower().rstrip(".") for host in self.allowed_hosts if host.strip()})
        )
        if any(
            "://" in host or "/" in host or any(character.isspace() for character in host)
            for host in normalized_hosts
        ):
            raise ValueError("allowed hosts must be bare hostnames or IP addresses")
        object.__setattr__(self, "allowed_hosts", normalized_hosts)
        object.__setattr__(self, "allowed_ports", tuple(sorted(set(self.allowed_ports))))
        query_parameters = tuple(
            sorted({name for name in self.allowed_query_parameters if name.strip()})
        )
        if any(_is_sensitive_query_name(name) for name in query_parameters):
            raise ValueError("credential-like query parameter names cannot be allowlisted")
        object.__setattr__(self, "allowed_query_parameters", query_parameters)
        if self.max_requests < 1:
            raise ValueError("max_requests must be positive")
        if self.requests_per_minute < 1:
            raise ValueError("requests_per_minute must be positive")
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        if self.max_concurrency > 32:
            raise ValueError("max_concurrency must not exceed 32")
        if any(not 1 <= port <= 65535 for port in self.allowed_ports):
            raise ValueError("allowed ports must be between 1 and 65535")
        if self.mode is ScopeMode.AUTHORIZED_REMOTE:
            if not self.allowed_hosts:
                raise ValueError("authorized remote scope requires at least one allowed host")
            if not self.authorization_reference or not self.authorization_reference.strip():
                raise ValueError("authorized remote scope requires an authorization reference")

    @classmethod
    def local_only(
        cls,
        *,
        max_requests: int = 100,
        requests_per_minute: int = 120,
        max_concurrency: int = 1,
        authorization_reference: str | None = None,
        allowed_query_parameters: list[str] | tuple[str, ...] = (),
    ) -> Scope:
        """Create a scope restricted to in-memory and loopback targets."""

        return cls(
            mode=ScopeMode.LOCAL,
            authorization_reference=authorization_reference,
            max_requests=max_requests,
            requests_per_minute=requests_per_minute,
            max_concurrency=max_concurrency,
            allow_insecure_http=True,
            allowed_query_parameters=tuple(allowed_query_parameters),
        )

    @classmethod
    def authorized(
        cls,
        allowed_hosts: list[str] | tuple[str, ...],
        authorization_reference: str,
        *,
        allowed_ports: list[int] | tuple[int, ...] = (),
        max_requests: int = 100,
        requests_per_minute: int = 60,
        max_concurrency: int = 1,
        allow_insecure_http: bool = False,
        allowed_query_parameters: list[str] | tuple[str, ...] = (),
        allow_unpinned_dns: bool = False,
    ) -> Scope:
        """Create an explicit allowlisted remote scope."""

        hosts = tuple(sorted({host.lower().rstrip(".") for host in allowed_hosts if host.strip()}))
        return cls(
            mode=ScopeMode.AUTHORIZED_REMOTE,
            allowed_hosts=hosts,
            allowed_ports=tuple(sorted(set(allowed_ports))),
            authorization_reference=authorization_reference,
            max_requests=max_requests,
            requests_per_minute=requests_per_minute,
            max_concurrency=max_concurrency,
            allow_insecure_http=allow_insecure_http,
            allowed_query_parameters=tuple(allowed_query_parameters),
            allow_unpinned_dns=allow_unpinned_dns,
        )

    def assert_endpoint(self, endpoint: str) -> None:
        """Raise when an endpoint is outside this scope."""

        try:
            parsed = urlparse(endpoint)
            host = parsed.hostname
        except ValueError as exc:
            raise ScopeViolation("target endpoint is malformed") from exc
        if parsed.scheme in {"memory", "function"}:
            return
        if not host:
            raise ScopeViolation("target endpoint has no valid host")
        if parsed.scheme not in {"http", "https"}:
            raise ScopeViolation(f"target endpoint uses unsupported scheme: {parsed.scheme!r}")
        if parsed.username or parsed.password:
            raise ScopeViolation("target endpoint must not contain embedded credentials")
        query_names = tuple(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
        if any(_is_sensitive_query_name(name) for name in query_names):
            raise ScopeViolation("target endpoint must not contain credentials in its query")
        unexpected_query_names = sorted(set(query_names) - set(self.allowed_query_parameters))
        if unexpected_query_names:
            raise ScopeViolation(
                "target endpoint query parameter is not explicitly allowlisted: "
                + ", ".join(unexpected_query_names)
            )
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ScopeViolation("target endpoint has an invalid port") from exc
        if self.mode is ScopeMode.LOCAL:
            if not _is_local_host(host):
                raise ScopeViolation(f"local scope rejected non-loopback target host: {host}")
            return
        normalized = host.lower().rstrip(".")
        if normalized not in self.allowed_hosts:
            raise ScopeViolation(f"target host {host!r} is not in the authorization allowlist")
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            if not self.allow_unpinned_dns:
                raise ScopeViolation(
                    "authorized remote DNS hostnames require explicit unpinned-DNS opt-in "
                    "and enforced network egress controls"
                ) from None
        if parsed.scheme == "http" and not self.allow_insecure_http:
            raise ScopeViolation(
                "authorized remote HTTP requires explicit insecure-transport opt-in"
            )
        if self.allowed_ports and port not in self.allowed_ports:
            raise ScopeViolation(f"target port {port} is not in the authorization allowlist")


class RequestGuard:
    """Thread-safe request budget and simple fixed-interval rate limiter."""

    def __init__(
        self,
        scope: Scope,
        *,
        initial_count: int = 0,
        initial_not_before_epoch_s: float | None = None,
    ) -> None:
        if initial_count < 0:
            raise ValueError("initial_count must not be negative")
        if initial_count > scope.max_requests:
            raise BudgetExceeded(
                f"previous request count {initial_count} exceeds budget {scope.max_requests}"
            )
        if initial_not_before_epoch_s is not None and (
            isinstance(initial_not_before_epoch_s, bool)
            or not isinstance(initial_not_before_epoch_s, (int, float))
            or not math.isfinite(initial_not_before_epoch_s)
            or initial_not_before_epoch_s < 0
        ):
            raise ValueError("initial rate-limit timestamp must be a finite non-negative number")
        minimum_interval = 60.0 / scope.requests_per_minute
        remaining = (
            max(0.0, initial_not_before_epoch_s - time.time())
            if initial_not_before_epoch_s is not None
            else 0.0
        )
        if remaining > minimum_interval + 1.0:
            raise ValueError("initial rate-limit timestamp is more than one interval in the future")
        self._scope = scope
        self._count = initial_count
        self._next_request = time.monotonic() + remaining
        self._lock = threading.Lock()

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    def acquire(self) -> None:
        """Reserve and rate-limit one request."""

        self.reserve(1)
        self.wait()

    def reserve(self, count: int) -> None:
        """Conservatively reserve requests before they can be dispatched."""

        if count < 0:
            raise ValueError("reservation count must not be negative")
        if count == 0:
            return
        with self._lock:
            if self._count + count > self._scope.max_requests:
                raise BudgetExceeded(
                    f"request budget exhausted: reservation would exceed "
                    f"{self._scope.max_requests} requests"
                )
            self._count += count

    def release(self, count: int) -> None:
        """Release unused pre-dispatch reservations."""

        if count < 0:
            raise ValueError("release count must not be negative")
        if count == 0:
            return
        with self._lock:
            if count > self._count:
                raise ValueError("cannot release more requests than are reserved")
            self._count -= count

    def wait(self) -> None:
        """Apply the shared rate limit to one already reserved request."""

        minimum_interval = 60.0 / self._scope.requests_per_minute
        while True:
            with self._lock:
                now = time.monotonic()
                remaining = self._next_request - now
                if remaining <= 0:
                    self._next_request = now + minimum_interval
                    return
            time.sleep(remaining)

"""Authorization scope and request-budget enforcement."""

from __future__ import annotations

import ipaddress
import math
import re
import socket
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
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


def _parse_time_bound(value: str | None, label: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty ISO 8601 timestamp")
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


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
    pinned_dns: Mapping[str, Sequence[str]] = field(default_factory=dict, hash=False)
    not_before: str | None = None
    not_after: str | None = None

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
        if not isinstance(self.pinned_dns, Mapping):
            raise ValueError("pinned_dns must be a hostname-to-addresses mapping")
        normalized_pins: dict[str, tuple[str, ...]] = {}
        for host, addresses in self.pinned_dns.items():
            normalized_host = str(host).lower().rstrip(".")
            if not normalized_host or "://" in normalized_host or "/" in normalized_host:
                raise ValueError("pinned DNS keys must be bare hostnames")
            try:
                ipaddress.ip_address(normalized_host)
            except ValueError:
                pass
            else:
                raise ValueError("pinned DNS keys must be hostnames, not IP addresses")
            if normalized_host not in normalized_hosts:
                raise ValueError("pinned DNS host must be present in allowed_hosts")
            if isinstance(addresses, (str, bytes)):
                raise ValueError("pinned DNS values must be sequences of IP addresses")
            try:
                normalized_addresses = tuple(
                    sorted({str(ipaddress.ip_address(address)) for address in addresses})
                )
            except ValueError as exc:
                raise ValueError("pinned DNS values must be IP addresses") from exc
            if not normalized_addresses:
                raise ValueError("pinned DNS hosts require at least one IP address")
            normalized_pins[normalized_host] = normalized_addresses
        object.__setattr__(self, "pinned_dns", MappingProxyType(normalized_pins))
        lower_bound = _parse_time_bound(self.not_before, "not_before")
        upper_bound = _parse_time_bound(self.not_after, "not_after")
        if lower_bound and upper_bound and lower_bound >= upper_bound:
            raise ValueError("not_before must be earlier than not_after")
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
        not_before: str | None = None,
        not_after: str | None = None,
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
            not_before=not_before,
            not_after=not_after,
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
        pinned_dns: Mapping[str, Sequence[str]] | None = None,
        not_before: str | None = None,
        not_after: str | None = None,
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
            pinned_dns={host: tuple(addresses) for host, addresses in (pinned_dns or {}).items()},
            not_before=not_before,
            not_after=not_after,
        )

    def assert_active(self, at: datetime | None = None) -> None:
        """Raise when the current time is outside the authorized window."""

        selected = at or datetime.now(timezone.utc)
        if selected.tzinfo is None or selected.utcoffset() is None:
            raise ValueError("active-window check requires a timezone-aware datetime")
        selected = selected.astimezone(timezone.utc)
        lower_bound = _parse_time_bound(self.not_before, "not_before")
        upper_bound = _parse_time_bound(self.not_after, "not_after")
        if lower_bound and selected < lower_bound:
            raise ScopeViolation("engagement authorization window has not started")
        if upper_bound and selected >= upper_bound:
            raise ScopeViolation("engagement authorization window has ended")

    def assert_endpoint(
        self,
        endpoint: str,
        *,
        verify_dns: bool = True,
        verify_time: bool = True,
    ) -> None:
        """Raise when an endpoint is outside this scope."""

        if verify_time:
            self.assert_active()

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
            pins = self.pinned_dns.get(normalized)
            if pins and verify_dns:
                try:
                    answers = {
                        str(ipaddress.ip_address(item[4][0]))
                        for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                    }
                except (OSError, ValueError) as exc:
                    raise ScopeViolation("pinned DNS resolution failed") from exc
                if not answers or not answers.issubset(set(pins)):
                    raise ScopeViolation(
                        "target DNS result did not match its approved IP pins"
                    ) from None
            elif not pins and not self.allow_unpinned_dns:
                raise ScopeViolation(
                    "authorized remote DNS hostnames require approved IP pins or explicit "
                    "unpinned-DNS opt-in with enforced network egress controls"
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

        self._scope.assert_active()
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
            self._scope.assert_active()
            with self._lock:
                now = time.monotonic()
                remaining = self._next_request - now
                if remaining <= 0:
                    self._scope.assert_active()
                    self._next_request = now + minimum_interval
                    return
            time.sleep(remaining)

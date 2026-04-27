"""Authorization scope helpers for CactusFuzz."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlparse


class ScopeError(PermissionError):
    """Raised when an adversarial action is outside authorized scope."""


_DOMAIN_RE = re.compile(r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)


@dataclass(frozen=True)
class AuthorizationScope:
    """Explicit authorization boundary for red-team/adversarial testing."""

    targets: tuple[str, ...]
    operator: str = "unknown"
    engagement_id: str = "local-lab"
    allow_network_contact: bool = False
    allow_shell: bool = False

    def normalized_targets(self) -> tuple[str, ...]:
        return tuple(t.strip().lower().rstrip(".") for t in self.targets if t and t.strip())

    def require_authorized(self, target: str) -> None:
        if not self.contains(target):
            raise ScopeError(f"Target outside CactusFuzz authorized scope: {target}")

    def contains(self, target: str) -> bool:
        host = normalize_host(target)
        if not host:
            return False

        target_ip = _try_parse_ip(host)

        for raw_scope in self.normalized_targets():
            if self._matches_scope(host, target_ip, raw_scope):
                return True

        return False

    def _matches_scope(
        self,
        host: str,
        target_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
        raw_scope: str,
    ) -> bool:
        """Check if host matches a single scope entry."""
        # Explicit lab aliases such as "local-lab" are valid for offline simulation.
        if host == raw_scope:
            return True

        # Check CIDR network match
        if "/" in raw_scope:
            return self._matches_cidr(target_ip, raw_scope)

        scope_host = normalize_host(raw_scope)

        # Check IP address match
        scope_ip = _try_parse_ip(scope_host)
        if scope_ip is not None:
            return target_ip is not None and target_ip == scope_ip

        # Check domain match (including subdomain)
        return self._matches_domain(host, scope_host)

    def _matches_cidr(
        self, target_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None, raw_scope: str
    ) -> bool:
        """Check if target IP is within a CIDR network."""
        if target_ip is None:
            return False
        try:
            net = ipaddress.ip_network(raw_scope, strict=False)
            return target_ip in net
        except ValueError:
            return False

    def _matches_domain(self, host: str, scope_host: str) -> bool:
        """Check if host matches scope domain (including subdomains)."""
        if not (_DOMAIN_RE.match(scope_host) and _DOMAIN_RE.match(host)):
            return False
        return host == scope_host or host.endswith(f".{scope_host}")


def _try_parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Try to parse a value as an IP address.

    Args:
        value: String that may represent an IPv4 or IPv6 address.

    Returns:
        Parsed IP address object if valid, None otherwise.
    """
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def normalize_host(value: str) -> str:
    """Normalize a hostname or URL to a canonical form.

    Strips whitespace, converts to lowercase, removes trailing dots,
    and extracts the hostname from URLs.

    Args:
        value: Raw hostname or URL string.

    Returns:
        Normalized hostname.
    """
    value = (value or "").strip().lower().rstrip(".")
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).strip().lower().rstrip(".")


__all__ = [
    "AuthorizationScope",
    "ScopeError",
    "normalize_host",
]

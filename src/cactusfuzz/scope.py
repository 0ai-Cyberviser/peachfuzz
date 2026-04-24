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

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None

        for raw_scope in self.normalized_targets():
            # Explicit lab aliases such as "local-lab" are valid for offline simulation.
            if host == raw_scope:
                return True

            if "/" in raw_scope:
                try:
                    net = ipaddress.ip_network(raw_scope, strict=False)
                    if ip is not None and ip in net:
                        return True
                except ValueError:
                    pass
                continue

            scope_host = normalize_host(raw_scope)
            try:
                scope_ip = ipaddress.ip_address(scope_host)
                if ip is not None and ip == scope_ip:
                    return True
                continue
            except ValueError:
                pass

            if _DOMAIN_RE.match(scope_host) and _DOMAIN_RE.match(host):
                if host == scope_host or host.endswith(f".{scope_host}"):
                    return True

        return False


def normalize_host(value: str) -> str:
    value = (value or "").strip().lower().rstrip(".")
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).strip().lower().rstrip(".")

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from app.core.exceptions import AuthorizationRequired, ScopeViolation, ValidationError

HOSTNAME_RE = re.compile(r"^(?=.{1,253}\.?$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.?$")


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    value: str
    is_network: bool
    count: int


class ScopeValidator:
    def __init__(self, allowlist: list[str] | None = None, denylist: list[str] | None = None, max_targets: int = 256):
        self.allowlist = allowlist or []
        self.denylist = denylist or []
        self.max_targets = max_targets

    @staticmethod
    def _network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        try:
            return ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None

    def validate(self, target: str, scope: str | None, authorized: bool) -> ValidatedTarget:
        if not authorized:
            raise AuthorizationRequired("Explicit authorization confirmation is required")
        target = target.strip()
        if not target or any(ch.isspace() for ch in target):
            raise ValidationError("Target must be a single IP, CIDR, or hostname")
        target_net = self._network(target)
        if target_net:
            count = target_net.num_addresses
            if count > self.max_targets:
                raise ScopeViolation(f"Target contains {count} addresses; maximum is {self.max_targets}")
        elif HOSTNAME_RE.fullmatch(target):
            count = 1
        else:
            raise ValidationError("Invalid target")

        if self._overlaps_any(target, self.denylist):
            raise ScopeViolation("Target is denied by policy")
        effective_scope = scope.strip() if scope else None
        if effective_scope and not self._inside_scope(target, effective_scope):
            raise ScopeViolation("Target is outside the declared scope")
        if self.allowlist and not self._matches_any(target, self.allowlist):
            raise ScopeViolation("Target is not in the configured allowlist")
        return ValidatedTarget(target, target_net is not None and "/" in target, count)

    def _inside_scope(self, target: str, scope: str) -> bool:
        scope_net = self._network(scope)
        target_net = self._network(target)
        if scope_net and target_net:
            if target_net.version != scope_net.version:
                return False
            return target_net.subnet_of(scope_net)  # type: ignore[arg-type]
        return target.casefold() == scope.casefold()

    def _matches_any(self, target: str, entries: list[str]) -> bool:
        return any(self._inside_scope(target, item) for item in entries)

    def _overlaps_any(self, target: str, entries: list[str]) -> bool:
        target_net = self._network(target)
        for item in entries:
            item_net = self._network(item)
            if target_net and item_net and target_net.version == item_net.version and target_net.overlaps(item_net):
                return True
            if target.casefold() == item.casefold():
                return True
        return False

"""
backend/guardrails/scope.py
Enforces target boundaries, network exclusions, and authorized lab boundaries.
"""

import ipaddress
import socket
from typing import Union
from backend.models import AssessmentScope


class ScopeViolationError(Exception):
    """Raised when an action targets an unapproved or excluded host."""
    pass


class ScopeValidator:
    def __init__(self, scope: AssessmentScope):
        self.scope = scope
        self.authorized_networks = []
        self.excluded_networks = []
        self._initialize_networks()

    def _initialize_networks(self):
        for target in self.scope.authorized_targets:
            self.authorized_networks.append(self._parse_network(target))
        for excluded in self.scope.excluded_targets:
            self.excluded_networks.append(self._parse_network(excluded))

    @staticmethod
    def _parse_network(target_str: str) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
        target_str = target_str.strip()
        try:
            return ipaddress.ip_network(target_str, strict=False)
        except ValueError:
            # Resolve hostname to IP if target is a domain/hostname
            ip_str = socket.gethostbyname(target_str)
            return ipaddress.ip_network(ip_str, strict=False)

    def is_target_allowed(self, target: str) -> bool:
        """
        Verifies whether an IP or domain is within authorized scope
        and not inside an excluded range.
        """
        try:
            target_net = self._parse_network(target)
            target_ip = target_net.network_address
        except Exception:
            return False

        # Check explicit exclusions first
        for excluded in self.excluded_networks:
            if target_ip in excluded:
                return False

        # Verify against authorized boundaries
        for authorized in self.authorized_networks:
            if target_ip in authorized:
                return True

        return False

    def enforce_scope(self, target: str) -> None:
        """Raises ScopeViolationError if the target fails validation."""
        if not self.is_target_allowed(target):
            raise ScopeViolationError(
                f"Target '{target}' violates authorized scope or matches exclusion boundaries."
            )
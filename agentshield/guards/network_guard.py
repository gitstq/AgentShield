"""Network request guard for AgentShield.

Controls HTTP requests by domain, method, URL patterns, and protocol.
Supports blocking internal IPs and restricting to HTTPS-only.
"""

import fnmatch
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from agentshield.guards.base import BaseGuard, GuardResult

# Pattern for matching private/internal IP addresses
_PRIVATE_IP_PATTERNS = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^::1$"),
    re.compile(r"^fe80:"),
    re.compile(r"^fc"),
    re.compile(r"^fd"),
]


class NetworkGuard(BaseGuard):
    """Guard for controlling network requests.

    Controls HTTP requests based on domain allow/deny lists, method restrictions,
    protocol requirements, and internal IP blocking.

    Attributes:
        denied_domains: Set of domain patterns that are denied.
        allowed_domains: Set of domain patterns that are allowed.
        denied_methods: Set of HTTP methods that are denied.
        allowed_methods: Set of HTTP methods that are allowed.
        denied_url_patterns: Set of URL glob patterns that are denied.
        allowed_url_patterns: Set of URL glob patterns that are allowed.
        https_only: If True, only HTTPS URLs are allowed.
        block_internal_ips: If True, requests to internal IPs are blocked.
        allow_by_default: If True, allow all requests not explicitly denied.
    """

    def __init__(
        self,
        name: str = "network",
        description: str = "Controls network requests",
        enforce_mode: bool = True,
        enabled: bool = True,
        denied_domains: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None,
        denied_methods: Optional[List[str]] = None,
        allowed_methods: Optional[List[str]] = None,
        denied_url_patterns: Optional[List[str]] = None,
        allowed_url_patterns: Optional[List[str]] = None,
        https_only: bool = False,
        block_internal_ips: bool = True,
        allow_by_default: bool = False,
    ):
        super().__init__(
            name=name,
            description=description,
            enforce_mode=enforce_mode,
            enabled=enabled,
        )
        self.denied_domains: Set[str] = set(denied_domains or [])
        self.allowed_domains: Set[str] = set(allowed_domains or [])
        self.denied_methods: Set[str] = set(denied_methods or [])
        self.allowed_methods: Set[str] = set(allowed_methods or [])
        self.denied_url_patterns: Set[str] = set(denied_url_patterns or [])
        self.allowed_url_patterns: Set[str] = set(allowed_url_patterns or [])
        self.https_only = https_only
        self.block_internal_ips = block_internal_ips
        self.allow_by_default = allow_by_default

    @staticmethod
    def _parse_url(url: str) -> Optional[urlparse]:
        """Parse a URL string.

        Args:
            url: The URL string to parse.

        Returns:
            A urlparse result, or None if parsing fails.
        """
        try:
            return urlparse(url)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _is_internal_ip(hostname: str) -> bool:
        """Check if a hostname is an internal/private IP address.

        Args:
            hostname: The hostname to check.

        Returns:
            True if the hostname appears to be a private/internal IP.
        """
        for pattern in _PRIVATE_IP_PATTERNS:
            if pattern.match(hostname):
                return True
        return False

    def _matches_any(self, value: str, patterns: Set[str]) -> bool:
        """Check if a value matches any of the given glob patterns.

        Args:
            value: The string to check.
            patterns: Set of glob patterns.

        Returns:
            True if the value matches any pattern.
        """
        return any(fnmatch.fnmatch(value, p) for p in patterns)

    def check(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any],
    ) -> GuardResult:
        """Check whether a network request is allowed.

        Args:
            action: The action (e.g., "http:request", "http:get", "http:post").
            resource: The URL being accessed.
            context: Additional context (may contain "method" key).

        Returns:
            GuardResult indicating whether the action is allowed.
        """
        # Only handle network-related actions
        if not action.startswith("http:") and not action.startswith("network:"):
            return GuardResult(
                allowed=True,
                reason=f"Guard '{self.name}' does not handle action '{action}'",
            )

        parsed = self._parse_url(resource)
        if parsed is None:
            return GuardResult(
                allowed=False,
                reason=f"Invalid URL: '{resource}'",
                details={"guard": self.name, "resource": resource},
            )

        hostname = parsed.hostname or ""
        method = context.get("method", "").upper()
        scheme = parsed.scheme.lower()

        # Check HTTPS-only requirement
        if self.https_only and scheme != "https":
            return GuardResult(
                allowed=False,
                reason=f"Non-HTTPS URL blocked: '{resource}'",
                details={
                    "guard": self.name,
                    "resource": resource,
                    "scheme": scheme,
                },
            )

        # Check internal IP blocking
        if self.block_internal_ips and self._is_internal_ip(hostname):
            return GuardResult(
                allowed=False,
                reason=f"Internal IP address blocked: '{hostname}'",
                details={
                    "guard": self.name,
                    "resource": resource,
                    "hostname": hostname,
                },
            )

        # Check denied domains
        if self._matches_any(hostname, self.denied_domains):
            return GuardResult(
                allowed=False,
                reason=f"Domain '{hostname}' is denied",
                details={
                    "guard": self.name,
                    "resource": resource,
                    "hostname": hostname,
                },
            )

        # Check denied methods
        if method and self._matches_any(method, self.denied_methods):
            return GuardResult(
                allowed=False,
                reason=f"HTTP method '{method}' is denied",
                details={
                    "guard": self.name,
                    "resource": resource,
                    "method": method,
                },
            )

        # Check denied URL patterns
        if self._matches_any(resource, self.denied_url_patterns):
            return GuardResult(
                allowed=False,
                reason=f"URL pattern matched deny list: '{resource}'",
                details={
                    "guard": self.name,
                    "resource": resource,
                },
            )

        # Check allowed domains
        if self.allowed_domains and not self._matches_any(hostname, self.allowed_domains):
            return GuardResult(
                allowed=False,
                reason=f"Domain '{hostname}' not in allow list",
                details={
                    "guard": self.name,
                    "resource": resource,
                    "hostname": hostname,
                },
            )

        # Check allowed methods
        if method and self.allowed_methods and not self._matches_any(method, self.allowed_methods):
            return GuardResult(
                allowed=False,
                reason=f"HTTP method '{method}' not in allow list",
                details={
                    "guard": self.name,
                    "resource": resource,
                    "method": method,
                },
            )

        # Check allowed URL patterns (only if set)
        if self.allowed_url_patterns and not self._matches_any(resource, self.allowed_url_patterns):
            return GuardResult(
                allowed=False,
                reason=f"URL not in allow list: '{resource}'",
                details={
                    "guard": self.name,
                    "resource": resource,
                },
            )

        # Fall back to default
        if self.allow_by_default:
            return GuardResult(
                allowed=True,
                reason=f"Request to '{resource}' allowed by default",
                details={"guard": self.name, "resource": resource},
            )
        elif not self.denied_domains and not self.allowed_domains:
            # No restrictions configured
            return GuardResult(
                allowed=True,
                reason=f"No domain restrictions configured for '{resource}'",
                details={"guard": self.name, "resource": resource},
            )
        else:
            # Restrictions exist but no deny was triggered
            return GuardResult(
                allowed=True,
                reason=f"Request to '{resource}' passed all checks",
                details={"guard": self.name, "resource": resource},
            )

    def configure(
        self,
        denied_domains: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None,
        denied_methods: Optional[List[str]] = None,
        allowed_methods: Optional[List[str]] = None,
        denied_url_patterns: Optional[List[str]] = None,
        allowed_url_patterns: Optional[List[str]] = None,
        https_only: Optional[bool] = None,
        block_internal_ips: Optional[bool] = None,
        allow_by_default: Optional[bool] = None,
        **kwargs: Any,
    ) -> None:
        """Configure the network guard.

        Args:
            denied_domains: Domain patterns to deny.
            allowed_domains: Domain patterns to allow.
            denied_methods: HTTP methods to deny.
            allowed_methods: HTTP methods to allow.
            denied_url_patterns: URL patterns to deny.
            allowed_url_patterns: URL patterns to allow.
            https_only: Require HTTPS.
            block_internal_ips: Block internal IP addresses.
            allow_by_default: Default allow behavior.
            **kwargs: Additional configuration.
        """
        if denied_domains is not None:
            self.denied_domains = set(denied_domains)
        if allowed_domains is not None:
            self.allowed_domains = set(allowed_domains)
        if denied_methods is not None:
            self.denied_methods = set(denied_methods)
        if allowed_methods is not None:
            self.allowed_methods = set(allowed_methods)
        if denied_url_patterns is not None:
            self.denied_url_patterns = set(denied_url_patterns)
        if allowed_url_patterns is not None:
            self.allowed_url_patterns = set(allowed_url_patterns)
        if https_only is not None:
            self.https_only = https_only
        if block_internal_ips is not None:
            self.block_internal_ips = block_internal_ips
        if allow_by_default is not None:
            self.allow_by_default = allow_by_default
        super().configure(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this guard to a dictionary.

        Returns:
            A dictionary representation of this guard.
        """
        result = super().to_dict()
        result.update({
            "denied_domains": sorted(self.denied_domains),
            "allowed_domains": sorted(self.allowed_domains),
            "denied_methods": sorted(self.denied_methods),
            "allowed_methods": sorted(self.allowed_methods),
            "denied_url_patterns": sorted(self.denied_url_patterns),
            "allowed_url_patterns": sorted(self.allowed_url_patterns),
            "https_only": self.https_only,
            "block_internal_ips": self.block_internal_ips,
            "allow_by_default": self.allow_by_default,
        })
        return result

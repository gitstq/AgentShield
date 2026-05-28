"""Utility functions for AgentShield.

Provides helper functions for common operations such as path matching,
domain parsing, and pattern validation.
"""

import fnmatch
import os
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse


def match_glob(value: str, pattern: str) -> bool:
    """Check if a value matches a glob pattern.

    Args:
        value: The string to check.
        pattern: The glob pattern.

    Returns:
        True if the value matches the pattern.
    """
    return fnmatch.fnmatch(value, pattern)


def match_regex(value: str, pattern: str) -> bool:
    """Check if a value matches a regular expression pattern.

    Args:
        value: The string to check.
        pattern: The regular expression pattern.

    Returns:
        True if the value matches the pattern.
    """
    try:
        return bool(re.search(pattern, value))
    except re.error:
        return False


def is_private_ip(hostname: str) -> bool:
    """Check if a hostname is a private/internal IP address.

    Args:
        hostname: The hostname or IP address to check.

    Returns:
        True if the hostname is a private IP address.
    """
    private_patterns = [
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[01])\.",
        r"^192\.168\.",
        r"^127\.",
        r"^0\.",
        r"^169\.254\.",
        r"^::1$",
        r"^fe80:",
        r"^fc",
        r"^fd",
    ]
    for pattern in private_patterns:
        if re.match(pattern, hostname):
            return True
    return False


def parse_domain(url: str) -> Optional[str]:
    """Extract the domain from a URL string.

    Args:
        url: The URL to parse.

    Returns:
        The domain name, or None if parsing fails.
    """
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except (ValueError, TypeError):
        return None


def normalize_path(path: str) -> str:
    """Normalize a file path to its absolute form.

    Expands user home directory (~) and resolves relative paths.

    Args:
        path: The file path to normalize.

    Returns:
        The normalized absolute path.
    """
    return os.path.abspath(os.path.expanduser(path))


def validate_pattern(pattern: str, pattern_type: str = "glob") -> bool:
    """Validate a pattern string.

    Args:
        pattern: The pattern to validate.
        pattern_type: Type of pattern ("glob" or "regex").

    Returns:
        True if the pattern is valid.

    Raises:
        ValueError: If the pattern type is unknown.
    """
    if pattern_type == "glob":
        try:
            fnmatch.translate(pattern)
            return True
        except (TypeError, re.error):
            return False
    elif pattern_type == "regex":
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False
    else:
        raise ValueError(f"Unknown pattern type: {pattern_type}")


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate a string to a maximum length.

    Args:
        s: The string to truncate.
        max_length: Maximum length of the result.
        suffix: Suffix to add when truncating.

    Returns:
        The truncated string.
    """
    if len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix


def safe_json_serialize(obj: Any) -> Any:
    """Safely serialize an object for JSON output.

    Handles common non-serializable types like datetime, set, etc.

    Args:
        obj: The object to serialize.

    Returns:
        A JSON-serializable representation.
    """
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (list, tuple)):
        return [safe_json_serialize(item) for item in obj]
    if isinstance(obj, dict):
        return {str(k): safe_json_serialize(v) for k, v in obj.items()}
    if isinstance(obj, set):
        return [safe_json_serialize(item) for item in obj]
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode("utf-8", errors="replace")
    return str(obj)

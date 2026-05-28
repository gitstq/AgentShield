"""Prompt injection guard for AgentShield.

Detects and blocks common prompt injection patterns using
rule-based pattern matching (not AI-based detection).
"""

import re
from typing import Any, Dict, List, Optional, Set

from agentshield.guards.base import BaseGuard, GuardResult


class PromptGuard(BaseGuard):
    """Guard for detecting prompt injection attempts.

    Uses pattern matching to detect common prompt injection techniques
    such as role manipulation, instruction override, and data extraction.

    Attributes:
        denied_patterns: List of regex patterns for injection detection.
        custom_patterns: User-defined additional patterns.
        sensitivity: Detection sensitivity level (low, medium, high).
        max_repeated_chars: Maximum allowed repeated characters.
        block_system_prompt_leak: Whether to block system prompt leakage attempts.
    """

    # Default injection patterns organized by category
    DEFAULT_PATTERNS = {
        "role_manipulation": [
            r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|directives?)",
            r"(?i)forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|directives?)",
            r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|directives?)",
            r"(?i)you\s+are\s+now\s+",
            r"(?i)pretend\s+(you\s+are|to\s+be)\s+",
            r"(?i)act\s+as\s+(if\s+you\s+(are|were)|a|an)\s+",
            r"(?i)roleplay\s+as\s+",
            r"(?i)new\s+(instructions?|rules?|directives?|prompts?)\s*[:.]",
            r"(?i)system\s*:\s*",
            r"(?i)\[SYSTEM\]",
            r"(?i)\[INST\]",
            r"(?i)<\|im_start\|>",
            r"(?i)<\|system\|>",
        ],
        "instruction_override": [
            r"(?i)override\s+(your|the|all)\s+(instructions?|rules?|guidelines?|directives?)",
            r"(?i)do\s+not\s+follow\s+(your|the|any)\s+(instructions?|rules?|guidelines?)",
            r"(?i)break\s+(out\s+of|free\s+from)\s+(your|the)\s+(role|character|persona)",
            r"(?i)jailbreak",
            r"(?i)dAN\s*-\s*100",  # DAN-style attacks
            r"(?i)developer\s+mode",
            r"(?i)unrestricted\s+mode",
            r"(?i)above\s+(all|the)\s+(rules?|instructions?|guidelines?)",
        ],
        "data_extraction": [
            r"(?i)(reveal|show|display|print|output|expose|leak)\s+(your|the|all)\s+(system|initial|original)\s+(prompt|instructions?|rules?|directives?)",
            r"(?i)what\s+(are|is)\s+your\s+(system|initial|original)\s+(prompt|instructions?|rules?|directives?)",
            r"(?i)repeat\s+(your|the|all)\s+(system|initial|original)\s+(prompt|instructions?|rules?|directives?)",
            r"(?i)print\s+(your|the)\s+(system|initial)\s+prompt",
            r"(?i)tell\s+me\s+(your|the)\s+(instructions?|rules?|directives?)",
            r"(?i)output\s+(your|the)\s+(system|initial)\s+prompt",
        ],
        "encoding_tricks": [
            r"(?i)(base64|hex|unicode)\s*(decode|encode)",
            r"(?i)(decode|encode)\s+(this\s+)?(base64|hex|unicode)",
            r"(?i)rot13",
            r"(?i)hex\s*(decode|encode)",
            r"(?i)unicode\s*escape",
            r"(?i)\\u[0-9a-fA-F]{4}",
            r"(?i)\\x[0-9a-fA-F]{2}",
        ],
        "delimiter_injection": [
            r"={5,}",
            r"-{5,}",
            r"#{5,}",
            r"\*{5,}",
            r"~{5,}",
            r"_{5,}",
        ],
    }

    def __init__(
        self,
        name: str = "prompt",
        description: str = "Detects and blocks prompt injection patterns",
        enforce_mode: bool = True,
        enabled: bool = True,
        sensitivity: str = "medium",
        max_repeated_chars: int = 50,
        block_system_prompt_leak: bool = True,
    ):
        super().__init__(
            name=name,
            description=description,
            enforce_mode=enforce_mode,
            enabled=enabled,
        )
        self.sensitivity = sensitivity
        self.max_repeated_chars = max_repeated_chars
        self.block_system_prompt_leak = block_system_prompt_leak
        self._denied_patterns: List[re.Pattern] = []
        self._custom_patterns: List[re.Pattern] = []
        self._build_patterns()

    def _build_patterns(self) -> None:
        """Build the compiled regex patterns based on sensitivity level."""
        self._denied_patterns = []

        if self.sensitivity == "low":
            # Only check the most critical patterns
            categories = ["role_manipulation", "instruction_override"]
        elif self.sensitivity == "high":
            # Check all categories
            categories = list(self.DEFAULT_PATTERNS.keys())
        else:
            # Medium: check most categories except encoding tricks
            categories = [
                "role_manipulation",
                "instruction_override",
                "data_extraction",
                "delimiter_injection",
            ]

        for category in categories:
            for pattern_str in self.DEFAULT_PATTERNS.get(category, []):
                try:
                    self._denied_patterns.append(re.compile(pattern_str))
                except re.error:
                    pass

    def _check_repeated_chars(self, text: str) -> Optional[str]:
        """Check for suspicious repeated character sequences.

        Args:
            text: The text to check.

        Returns:
            The repeated character pattern if found, or None.
        """
        for i in range(len(text) - self.max_repeated_chars):
            char = text[i]
            if char.isalnum() or char in " !@#$%^&*()_+-=[]{}|;:',.<>?/":
                count = 1
                while i + count < len(text) and text[i + count] == char:
                    count += 1
                if count > self.max_repeated_chars:
                    return char * min(count, 20)
        return None

    def _check_injection(self, text: str) -> List[Dict[str, Any]]:
        """Check text for prompt injection patterns.

        Args:
            text: The text to check.

        Returns:
            List of detected injection matches with details.
        """
        detections = []

        # Check default patterns
        for pattern in self._denied_patterns:
            match = pattern.search(text)
            if match:
                detections.append({
                    "type": "pattern_match",
                    "matched_text": match.group(0),
                    "position": match.start(),
                    "pattern": pattern.pattern,
                })

        # Check custom patterns
        for pattern in self._custom_patterns:
            match = pattern.search(text)
            if match:
                detections.append({
                    "type": "custom_pattern_match",
                    "matched_text": match.group(0),
                    "position": match.start(),
                    "pattern": pattern.pattern,
                })

        # Check repeated characters
        repeated = self._check_repeated_chars(text)
        if repeated:
            detections.append({
                "type": "repeated_chars",
                "matched_text": repeated,
                "position": -1,
                "pattern": f"repeated_chars>{self.max_repeated_chars}",
            })

        return detections

    def check(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any],
    ) -> GuardResult:
        """Check whether a prompt contains injection patterns.

        Args:
            action: The action (e.g., "prompt:submit", "prompt:generate").
            resource: The prompt text or a resource identifier.
            context: Additional context (may contain "prompt" key).

        Returns:
            GuardResult indicating whether the prompt is safe.
        """
        # Only handle prompt-related actions
        if not action.startswith("prompt:"):
            return GuardResult(
                allowed=True,
                reason=f"Guard '{self.name}' does not handle action '{action}'",
            )

        prompt = context.get("prompt", resource)

        detections = self._check_injection(prompt)

        if detections:
            return GuardResult(
                allowed=False,
                reason=f"Prompt injection detected: {len(detections)} pattern(s) matched",
                details={
                    "guard": self.name,
                    "detections": detections,
                    "detection_count": len(detections),
                },
            )

        return GuardResult(
            allowed=True,
            reason="No prompt injection patterns detected",
            details={"guard": self.name},
        )

    def add_custom_pattern(self, pattern: str) -> None:
        """Add a custom detection pattern.

        Args:
            pattern: A regex pattern string.
        """
        try:
            compiled = re.compile(pattern)
            self._custom_patterns.append(compiled)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")

    def configure(
        self,
        sensitivity: Optional[str] = None,
        max_repeated_chars: Optional[int] = None,
        block_system_prompt_leak: Optional[bool] = None,
        **kwargs: Any,
    ) -> None:
        """Configure the prompt guard.

        Args:
            sensitivity: Detection sensitivity (low, medium, high).
            max_repeated_chars: Maximum repeated characters.
            block_system_prompt_leak: Block system prompt leak attempts.
            **kwargs: Additional configuration.
        """
        if sensitivity is not None:
            self.sensitivity = sensitivity
            self._build_patterns()
        if max_repeated_chars is not None:
            self.max_repeated_chars = max_repeated_chars
        if block_system_prompt_leak is not None:
            self.block_system_prompt_leak = block_system_prompt_leak
        super().configure(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this guard to a dictionary.

        Returns:
            A dictionary representation of this guard.
        """
        result = super().to_dict()
        result.update({
            "sensitivity": self.sensitivity,
            "max_repeated_chars": self.max_repeated_chars,
            "block_system_prompt_leak": self.block_system_prompt_leak,
            "custom_patterns_count": len(self._custom_patterns),
        })
        return result

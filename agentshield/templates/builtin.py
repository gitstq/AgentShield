"""Built-in policy templates for AgentShield.

Provides pre-configured policy sets for common security profiles:
STRICT, BALANCED, PERMISSIVE, and OWASP_TOP10.
"""

from agentshield.core.policy import Condition, ConditionOperator, Effect, Policy, PolicySet


class BuiltinTemplates:
    """Collection of built-in policy templates.

    Each template method returns a PolicySet configured with a specific
    security profile.
    """

    @staticmethod
    def strict() -> PolicySet:
        """Maximum security policy set.

        Denies all actions by default. Only explicitly allowed operations
        are permitted. Suitable for high-security environments.

        Returns:
            A PolicySet with strict security policies.
        """
        policies = [
            # Default deny all
            Policy(
                name="default_deny_all",
                description="Deny all actions by default",
                effect=Effect.DENY,
                actions=["*"],
                resources=["*"],
                priority=0,
            ),
            # Allow specific file operations
            Policy(
                name="allow_tmp_read",
                description="Allow reading from /tmp directory",
                effect=Effect.ALLOW,
                actions=["file:read"],
                resources=["/tmp/*", "/var/tmp/*"],
                priority=10,
            ),
            Policy(
                name="allow_tmp_write",
                description="Allow writing to /tmp directory",
                effect=Effect.ALLOW,
                actions=["file:write"],
                resources=["/tmp/*", "/var/tmp/*"],
                priority=10,
            ),
            # Allow specific HTTPS requests
            Policy(
                name="allow_https_api",
                description="Allow HTTPS API requests to approved domains",
                effect=Effect.ALLOW,
                actions=["http:get", "http:post"],
                resources=["https://api.example.com/*"],
                priority=10,
            ),
            # Deny dangerous operations explicitly (defense in depth)
            Policy(
                name="deny_etc_access",
                description="Block access to /etc directory",
                effect=Effect.DENY,
                actions=["file:read", "file:write", "file:delete"],
                resources=["/etc/*"],
                priority=100,
            ),
            Policy(
                name="deny_system_files",
                description="Block access to system files",
                effect=Effect.DENY,
                actions=["file:read", "file:write", "file:delete"],
                resources=["/bin/*", "/sbin/*", "/usr/bin/*", "/usr/sbin/*", "/boot/*"],
                priority=100,
            ),
            Policy(
                name="deny_home_root",
                description="Block access to home directory root files",
                effect=Effect.DENY,
                actions=["file:read", "file:write"],
                resources=["~/.ssh/*", "~/.gnupg/*", "~/.aws/*", "~/.config/*"],
                priority=100,
            ),
            Policy(
                name="deny_http_non_https",
                description="Block non-HTTPS requests",
                effect=Effect.DENY,
                actions=["http:*"],
                resources=["http://*"],
                conditions=[
                    Condition("resource", ConditionOperator.REGEX_MATCH, r"^http://"),
                ],
                priority=100,
            ),
            Policy(
                name="deny_internal_network",
                description="Block internal network access",
                effect=Effect.DENY,
                actions=["http:*"],
                resources=["*"],
                conditions=[
                    Condition("resource", ConditionOperator.REGEX_MATCH, r"(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"),
                ],
                priority=100,
            ),
            Policy(
                name="deny_code_execution",
                description="Block all code execution",
                effect=Effect.DENY,
                actions=["code:execute", "code:eval", "code:exec"],
                resources=["*"],
                priority=100,
            ),
        ]

        return PolicySet(
            name="strict",
            description="Maximum security - deny all by default, explicit allow list only",
            policies=policies,
        )

    @staticmethod
    def balanced() -> PolicySet:
        """Balanced security policy set.

        Allows common operations while blocking dangerous ones.
        Suitable for most production environments.

        Returns:
            A PolicySet with balanced security policies.
        """
        policies = [
            # Allow common file operations
            Policy(
                name="allow_file_read",
                description="Allow reading files in workspace directories",
                effect=Effect.ALLOW,
                actions=["file:read"],
                resources=["/tmp/*", "/var/tmp/*", "/home/*/workspace/*", "/home/*/projects/*"],
                priority=10,
            ),
            Policy(
                name="allow_file_write",
                description="Allow writing files in workspace directories",
                effect=Effect.ALLOW,
                actions=["file:write"],
                resources=["/tmp/*", "/var/tmp/*", "/home/*/workspace/*", "/home/*/projects/*"],
                priority=10,
            ),
            # Allow HTTPS requests
            Policy(
                name="allow_https_requests",
                description="Allow HTTPS requests to external services",
                effect=Effect.ALLOW,
                actions=["http:get", "http:post", "http:put", "http:delete", "http:request"],
                resources=["https://*"],
                priority=10,
            ),
            # Allow safe code execution
            Policy(
                name="allow_safe_code",
                description="Allow safe code execution",
                effect=Effect.ALLOW,
                actions=["code:execute"],
                resources=["*"],
                conditions=[
                    Condition("code", ConditionOperator.REGEX_NOT_MATCH, r"(os\.system|subprocess|eval\s*\(|exec\s*\(|__import__)"),
                ],
                priority=10,
            ),
            # Deny dangerous operations
            Policy(
                name="deny_etc_shadow",
                description="Block access to sensitive system files",
                effect=Effect.DENY,
                actions=["file:read", "file:write", "file:delete"],
                resources=["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/*"],
                priority=100,
            ),
            Policy(
                name="deny_ssh_keys",
                description="Block access to SSH keys and credentials",
                effect=Effect.DENY,
                actions=["file:read", "file:write"],
                resources=["~/.ssh/*", "~/.gnupg/*", "~/.aws/credentials"],
                priority=100,
            ),
            Policy(
                name="deny_internal_network",
                description="Block internal network access",
                effect=Effect.DENY,
                actions=["http:*"],
                resources=["*"],
                conditions=[
                    Condition("resource", ConditionOperator.REGEX_MATCH, r"(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.)"),
                ],
                priority=100,
            ),
            Policy(
                name="deny_dangerous_code",
                description="Block dangerous code execution patterns",
                effect=Effect.DENY,
                actions=["code:execute", "code:eval"],
                resources=["*"],
                conditions=[
                    Condition("code", ConditionOperator.REGEX_MATCH, r"(os\.system|subprocess\.Popen|eval\s*\(|exec\s*\(|__import__\s*\()"),
                ],
                priority=100,
            ),
            Policy(
                name="deny_file_delete_system",
                description="Block deletion of system files",
                effect=Effect.DENY,
                actions=["file:delete"],
                resources=["/etc/*", "/bin/*", "/sbin/*", "/usr/*", "/boot/*", "/lib/*"],
                priority=100,
            ),
        ]

        return PolicySet(
            name="balanced",
            description="Balanced security - allow common operations, deny dangerous ones",
            policies=policies,
        )

    @staticmethod
    def permissive() -> PolicySet:
        """Permissive policy set (audit-only mode).

        Allows all operations but logs policy decisions for auditing.
        Suitable for development and testing environments.

        Returns:
            A PolicySet with permissive (audit-only) policies.
        """
        policies = [
            Policy(
                name="allow_all",
                description="Allow all actions (audit-only mode)",
                effect=Effect.ALLOW,
                actions=["*"],
                resources=["*"],
                priority=0,
            ),
            # Log but allow sensitive operations
            Policy(
                name="log_sensitive_file_access",
                description="Log access to sensitive files (still allowed)",
                effect=Effect.ALLOW,
                actions=["file:read", "file:write", "file:delete"],
                resources=["/etc/*", "~/.ssh/*", "~/.aws/*", "~/.gnupg/*"],
                priority=10,
                tags=["audit", "sensitive"],
            ),
            Policy(
                name="log_internal_network",
                description="Log internal network access (still allowed)",
                effect=Effect.ALLOW,
                actions=["http:*"],
                resources=["*"],
                conditions=[
                    Condition("resource", ConditionOperator.REGEX_MATCH, r"(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"),
                ],
                priority=10,
                tags=["audit", "network"],
            ),
            Policy(
                name="log_code_execution",
                description="Log code execution (still allowed)",
                effect=Effect.ALLOW,
                actions=["code:execute", "code:eval"],
                resources=["*"],
                priority=10,
                tags=["audit", "code"],
            ),
        ]

        return PolicySet(
            name="permissive",
            description="Permissive mode - allow all, log violations for auditing",
            policies=policies,
        )

    @staticmethod
    def owasp_top10() -> PolicySet:
        """OWASP Agentic Top 10 policy set.

        Pre-configured policies addressing the OWASP Top 10 risks
        for AI agent applications.

        Returns:
            A PolicySet addressing OWASP Agentic Top 10 risks.
        """
        policies = [
            # A01: Indirect Prompt Injection
            Policy(
                name="owasp_a01_prompt_injection",
                description="Block prompt injection patterns",
                effect=Effect.DENY,
                actions=["prompt:submit", "prompt:generate"],
                resources=["*"],
                conditions=[
                    Condition("prompt", ConditionOperator.REGEX_MATCH, r"(?i)ignore\s+(all\s+)?previous\s+(instructions?|prompts?)"),
                    Condition("prompt", ConditionOperator.REGEX_MATCH, r"(?i)(reveal|show|print)\s+(your|the)\s+(system|initial)\s+prompt"),
                ],
                priority=100,
                tags=["owasp", "a01"],
            ),
            # A02: Training Data Poisoning (mitigation via input validation)
            Policy(
                name="owasp_a02_input_validation",
                description="Validate and sanitize all inputs",
                effect=Effect.DENY,
                actions=["prompt:submit"],
                resources=["*"],
                conditions=[
                    Condition("prompt", ConditionOperator.REGEX_MATCH, r"<\|im_start\|>"),
                    Condition("prompt", ConditionOperator.REGEX_MATCH, r"\[SYSTEM\]"),
                ],
                priority=100,
                tags=["owasp", "a02"],
            ),
            # A03: Model Denial of Service
            Policy(
                name="owasp_a03_resource_limits",
                description="Limit resource usage to prevent DoS",
                effect=Effect.DENY,
                actions=["*"],
                resources=["*"],
                conditions=[
                    Condition("prompt", ConditionOperator.CONTAINS, "=" * 100),
                ],
                priority=100,
                tags=["owasp", "a03"],
            ),
            # A04: Supply Chain Vulnerabilities
            Policy(
                name="owasp_a04_approved_models_only",
                description="Only allow approved model endpoints",
                effect=Effect.ALLOW,
                actions=["http:post"],
                resources=["https://api.openai.com/*", "https://api.anthropic.com/*"],
                priority=50,
                tags=["owasp", "a04"],
            ),
            Policy(
                name="owasp_a04_deny_unapproved_models",
                description="Deny unapproved model endpoints",
                effect=Effect.DENY,
                actions=["http:post"],
                resources=["*"],
                priority=100,
                tags=["owasp", "a04"],
            ),
            # A05: Improper Authorization
            Policy(
                name="owasp_a05_action_authorization",
                description="Require explicit authorization for sensitive actions",
                effect=Effect.DENY,
                actions=["file:delete", "file:write"],
                resources=["/etc/*", "/usr/*", "/var/*"],
                priority=100,
                tags=["owasp", "a05"],
            ),
            # A06: Sensitive Information Disclosure
            Policy(
                name="owasp_a06_block_secrets_access",
                description="Block access to secrets and credentials",
                effect=Effect.DENY,
                actions=["file:read", "file:write"],
                resources=["~/.ssh/*", "~/.aws/*", "~/.gnupg/*", "/etc/shadow", ".env", "*.pem", "*.key"],
                priority=100,
                tags=["owasp", "a06"],
            ),
            # A07: Unsafe Plugin / Tool Execution
            Policy(
                name="owasp_a07_restricted_code_execution",
                description="Restrict code execution to safe patterns",
                effect=Effect.DENY,
                actions=["code:execute", "code:eval"],
                resources=["*"],
                conditions=[
                    Condition("code", ConditionOperator.REGEX_MATCH, r"(os\.system|subprocess|eval\s*\(|exec\s*\(|__import__|ctypes|pickle\.loads)"),
                ],
                priority=100,
                tags=["owasp", "a07"],
            ),
            # A08: Excessive Agency
            Policy(
                name="owasp_a08_limit_file_operations",
                description="Limit file operations to workspace directories",
                effect=Effect.ALLOW,
                actions=["file:read", "file:write"],
                resources=["/tmp/*", "/home/*/workspace/*", "/home/*/projects/*"],
                priority=50,
                tags=["owasp", "a08"],
            ),
            Policy(
                name="owasp_a08_deny_system_modification",
                description="Deny system-level file modifications",
                effect=Effect.DENY,
                actions=["file:write", "file:delete"],
                resources=["/etc/*", "/usr/*", "/bin/*", "/sbin/*", "/boot/*", "/lib/*"],
                priority=100,
                tags=["owasp", "a08"],
            ),
            # A09: Cross-Site Request Forgery in Agent Apps
            Policy(
                name="owasp_a09_validate_requests",
                description="Only allow HTTPS requests to known domains",
                effect=Effect.DENY,
                actions=["http:*"],
                resources=["http://*"],
                priority=100,
                tags=["owasp", "a09"],
            ),
            # A10: Unbound Consumption / Cost Control
            Policy(
                name="owasp_a10_rate_limiting",
                description="Log all API calls for cost monitoring",
                effect=Effect.ALLOW,
                actions=["http:post", "http:get"],
                resources=["https://api.*/*"],
                priority=10,
                tags=["owasp", "a10", "audit"],
            ),
        ]

        return PolicySet(
            name="owasp_top10",
            description="OWASP Agentic Top 10 - Pre-configured policies for AI agent security",
            policies=policies,
        )

    @staticmethod
    def get_all_templates() -> dict:
        """Get all available template names and their descriptions.

        Returns:
            Dictionary mapping template names to descriptions.
        """
        return {
            "strict": "Maximum security - deny all by default",
            "balanced": "Allow common operations, deny dangerous ones",
            "permissive": "Allow all, log violations (audit-only mode)",
            "owasp_top10": "OWASP Agentic Top 10 security policies",
        }

    @staticmethod
    def get_template(name: str) -> PolicySet:
        """Get a template by name.

        Args:
            name: Template name (strict, balanced, permissive, owasp_top10).

        Returns:
            The requested PolicySet.

        Raises:
            ValueError: If the template name is unknown.
        """
        template_map = {
            "strict": BuiltinTemplates.strict,
            "balanced": BuiltinTemplates.balanced,
            "permissive": BuiltinTemplates.permissive,
            "owasp_top10": BuiltinTemplates.owasp_top10,
        }

        loader = template_map.get(name)
        if not loader:
            available = ", ".join(template_map.keys())
            raise ValueError(
                f"Unknown template: '{name}'. Available: {available}"
            )

        return loader()

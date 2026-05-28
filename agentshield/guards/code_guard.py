"""Code execution guard for AgentShield.

Controls code execution by blocking dangerous functions, modules, and patterns.
Supports allow/deny lists for modules and functions.
"""

import ast
import re
from typing import Any, Dict, List, Optional, Set

from agentshield.guards.base import BaseGuard, GuardResult


class CodeGuard(BaseGuard):
    """Guard for controlling code execution.

    Blocks dangerous functions (e.g., os.system, eval, exec, __import__)
    and restricts module usage based on allow/deny lists.

    Attributes:
        denied_functions: Set of function names that are denied.
        allowed_functions: Set of function names that are allowed.
        denied_modules: Set of module names that are denied.
        allowed_modules: Set of module names that are allowed.
        denied_patterns: Set of regex patterns that match dangerous code.
        allow_by_default: If True, allow all code not explicitly denied.
        max_code_length: Maximum allowed code length in characters.
    """

    # Default dangerous functions
    DEFAULT_DENIED_FUNCTIONS = {
        "os.system",
        "os.popen",
        "os.spawn",
        "os.exec",
        "os.execvp",
        "os.execve",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.run",
        "subprocess.check_output",
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "input",
        "breakpoint",
        "globals",
        "locals",
        "getattr",
        "setattr",
        "delattr",
        "ctypes",
        "pickle.loads",
        "pickle.load",
        "marshal.loads",
        "shutil.rmtree",
        "os.remove",
        "os.unlink",
        "os.rename",
        "os.mkdir",
        "os.makedirs",
        "tempfile.mktemp",
    }

    # Default dangerous patterns
    DEFAULT_DENIED_PATTERNS = [
        r"__\w+__",           # Dunder attributes
        r"\bos\.",            # Direct os module access
        r"\bsubprocess\.",    # Direct subprocess access
        r"\bsys\.",           # Direct sys module access
        r"\bimport\s+os\b",   # Import os
        r"\bfrom\s+os\s+import\b",  # From os import
        r"\bimport\s+subprocess\b",
        r"\bfrom\s+subprocess\s+import\b",
        r"\bimport\s+sys\b",
        r"\bfrom\s+sys\s+import\b",
        r"\bexec\s*\(",       # exec() call
        r"\beval\s*\(",       # eval() call
        r"\bcompile\s*\(",    # compile() call
        r"\bglobals\s*\(",    # globals() call
        r"\blocals\s*\(",     # locals() call
    ]

    def __init__(
        self,
        name: str = "code",
        description: str = "Controls code execution",
        enforce_mode: bool = True,
        enabled: bool = True,
        denied_functions: Optional[List[str]] = None,
        allowed_functions: Optional[List[str]] = None,
        denied_modules: Optional[List[str]] = None,
        allowed_modules: Optional[List[str]] = None,
        denied_patterns: Optional[List[str]] = None,
        allow_by_default: bool = False,
        max_code_length: int = 100000,
    ):
        super().__init__(
            name=name,
            description=description,
            enforce_mode=enforce_mode,
            enabled=enabled,
        )
        self.denied_functions: Set[str] = set(
            denied_functions or self.DEFAULT_DENIED_FUNCTIONS
        )
        self.allowed_functions: Set[str] = set(allowed_functions or [])
        self.denied_modules: Set[str] = set(denied_modules or [])
        self.allowed_modules: Set[str] = set(allowed_modules or [])
        self._use_default_patterns = denied_patterns is None
        self.denied_patterns: List[re.Pattern] = [
            re.compile(p) for p in (denied_patterns if denied_patterns is not None else self.DEFAULT_DENIED_PATTERNS)
        ]
        self.allow_by_default = allow_by_default
        self.max_code_length = max_code_length

    def _check_dangerous_functions(self, code: str) -> Optional[str]:
        """Check code for dangerous function calls.

        Args:
            code: The source code to check.

        Returns:
            Name of the first dangerous function found, or None.
        """
        for func_name in self.denied_functions:
            # Check for function call pattern: func_name(
            pattern = re.compile(r"\b" + re.escape(func_name) + r"\s*\(")
            if pattern.search(code):
                return func_name
        return None

    def _check_dangerous_patterns(self, code: str) -> Optional[str]:
        """Check code for dangerous patterns.

        Args:
            code: The source code to check.

        Returns:
            The first matching dangerous pattern string, or None.
        """
        for pattern in self.denied_patterns:
            match = pattern.search(code)
            if match:
                return match.group(0)
        return None

    def _check_imports(self, code: str) -> Optional[str]:
        """Check code for denied module imports.

        Args:
            code: The source code to check.

        Returns:
            Name of the first denied module imported, or None.
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return None

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_name = alias.name.split(".")[0]
                    if module_name in self.denied_modules:
                        return module_name
                    if self.allowed_modules and module_name not in self.allowed_modules:
                        return module_name
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module_name = node.module.split(".")[0]
                    if module_name in self.denied_modules:
                        return module_name
                    if self.allowed_modules and module_name not in self.allowed_modules:
                        return module_name

        return None

    def _check_code_length(self, code: str) -> bool:
        """Check if code exceeds the maximum allowed length.

        Args:
            code: The source code to check.

        Returns:
            True if the code is within the length limit.
        """
        return len(code) <= self.max_code_length

    def check(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any],
    ) -> GuardResult:
        """Check whether code execution is allowed.

        Args:
            action: The action (e.g., "code:execute", "code:eval").
            resource: The code string or module name.
            context: Additional context (may contain "code" key).

        Returns:
            GuardResult indicating whether the action is allowed.
        """
        # Only handle code-related actions
        if not action.startswith("code:"):
            return GuardResult(
                allowed=True,
                reason=f"Guard '{self.name}' does not handle action '{action}'",
            )

        code = context.get("code", resource)

        # Check code length
        if not self._check_code_length(code):
            return GuardResult(
                allowed=False,
                reason=f"Code exceeds maximum length of {self.max_code_length} characters",
                details={
                    "guard": self.name,
                    "code_length": len(code),
                    "max_length": self.max_code_length,
                },
            )

        # Check for denied functions
        dangerous_func = self._check_dangerous_functions(code)
        if dangerous_func:
            return GuardResult(
                allowed=False,
                reason=f"Dangerous function detected: '{dangerous_func}'",
                details={
                    "guard": self.name,
                    "function": dangerous_func,
                },
            )

        # Check for denied patterns
        dangerous_pattern = self._check_dangerous_patterns(code)
        if dangerous_pattern:
            return GuardResult(
                allowed=False,
                reason=f"Dangerous pattern detected: '{dangerous_pattern}'",
                details={
                    "guard": self.name,
                    "pattern": dangerous_pattern,
                },
            )

        # Check for denied imports
        denied_import = self._check_imports(code)
        if denied_import:
            return GuardResult(
                allowed=False,
                reason=f"Denied module import detected: '{denied_import}'",
                details={
                    "guard": self.name,
                    "module": denied_import,
                },
            )

        return GuardResult(
            allowed=True,
            reason="Code execution check passed",
            details={"guard": self.name},
        )

    def configure(
        self,
        denied_functions: Optional[List[str]] = None,
        allowed_functions: Optional[List[str]] = None,
        denied_modules: Optional[List[str]] = None,
        allowed_modules: Optional[List[str]] = None,
        denied_patterns: Optional[List[str]] = None,
        allow_by_default: Optional[bool] = None,
        max_code_length: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        """Configure the code guard.

        Args:
            denied_functions: Function names to deny.
            allowed_functions: Function names to allow.
            denied_modules: Module names to deny.
            allowed_modules: Module names to allow.
            denied_patterns: Regex patterns to deny.
            allow_by_default: Default allow behavior.
            max_code_length: Maximum code length.
            **kwargs: Additional configuration.
        """
        if denied_functions is not None:
            self.denied_functions = set(denied_functions)
        if allowed_functions is not None:
            self.allowed_functions = set(allowed_functions)
        if denied_modules is not None:
            self.denied_modules = set(denied_modules)
        if allowed_modules is not None:
            self.allowed_modules = set(allowed_modules)
        if denied_patterns is not None:
            self.denied_patterns = [re.compile(p) for p in denied_patterns]
        if allow_by_default is not None:
            self.allow_by_default = allow_by_default
        if max_code_length is not None:
            self.max_code_length = max_code_length
        super().configure(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this guard to a dictionary.

        Returns:
            A dictionary representation of this guard.
        """
        result = super().to_dict()
        result.update({
            "denied_functions": sorted(self.denied_functions),
            "allowed_functions": sorted(self.allowed_functions),
            "denied_modules": sorted(self.denied_modules),
            "allowed_modules": sorted(self.allowed_modules),
            "allow_by_default": self.allow_by_default,
            "max_code_length": self.max_code_length,
        })
        return result

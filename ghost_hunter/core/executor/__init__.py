"""
Ghost Hunter Executor - Moteurs d'exécution des tests de sécurité.

Modules:
- tool_wrapper: Interface abstraite pour les wrappers d'outils
- nuclei_runner: Intégration Nuclei (scanner de templates)
- http_runner: Exécuteur HTTP custom (httpx-based)
- multi_round_runner: Exécuteur multi-rounds avec apprentissage
"""

from .tool_wrapper import (
    ToolConfig,
    ExecutionContext,
    ToolWrapper,
    ToolRegistry,
    ShellTool,
    get_registry,
    register_tool,
)
from .nuclei_runner import NucleiRunner, register_nuclei
from .http_runner import CustomHTTPRunner
from .multi_round_runner import MultiRoundRunner, MultiRoundResult
from .constants import ERROR_PATTERNS, _safe_get_payload_value

__all__ = [
    "ToolConfig",
    "ExecutionContext",
    "ToolWrapper",
    "ToolRegistry",
    "ShellTool",
    "get_registry",
    "register_tool",
    "NucleiRunner",
    "register_nuclei",
    "CustomHTTPRunner",
    "MultiRoundRunner",
    "MultiRoundResult",
    "ERROR_PATTERNS",
    "_safe_get_payload_value",
]
"""
Ghost-Hunter Tool Wrapper
=========================
Interface abstraite pour les wrappers d'outils de sécurité.
"""

import asyncio
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import logging

from ..contracts import ExecutionResult, Finding

logger = logging.getLogger(__name__)


@dataclass
class ToolConfig:
    """Configuration d'un outil externe."""
    name: str
    executable: str
    timeout_seconds: int = 300
    max_concurrent: int = 5
    default_args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)


@dataclass
class ExecutionContext:
    """Contexte d'exécution d'un test."""
    plan: Any  # AttackPlan
    working_dir: Path = field(default_factory=lambda: Path("/tmp/ghost-hunter"))
    output_dir: Path = field(default_factory=lambda: Path("/tmp/ghost-hunter/output"))
    dry_run: bool = False
    verbose: bool = False
    
    def __post_init__(self):
        self.working_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)


class ToolWrapper(ABC):
    """
    Interface abstraite pour wrapper des outils de sécurité.
    
    Chaque outil (Nuclei, ffuf, sqlmap, etc.) hérite de cette classe.
    """
    
    def __init__(self, config: ToolConfig):
        self.config = config
        self.executions: List[ExecutionResult] = []
        self._semaphore = asyncio.Semaphore(config.max_concurrent)
    
    @property
    def is_available(self) -> bool:
        """Vérifie si l'outil est installé et disponible."""
        return shutil.which(self.config.executable) is not None
    
    @property
    def version(self) -> Optional[str]:
        """Récupère la version de l'outil."""
        try:
            result = subprocess.run(
                [self.config.executable, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() or result.stderr.strip()
        except Exception:
            return None
    
    @abstractmethod
    async def execute(self, context: ExecutionContext) -> ExecutionResult:
        """Exécute l'outil avec le contexte donné."""
        pass
    
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse la sortie brute de l'outil."""
        return {"raw": raw_output}
    
    def _create_base_result(self, context: ExecutionContext) -> ExecutionResult:
        """Crée un résultat d'exécution de base."""
        return ExecutionResult(
            tool_used=self.config.name,
            request=context.plan.request if context.plan else None,
            plan=context.plan if context.plan else None,
        )
    
    async def _run_command(
        self,
        args: List[str],
        context: ExecutionContext,
        stdin: Optional[str] = None
    ) -> tuple[int, str, str]:
        """
        Exécute une commande shell de manière asynchrone.
        
        Returns:
            (returncode, stdout, stderr)
        """
        async with self._semaphore:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdin=asyncio.subprocess.PIPE if stdin else None,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(context.working_dir),
                    env={**dict(self.config.env)},
                )
                
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(stdin.encode() if stdin else None),
                    timeout=self.config.timeout_seconds
                )
                
                return proc.returncode, stdout.decode(), stderr.decode()
                
            except asyncio.TimeoutError:
                proc.kill()
                return -1, "", "Timeout exceeded"
            except Exception as e:
                return -1, "", str(e)


class ShellTool(ToolWrapper):
    """
    Outil générique pour exécuter des commandes shell.
    """
    
    def __init__(self, name: str, command: str, **kwargs):
        config = ToolConfig(
            name=name,
            executable=command.split()[0],
            **kwargs
        )
        super().__init__(config)
        self._full_command = command
    
    async def execute(self, context: ExecutionContext) -> ExecutionResult:
        """Exécute la commande shell."""
        result = self._create_base_result(context)
        
        args = self._full_command.split()
        returncode, stdout, stderr = await self._run_command(args, context)
        
        result.success = returncode == 0
        result.raw_response = stdout
        result.error = stderr if returncode != 0 else None
        
        return result


# Registry global des outils
class ToolRegistry:
    """Registre des outils disponibles."""
    
    _instance: Optional['ToolRegistry'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tools: Dict[str, ToolWrapper] = {}
        return cls._instance
    
    def register(self, tool: ToolWrapper):
        """Enregistre un outil."""
        self._tools[tool.config.name] = tool
        logger.info(f"Registered tool: {tool.config.name}")
    
    def get(self, name: str) -> Optional[ToolWrapper]:
        """Récupère un outil par son nom."""
        return self._tools.get(name)
    
    def list_available(self) -> List[str]:
        """Liste les outils disponibles."""
        return [
            name for name, tool in self._tools.items()
            if tool.is_available
        ]
    
    def list_all(self) -> Dict[str, bool]:
        """Liste tous les outils avec leur disponibilité."""
        return {
            name: tool.is_available
            for name, tool in self._tools.items()
        }


def get_registry() -> ToolRegistry:
    """Récupère le registre global des outils."""
    return ToolRegistry()


def register_tool(tool: ToolWrapper):
    """Raccourci pour enregistrer un outil."""
    get_registry().register(tool)

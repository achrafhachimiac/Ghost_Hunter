"""
Nuclei Runner - Wrapper pour l'outil Nuclei de Project Discovery.

Nuclei est un scanner de vulnérabilités rapide basé sur des templates.
Ce wrapper l'intègre dans le pipeline Ghost-Hunter.
"""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from .tool_wrapper import (
    ToolWrapper,
    ToolConfig,
    ExecutionContext,
    register_tool,
)
from ..contracts import (
    ExecutionResult,
    Finding,
    FindingSeverity,
    FindingStatus,
    ResponseSignature,
)
from ..evasion import get_residential_proxy, get_proxy_manager


logger = logging.getLogger(__name__)


# Mapping de sévérité Nuclei → Ghost-Hunter
SEVERITY_MAP = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
    "unknown": FindingSeverity.INFO,
}


class NucleiRunner(ToolWrapper):
    """
    Wrapper pour Nuclei.
    
    Exécute des templates Nuclei ciblés sur les endpoints découverts.
    Supporte:
    - Templates custom générés par l'IA
    - Templates officiels par catégorie
    - Output JSON parsé automatiquement
    """
    
    DEFAULT_CONFIG = ToolConfig(
        name="nuclei",
        executable="nuclei",
        timeout_seconds=600,
        max_concurrent=10,
        default_args=["-json", "-silent", "-no-color"],
    )
    
    def __init__(
        self,
        config: Optional[ToolConfig] = None,
        templates_dir: Optional[Path] = None,
        rate_limit: int = 150,  # requests per second
        use_proxy: bool = True,  # Use residential proxy
    ):
        """
        Args:
            config: Configuration de l'outil (optionnel)
            templates_dir: Dossier des templates custom
            rate_limit: Limite de requêtes par seconde
            use_proxy: Utiliser les proxies résidentiels GonzoProxy
        """
        super().__init__(config or self.DEFAULT_CONFIG)
        self.templates_dir = templates_dir or Path.home() / "nuclei-templates"
        self.rate_limit = rate_limit
        self.use_proxy = use_proxy
        self._proxy_manager = get_proxy_manager() if use_proxy else None
    
    async def execute(self, context: ExecutionContext) -> ExecutionResult:
        """Exécute Nuclei avec le plan d'attaque."""
        result = self._create_base_result(context)
        start_time = datetime.now()
        
        try:
            # Créer le fichier de targets
            target_file = await self._create_target_file(context)
            
            # Construire la commande
            args = self._build_command(context, target_file)
            
            # Exécuter
            returncode, stdout, stderr = await self._run_command(args, context)
            
            # Calculer le temps
            result.execution_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            if returncode == 0 or stdout:  # Nuclei peut retourner 0 même avec findings
                result.success = True
                findings = self._parse_nuclei_output(stdout)
                
                if findings:
                    # Prendre le premier finding comme résultat principal
                    result.finding = findings[0]
                    result.raw_response = stdout
            else:
                result.success = False
                result.error = stderr or f"Nuclei exit code: {returncode}"
            
            # Cleanup
            if target_file.exists():
                target_file.unlink()
                
        except Exception as e:
            result.success = False
            result.error = str(e)
            logger.exception("Nuclei execution failed")
        
        self.executions.append(result)
        return result
    
    async def _create_target_file(self, context: ExecutionContext) -> Path:
        """Crée un fichier temporaire avec les targets."""
        target_file = context.working_dir / "nuclei_targets.txt"
        
        # Récupérer l'URL du plan
        plan = context.plan
        url = plan.request.request.request.request.url
        
        target_file.write_text(url)
        return target_file
    
    def _build_command(
        self,
        context: ExecutionContext,
        target_file: Path
    ) -> List[str]:
        """Construit la commande Nuclei."""
        args = [
            self.config.executable,
            "-l", str(target_file),
            "-json",
            "-silent",
            "-no-color",
            "-rate-limit", str(self.rate_limit),
        ]
        
        # Ajouter les templates spécifiques si disponibles
        plan = context.plan
        vuln_class = plan.vuln_class.lower()
        
        # Mapper les classes de vuln aux tags Nuclei
        tag_mapping = {
            "idor": ["idor", "auth-bypass"],
            "sqli": ["sqli", "sql-injection"],
            "xss": ["xss"],
            "ssrf": ["ssrf"],
            "lfi": ["lfi", "file-inclusion"],
            "rce": ["rce", "command-injection"],
            "cmdi": ["rce", "command-injection"],
            "xxe": ["xxe"],
            "ssti": ["ssti"],
        }
        
        tags = tag_mapping.get(vuln_class, [vuln_class])
        if tags:
            args.extend(["-tags", ",".join(tags)])
        
        # Timeout
        args.extend(["-timeout", "10"])
        
        # Proxy résidentiel GonzoProxy
        if self.use_proxy and self._proxy_manager and self._proxy_manager.enabled:
            proxy = self._proxy_manager.get_proxy()
            if proxy:
                args.extend(["-proxy", proxy.url])
                logger.info(f"🌐 Nuclei using residential proxy: {proxy.hostname}:{proxy.port}")
        
        # Output
        output_file = context.output_dir / "nuclei_results.json"
        args.extend(["-o", str(output_file)])
        
        return args
    
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse la sortie JSON de Nuclei."""
        findings = []
        
        for line in raw_output.strip().split('\n'):
            if not line:
                continue
            try:
                finding = json.loads(line)
                findings.append(finding)
            except json.JSONDecodeError:
                continue
        
        return {"findings": findings, "count": len(findings)}
    
    def _parse_nuclei_output(self, raw_output: str) -> List[Finding]:
        """Parse et convertit les findings Nuclei en Finding objects."""
        findings = []
        
        for line in raw_output.strip().split('\n'):
            if not line:
                continue
                
            try:
                data = json.loads(line)
                finding = self._nuclei_to_finding(data)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                continue
        
        return findings
    
    def _nuclei_to_finding(self, nuclei_result: dict) -> Optional[Finding]:
        """Convertit un résultat Nuclei en Finding."""
        try:
            info = nuclei_result.get("info", {})
            
            severity_str = info.get("severity", "info").lower()
            severity = SEVERITY_MAP.get(severity_str, FindingSeverity.INFO)
            
            return Finding(
                endpoint=nuclei_result.get("matched-at", ""),
                method=nuclei_result.get("type", "http").upper(),
                vuln_type=info.get("name", "Unknown"),
                vuln_subtype=nuclei_result.get("template-id", ""),
                severity=severity,
                status=FindingStatus.NEW,
                confidence=self._calculate_confidence(nuclei_result),
                cwe_id=info.get("classification", {}).get("cwe-id", [None])[0] if info.get("classification") else None,
                request_sent=nuclei_result.get("request", ""),
                response_received=nuclei_result.get("response", "")[:5000] if nuclei_result.get("response") else "",
                payload_successful=nuclei_result.get("matched-at", ""),
                ai_analysis=info.get("description", ""),
                impact=info.get("impact", ""),
                reproduction_steps=[
                    f"Run template: {nuclei_result.get('template-id', '')}",
                    f"Target: {nuclei_result.get('host', '')}",
                ],
                tool_used="nuclei",
            )
        except Exception as e:
            logger.error(f"Failed to parse Nuclei result: {e}")
            return None
    
    def _calculate_confidence(self, nuclei_result: dict) -> int:
        """Calcule un score de confiance basé sur le résultat."""
        confidence = 50  # Base
        
        info = nuclei_result.get("info", {})
        
        # Matcher type affects confidence
        matcher_type = nuclei_result.get("matcher-name", "")
        if "status" in matcher_type.lower():
            confidence += 10
        if "word" in matcher_type.lower():
            confidence += 15
        if "regex" in matcher_type.lower():
            confidence += 20
        
        # Severity affects confidence
        severity = info.get("severity", "").lower()
        if severity in ["critical", "high"]:
            confidence += 15
        
        # Has extractor? More confident
        if nuclei_result.get("extracted-results"):
            confidence += 15
        
        return min(confidence, 95)
    
    async def scan_with_template(
        self,
        target: str,
        template_path: Path,
        context: ExecutionContext
    ) -> ExecutionResult:
        """Exécute un scan avec un template spécifique."""
        result = self._create_base_result(context)
        start_time = datetime.now()
        
        args = [
            self.config.executable,
            "-u", target,
            "-t", str(template_path),
            "-json",
            "-silent",
        ]
        
        # Proxy résidentiel
        if self.use_proxy and self._proxy_manager and self._proxy_manager.enabled:
            proxy = self._proxy_manager.get_proxy()
            if proxy:
                args.extend(["-proxy", proxy.url])
                logger.info(f"🌐 Nuclei template scan using proxy: {proxy}")
        
        returncode, stdout, stderr = await self._run_command(args, context)
        
        result.execution_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        if stdout:
            result.success = True
            result.raw_response = stdout
            findings = self._parse_nuclei_output(stdout)
            if findings:
                result.finding = findings[0]
        else:
            result.success = returncode == 0
            result.error = stderr if returncode != 0 else None
        
        return result
    
    def generate_custom_template(
        self,
        plan,  # AttackPlan
        output_path: Path
    ) -> Path:
        """Génère un template Nuclei custom basé sur le plan d'attaque."""
        template = {
            "id": f"ghost-hunter-{plan.id[:8]}",
            "info": {
                "name": f"Ghost-Hunter Custom - {plan.vuln_class}",
                "author": "ghost-hunter",
                "severity": "medium",
                "description": plan.reasoning or f"Custom test for {plan.vuln_class}",
                "tags": [plan.vuln_class.lower(), "ghost-hunter", "custom"],
            },
            "requests": []
        }
        
        # Construire les requêtes
        req = plan.request.request.request.request
        
        for payload in plan.payloads[:5]:  # Max 5 payloads par template
            for injection_point in plan.injection_points[:3]:  # Max 3 points
                request_def = {
                    "method": req.method,
                    "path": [req.path],
                    "headers": dict(req.headers),
                }
                
                # Injecter le payload
                if injection_point in (req.query_params or {}):
                    request_def["path"] = [
                        f"{req.path}?{injection_point}={payload.payload}"
                    ]
                
                # Matchers basiques
                request_def["matchers"] = [
                    {
                        "type": "status",
                        "status": [200, 201, 302, 500]
                    }
                ]
                
                template["requests"].append(request_def)
        
        # Sauvegarder
        import yaml
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(yaml.safe_dump(template, default_flow_style=False))
        
        return output_path


# Enregistrer le runner
def register_nuclei():
    """Enregistre le runner Nuclei dans le registre global."""
    runner = NucleiRunner()
    if runner.is_available:
        register_tool(runner)
        logger.info("Nuclei runner registered")
    else:
        logger.warning("Nuclei not found in PATH - runner not registered")

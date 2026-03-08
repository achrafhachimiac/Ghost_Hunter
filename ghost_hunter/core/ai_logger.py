"""
Ghost-Hunter AI Decision Logger
================================
Log synthétique des décisions IA pour construire un path déterministe.

Format JSONL - Une ligne par décision :
{
    "ts": 1703592000,
    "endpoint": "POST /api/users/{id}",
    "vuln": "IDOR",
    "injection_points": ["id", "account_id"],
    "payloads": ["1", "2", "-1"],
    "reasoning": "ID manipulation possible",
    "source": "ai|fallback",
    "result": "vulnerable|safe|error"
}
"""

import json
import os
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path
from dataclasses import asdict

logger = logging.getLogger(__name__)

# Fichier de log centralisé
LOG_DIR = Path(__file__).parent.parent.parent / "data" / "logs"
AI_DECISIONS_LOG = LOG_DIR / "ai_decisions.jsonl"


class AIDecisionLogger:
    """Logger synthétique pour les décisions IA."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        # Créer le dossier si nécessaire
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._log_file = AI_DECISIONS_LOG
        self._initialized = True
        logger.info(f"📝 AI Logger initialized: {self._log_file}")
    
    def log_plan(
        self,
        endpoint: str,
        method: str,
        vuln_class: str,
        injection_points: List[str],
        payloads: List[str],
        reasoning: str = "",
        source: str = "ai",  # "ai" ou "fallback"
        model: str = "",
        host: str = "",
    ) -> None:
        """
        Log un plan d'attaque généré.
        
        Args:
            endpoint: Path template (ex: /api/users/{id})
            method: HTTP method
            vuln_class: Type de vulnérabilité ciblée
            injection_points: Points d'injection identifiés
            payloads: Payloads à tester (premiers 10 max)
            reasoning: Explication de l'IA
            source: "ai" ou "fallback"
            model: Modèle utilisé
            host: Domaine cible
        """
        entry = {
            "ts": int(datetime.now().timestamp()),
            "host": host,
            "method": method,
            "endpoint": endpoint,
            "vuln": vuln_class,
            "injection_points": injection_points[:5],  # Max 5
            "payloads": payloads[:10],  # Max 10
            "source": source,
        }
        
        # Optionnels (si non vides)
        if reasoning:
            # Tronquer le reasoning à 200 chars
            entry["reasoning"] = reasoning[:200]
        if model:
            entry["model"] = model
        
        self._write(entry)
    
    def log_result(
        self,
        endpoint: str,
        method: str,
        vuln_class: str,
        payload_used: str,
        injection_point: str,
        result: str,  # "vulnerable", "safe", "error", "timeout"
        status_code: int = 0,
        evidence: str = "",
        host: str = "",
    ) -> None:
        """
        Log le résultat d'un test.
        
        Args:
            endpoint: Path template
            method: HTTP method
            vuln_class: Type de vulnérabilité testée
            payload_used: Payload qui a été testé
            injection_point: Point d'injection utilisé
            result: Résultat du test
            status_code: Code HTTP de la réponse
            evidence: Preuve courte si vulnérable
            host: Domaine cible
        """
        entry = {
            "ts": int(datetime.now().timestamp()),
            "type": "result",
            "host": host,
            "method": method,
            "endpoint": endpoint,
            "vuln": vuln_class,
            "injection": injection_point,
            "payload": payload_used[:100],  # Max 100 chars
            "result": result,
        }
        
        if status_code:
            entry["status"] = status_code
        if evidence and result == "vulnerable":
            entry["evidence"] = evidence[:200]
        
        self._write(entry)
    
    def log_finding(
        self,
        endpoint: str,
        method: str,
        vuln_class: str,
        severity: str,
        payload: str,
        injection_point: str,
        confidence: float = 0.0,
        host: str = "",
    ) -> None:
        """
        Log un finding confirmé.
        """
        entry = {
            "ts": int(datetime.now().timestamp()),
            "type": "finding",
            "host": host,
            "method": method,
            "endpoint": endpoint,
            "vuln": vuln_class,
            "severity": severity,
            "injection": injection_point,
            "payload": payload[:100],
            "confidence": round(confidence, 2),
        }
        self._write(entry)
    
    def _write(self, entry: Dict[str, Any]) -> None:
        """Écrit une entrée dans le fichier JSONL."""
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"Failed to write AI decision log: {e}")
    
    def get_patterns(self, vuln_type: Optional[str] = None) -> Dict[str, List[Dict]]:
        """
        Analyse les logs pour extraire les patterns efficaces.
        
        Returns:
            Dict avec les patterns groupés par endpoint/vuln
        """
        patterns = {}
        
        if not self._log_file.exists():
            return patterns
        
        try:
            with open(self._log_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        
                        # Filtrer par type de vuln si spécifié
                        if vuln_type and entry.get("vuln") != vuln_type:
                            continue
                        
                        # Grouper par endpoint
                        key = f"{entry.get('method', 'GET')} {entry.get('endpoint', '/')}"
                        if key not in patterns:
                            patterns[key] = []
                        patterns[key].append(entry)
                        
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Failed to read AI decision log: {e}")
        
        return patterns
    
    def get_effective_payloads(self, vuln_type: str) -> List[str]:
        """
        Retourne les payloads qui ont abouti à des findings.
        
        Args:
            vuln_type: Type de vulnérabilité
            
        Returns:
            Liste des payloads efficaces triés par fréquence
        """
        payload_hits = {}
        
        if not self._log_file.exists():
            return []
        
        try:
            with open(self._log_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        
                        # Ne garder que les findings du bon type
                        if entry.get("type") != "finding":
                            continue
                        if entry.get("vuln") != vuln_type:
                            continue
                        
                        payload = entry.get("payload", "")
                        if payload:
                            payload_hits[payload] = payload_hits.get(payload, 0) + 1
                            
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Failed to analyze AI decision log: {e}")
        
        # Trier par nombre de hits
        sorted_payloads = sorted(
            payload_hits.keys(),
            key=lambda p: payload_hits[p],
            reverse=True
        )
        
        return sorted_payloads


# Singleton global
_ai_logger: Optional[AIDecisionLogger] = None


def get_ai_logger() -> AIDecisionLogger:
    """Retourne le logger singleton."""
    global _ai_logger
    if _ai_logger is None:
        _ai_logger = AIDecisionLogger()
    return _ai_logger

"""
Response Analyzer - Détecte les vulnérabilités dans les réponses HTTP.

Extracted from http_runner.py - Phase 6 refactoring.
Centralise la logique d'analyse des réponses pour identifier les findings.
"""
import hashlib
import re
from typing import Optional, TYPE_CHECKING

from ..contracts import (
    Finding,
    PayloadVariant,
    ResponseSignature,
)
from .constants import ERROR_PATTERNS, _safe_get_payload_value
from .finding_factory import FindingFactory

if TYPE_CHECKING:
    import httpx


# Types de vulnérabilités sensibles au timing
TIME_BASED_VULN_TYPES = {"SQLI", "CMDI", "RCE"}

# Seuil de timing anomaly (5 secondes)
TIMING_ANOMALY_THRESHOLD_MS = 5000

# Status codes indiquant une erreur serveur
ERROR_STATUS_CODES = {500, 502, 503}


class ResponseAnalyzer:
    """
    Analyse les réponses HTTP pour détecter les vulnérabilités.
    
    Responsabilités:
    - Générer une signature de réponse
    - Détecter les patterns d'erreur
    - Identifier les réflexions de payload
    - Détecter les anomalies de timing
    - Créer des Finding objects
    
    Usage:
        analyzer = ResponseAnalyzer()
        finding = analyzer.analyze(response, response_time, vuln_class, payload, injection_point, url)
    """
    
    @staticmethod
    def build_signature(
        response: 'httpx.Response',
        response_time: float,
        vuln_class: str,
        payload_value: str,
    ) -> ResponseSignature:
        """
        Construit une signature de réponse pour analyse.
        
        Args:
            response: Réponse HTTP
            response_time: Temps de réponse en ms
            vuln_class: Classe de vulnérabilité testée
            payload_value: Valeur du payload injecté
            
        Returns:
            ResponseSignature avec tous les indicateurs
        """
        content = response.text or ""
        
        signature = ResponseSignature(
            status_code=response.status_code,
            content_type=response.headers.get("content-type", ""),
            body_length=len(content),
            body_hash=hashlib.md5(content.encode()).hexdigest(),
            response_time_ms=response_time,
        )
        
        # Chercher des patterns d'erreur
        vuln_key = vuln_class.lower()
        if vuln_key in ERROR_PATTERNS:
            for pattern in ERROR_PATTERNS[vuln_key]:
                if re.search(pattern, content, re.IGNORECASE):
                    signature.error_patterns_found.append(pattern)
        
        # Vérifier la réflexion du payload (XSS)
        if payload_value and payload_value in content:
            signature.reflection_found = True
        
        # Vérifier anomalie de timing
        if response_time > TIMING_ANOMALY_THRESHOLD_MS:
            signature.timing_anomaly = True
        
        return signature
    
    @staticmethod
    def is_potential_finding(
        signature: ResponseSignature,
        vuln_class: str,
        response: 'httpx.Response',
    ) -> bool:
        """
        Détermine si la réponse indique une vulnérabilité potentielle.
        
        Critères de détection:
        - Patterns d'erreur trouvés dans la réponse
        - Réflexion de payload pour XSS
        - Anomalie de timing pour injections time-based
        - Status codes d'erreur serveur
        
        Args:
            signature: Signature de la réponse
            vuln_class: Classe de vulnérabilité testée
            response: Réponse HTTP originale
            
        Returns:
            True si un finding potentiel est détecté
        """
        # Error patterns trouvés
        if signature.error_patterns_found:
            return True
        
        vuln_upper = vuln_class.upper()
        
        # Réflexion XSS
        if vuln_upper == "XSS" and signature.reflection_found:
            return True
        
        # Timing anomaly pour time-based vulns
        if vuln_upper in TIME_BASED_VULN_TYPES and signature.timing_anomaly:
            return True
        
        # Status codes suspects
        if response.status_code in ERROR_STATUS_CODES:
            return True
        
        # IDOR - status 200 avec contenu différent
        # Note: Nécessite comparaison avec baseline, non implémenté ici
        if vuln_upper == "IDOR" and response.status_code == 200:
            return False  # TODO: implémenter avec baseline
        
        return False
    
    @classmethod
    def analyze(
        cls,
        response: 'httpx.Response',
        response_time: float,
        vuln_class: str,
        payload: PayloadVariant,
        injection_point: str,
        url: str,
    ) -> Optional[Finding]:
        """
        Analyse la réponse pour détecter des vulnérabilités.
        
        Pipeline d'analyse:
        1. Extraction sécurisée de la valeur du payload
        2. Construction de la signature de réponse
        3. Détection des patterns et anomalies
        4. Création du Finding si vulnérabilité détectée
        
        Args:
            response: Réponse HTTP à analyser
            response_time: Temps de réponse en ms
            vuln_class: Classe de vulnérabilité testée (SQLi, XSS, etc.)
            payload: Payload injecté (dict, PayloadVariant, ou str)
            injection_point: Point d'injection (param, header, etc.)
            url: URL testée
            
        Returns:
            Finding si vulnérabilité détectée, None sinon
        """
        content = response.text or ""
        
        # Extraction sécurisée du payload
        payload_value = _safe_get_payload_value(payload)
        
        # Construire la signature
        signature = cls.build_signature(
            response=response,
            response_time=response_time,
            vuln_class=vuln_class,
            payload_value=payload_value,
        )
        
        # Vérifier si c'est un finding potentiel
        if not cls.is_potential_finding(signature, vuln_class, response):
            return None
        
        # Créer le finding via la factory
        return FindingFactory.create(
            endpoint=url,
            method="",  # Sera rempli plus tard par le caller
            vuln_class=vuln_class,
            signature=signature,
            payload=payload_value,
            injection_point=injection_point,
            request_sent=f"Payload: {payload_value} in {injection_point}",
            response_received=content,
        )

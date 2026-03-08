"""
Analyzer pour le Strategist V2.

Analyse les résultats d'exécution HTTP pour extraire les informations
pertinentes et détecter les patterns WAF.
~250 lignes max selon les règles du projet.
"""

import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from .contracts import (
    AttemptResult,
    RoundResult,
    RoundNPlan,
    PayloadSpec,
)


# Signatures WAF connues (subset des principales)
WAF_SIGNATURES = {
    "cloudflare": [
        "attention required",
        "cloudflare ray id",
        "cf-ray",
        "please wait while we check your browser",
        "__cf_bm",
        "cf-chl-bypass",
    ],
    "aws_waf": [
        "request blocked",
        "aws-waf",
        "x-amzn-requestid",
        "forbidden by aws waf",
    ],
    "akamai": [
        "akamai ghost",
        "ak_bmsc",
        "akamai-grn",
        "reference #",
    ],
    "imperva": [
        "incapsula",
        "visid_incap",
        "_incap_",
        "incap_ses",
    ],
    "f5_bigip": [
        "big-ip",
        "bigipserver",
        "f5-",
        "ts-cookie",
    ],
    "modsecurity": [
        "mod_security",
        "modsec",
        "owasp",
        "coraza",
    ],
}

# Patterns qui indiquent un blocage WAF
WAF_BLOCK_PATTERNS = [
    r"(access|request)\s*(is\s*)?(denied|blocked|forbidden)",
    r"security\s*(violation|block|alert)",
    r"suspicious\s*(activity|request)",
    r"(attack|threat)\s*detected",
    r"please\s*verify\s*you\s*are\s*(human|not\s*a\s*robot)",
    r"captcha",
    r"rate\s*limit(ed)?",
]


def analyze_http_response(
    payload_original: str,
    payload_sent: str,
    encoding: str,
    injection_point: str,
    method: str,
    url: str,
    status_code: int,
    response_time_ms: float,
    response_body: str,
    response_headers: Dict[str, str],
    baseline_status: Optional[int] = None,
    baseline_length: Optional[int] = None,
    baseline_time_ms: Optional[float] = None,
) -> AttemptResult:
    """
    Analyse une réponse HTTP et détermine si c'est un blocage WAF.
    
    Args:
        payload_original: Payload avant encoding
        payload_sent: Payload réellement envoyé
        encoding: Type d'encoding utilisé
        injection_point: Point d'injection ciblé
        method: Méthode HTTP
        url: URL complète
        status_code: Code de réponse HTTP
        response_time_ms: Temps de réponse en ms
        response_body: Corps de la réponse
        response_headers: Headers de la réponse
        baseline_status: Code status de la baseline
        baseline_length: Longueur de la baseline
        baseline_time_ms: Temps de réponse baseline
        
    Returns:
        AttemptResult avec analyse WAF et diff
    """
    # Détection WAF
    waf_blocked, waf_provider, waf_signature = _detect_waf_block(
        status_code, response_body, response_headers
    )
    
    # Calcul des différences avec baseline
    diff_indicators = _compute_diff_indicators(
        status_code, len(response_body), response_time_ms,
        baseline_status, baseline_length, baseline_time_ms
    )
    
    # Déterminer si intéressant
    is_interesting = _is_interesting_response(
        status_code, diff_indicators, waf_blocked, response_body
    )
    
    return AttemptResult(
        payload_original=payload_original,
        payload_sent=payload_sent,
        encoding=encoding,
        injection_point=injection_point,
        method=method,
        url=url,
        status_code=status_code,
        response_time_ms=response_time_ms,
        response_length=len(response_body),
        response_snippet=response_body[:500] if response_body else "",
        waf_blocked=waf_blocked,
        waf_provider=waf_provider,
        waf_signature=waf_signature,
        is_interesting=is_interesting,
        diff_indicators=diff_indicators,
    )


def _detect_waf_block(
    status_code: int,
    response_body: str,
    response_headers: Dict[str, str],
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Détecte si la réponse est un blocage WAF.
    
    Returns:
        Tuple (is_blocked, waf_provider, waf_signature)
    """
    body_lower = response_body.lower()
    headers_str = str(response_headers).lower()
    
    # Check status codes typiques des blocages
    if status_code in (403, 406, 429, 503):
        # Chercher le provider dans les headers/body
        for provider, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig in body_lower or sig in headers_str:
                    return True, provider, sig
        
        # Check patterns génériques
        for pattern in WAF_BLOCK_PATTERNS:
            match = re.search(pattern, body_lower, re.IGNORECASE)
            if match:
                return True, "unknown", match.group(0)
        
        # 403/429 sans signature claire = probable WAF
        if status_code in (403, 429):
            return True, "unknown", f"HTTP {status_code}"
    
    # Même si status OK, chercher des signes de blocage
    for provider, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig in body_lower and "blocked" in body_lower:
                return True, provider, sig
    
    return False, None, None


def _compute_diff_indicators(
    status_code: int,
    response_length: int,
    response_time_ms: float,
    baseline_status: Optional[int],
    baseline_length: Optional[int],
    baseline_time_ms: Optional[float],
) -> List[str]:
    """
    Calcule les indicateurs de différence avec la baseline.
    
    Returns:
        Liste des différences détectées
    """
    indicators = []
    
    if baseline_status is not None and status_code != baseline_status:
        indicators.append(f"status_diff:{baseline_status}->{status_code}")
    
    if baseline_length is not None:
        length_diff = abs(response_length - baseline_length)
        if length_diff > 100:  # Différence significative
            percent = (length_diff / max(baseline_length, 1)) * 100
            if percent > 10:
                indicators.append(f"length_diff:{percent:.0f}%")
    
    if baseline_time_ms is not None:
        time_diff = response_time_ms - baseline_time_ms
        if abs(time_diff) > 500:  # Plus de 500ms de différence
            indicators.append(f"time_diff:{time_diff:.0f}ms")
    
    return indicators


def _is_interesting_response(
    status_code: int,
    diff_indicators: List[str],
    waf_blocked: bool,
    response_body: str,
) -> bool:
    """
    Détermine si la réponse est intéressante pour investigation.
    
    Une réponse est intéressante si:
    - Non bloquée par WAF ET (différences avec baseline OU status 200 avec contenu)
    """
    if waf_blocked:
        return False
    
    # Différences significatives
    if diff_indicators:
        return True
    
    # Status 200 avec du contenu
    if status_code == 200 and len(response_body) > 100:
        # Chercher des signes de données différentes
        interesting_patterns = [
            r'"id"\s*:\s*\d+',  # Autre ID
            r'"user"',          # Données utilisateur
            r'"email"',         # Email
            r'"password"',      # Mot de passe (leak!)
            r'"token"',         # Token
            r'"secret"',        # Secret
        ]
        for pattern in interesting_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True
    
    return False


def create_round_result(
    round_number: int,
    plan: RoundNPlan,
    attempts: List[AttemptResult],
) -> RoundResult:
    """
    Crée un RoundResult à partir des tentatives.
    
    Args:
        round_number: Numéro du round
        plan: Plan d'attaque utilisé
        attempts: Liste des résultats de tentatives
        
    Returns:
        RoundResult avec stats calculées
    """
    result = RoundResult(
        round_number=round_number,
        timestamp=datetime.now(),
        plan=plan,
        tests=attempts,
    )
    
    # Calculer les stats
    result.compute_stats()
    
    # Extraire les patterns
    result.blocked_patterns = _extract_blocked_patterns(attempts)
    result.working_techniques = _extract_working_techniques(attempts)
    result.promising_results = _extract_promising_results(attempts)
    
    return result


def _extract_blocked_patterns(attempts: List[AttemptResult]) -> List[str]:
    """Extrait les patterns qui ont été bloqués."""
    patterns = []
    for attempt in attempts:
        if attempt.waf_blocked:
            # Simplifier le payload pour le pattern
            payload = attempt.payload_original
            if len(payload) > 30:
                payload = payload[:27] + "..."
            pattern = f"{attempt.encoding}:{payload}"
            patterns.append(pattern)
    return patterns


def _extract_working_techniques(attempts: List[AttemptResult]) -> List[str]:
    """Extrait les techniques qui ont fonctionné."""
    techniques = []
    for attempt in attempts:
        if not attempt.waf_blocked:
            technique = f"{attempt.encoding} on {attempt.injection_point}"
            if technique not in techniques:
                techniques.append(technique)
    return techniques


def _extract_promising_results(attempts: List[AttemptResult]) -> List[str]:
    """Extrait les résultats prometteurs."""
    results = []
    for attempt in attempts:
        if attempt.is_interesting:
            desc = (
                f"Payload '{attempt.payload_original[:20]}...' "
                f"returned {attempt.status_code} with diffs: "
                f"{', '.join(attempt.diff_indicators)}"
            )
            results.append(desc)
    return results

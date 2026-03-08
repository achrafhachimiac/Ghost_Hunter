"""
Strategist Context Module
=========================
Récupération du contexte RAG, Knowledge Base et Security Profile.
"""

import logging
from typing import Optional, Tuple, List, Any

from ghost_hunter.core.contracts import TriageDecision, ScoredRequest

logger = logging.getLogger(__name__)


def build_request_data(triage: TriageDecision) -> dict:
    """
    Construit les données de requête COMPLÈTES pour le prompt et replay.
    
    Args:
        triage: Décision du triage avec la requête
        
    Returns:
        Dictionnaire avec toutes les données de la requête
    """
    req = triage.request.request.request
    
    return {
        "method": req.method,
        "url": req.url,
        "host": req.host,
        "path": req.path,
        "query_params": req.query_params,
        "headers": dict(req.headers),  # ALL headers including auth & cookies
        "cookies": req.cookies,  # Full cookie values for replay
        "body": req.body,  # Full body
        "body_json": req.body_json,
        "has_auth": "authorization" in [h.lower() for h in req.headers.keys()],
        "content_type": req.headers.get('content-type', req.headers.get('Content-Type', '')),
        # Response info
        "response_status": req.response_status,
        "response_headers": dict(req.response_headers) if req.response_headers else None,
        "response_body": req.response_body[:5000] if req.response_body else None,
    }


def build_triage_result(triage: TriageDecision) -> dict:
    """
    Construit le résultat du triage pour le prompt.
    
    Args:
        triage: Décision du triage
        
    Returns:
        Dictionnaire avec les résultats du triage
    """
    result = {
        "suggested_vulns": triage.suggested_vulns,
        "confidence": triage.confidence,
        "reason": triage.reason,
        "test_phase": triage.test_phase.value
    }
    
    # NEW: Include attack surface hints from Tier 2 for targeted testing
    if hasattr(triage, 'attack_surface_hints') and triage.attack_surface_hints:
        result["attack_surface_hints"] = triage.attack_surface_hints
        logger.info(f"🎯 Strategist received {len(triage.attack_surface_hints)} attack hints from Triage")
    
    if hasattr(triage, 'false_positive_reason') and triage.false_positive_reason:
        result["false_positive_reason"] = triage.false_positive_reason
    
    return result


def get_knowledge_context(knowledge_loader: Any, suggested_vulns: list) -> Tuple[Optional[str], Optional[List[str]]]:
    """
    Récupère le contexte Knowledge et les payloads (legacy).
    
    Args:
        knowledge_loader: Instance du KnowledgeLoader
        suggested_vulns: Liste des vulnérabilités suggérées
        
    Returns:
        Tuple (contexte, liste de payloads)
    """
    if not knowledge_loader or not suggested_vulns:
        return None, None
    
    try:
        # Contexte technique (HackTricks)
        context = knowledge_loader.get_context_for_prompt(
            vuln_types=suggested_vulns,
            max_techniques=3,  # Plus détaillé pour la stratégie
            max_payloads=0  # Payloads séparés
        )
        
        # Payloads de PayloadsAllTheThings
        all_payloads = []
        for vuln in suggested_vulns[:2]:  # Max 2 vulns
            vuln_payloads = knowledge_loader.get_payloads_for_prompt(
                vuln_type=vuln,
                limit=10
            )
            all_payloads.extend(vuln_payloads)
        
        return context, all_payloads[:15]  # Max 15 payloads total
        
    except Exception as e:
        logger.debug(f"Knowledge context error: {e}")
        return None, None


def get_rag_context(
    rag_engine: Any,
    triage: TriageDecision,
    max_tokens: int = 1500,
    max_chunks: int = 15
) -> Tuple[Optional[str], Optional[List[str]]]:
    """
    Récupère le contexte RAG pour le Strategist.
    
    Utilise la recherche sémantique pour trouver des techniques,
    CVE, et payloads pertinents basés sur le triage.
    
    Args:
        rag_engine: Instance du RAG Engine
        triage: Décision du triage
        max_tokens: Budget tokens maximum
        max_chunks: Nombre maximum de chunks
        
    Returns:
        Tuple (context_text, payloads_list)
    """
    if not rag_engine:
        return None, None
    
    scored = triage.request
    try:
        # Get RAG context with payloads included
        rag_result = rag_engine.get_context_sync(
            scored,
            max_tokens=max_tokens,
            max_chunks=max_chunks,
            include_payloads=True  # Strategist needs payloads
        )
        
        # Extract the formatted context string from RAGContext object
        context_text = None
        if rag_result and hasattr(rag_result, 'formatted_context'):
            context_text = rag_result.formatted_context
            if context_text:
                logger.info(f"🧠 RAG context for Strategist: {len(context_text)} chars, {len(rag_result.results)} chunks")
        
        # Note: payloads are included in the context string
        # Return as tuple for compatibility with existing prompt building
        return context_text, []
        
    except Exception as e:
        logger.warning(f"🧠 RAG context error: {e}")
        return None, None


def get_security_context(host: str) -> Optional[dict]:
    """
    Récupère le Security Profile pour le domaine cible.
    
    Args:
        host: Hostname de la cible
        
    Returns:
        Dictionnaire avec les infos de sécurité ou None
    """
    try:
        from ghost_hunter.core.intelligence import get_fingerprinter
        fingerprinter = get_fingerprinter()
        profile = fingerprinter.get_profile(host)
        
        if not profile:
            return None
        
        # Construire le contexte pour le prompt
        security_profile = profile.to_security_profile()
        
        return {
            "waf": profile.waf.name if profile.waf else None,
            "waf_confidence": profile.waf.confidence if profile.waf else 0,
            "cdn": profile.cdn.name if profile.cdn else None,
            "anti_bot": profile.anti_bot.name if profile.anti_bot else None,
            "rate_limiting": profile.rate_limiting is not None,
            "backend": profile.backend_framework.name if profile.backend_framework else None,
            "frontend": profile.frontend_framework.name if profile.frontend_framework else None,
            "security_headers_count": sum(1 for v in profile.security_headers.values() if v),
            "security_headers_total": len(profile.security_headers),
            "evasion_techniques": security_profile.recommended_evasion,
        }
    except Exception as e:
        logger.debug(f"Security context error: {e}")
        return None

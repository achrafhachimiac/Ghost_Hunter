"""
Ghost-Hunter Strategist Module
==============================
Moteur de stratégie IA pour créer des plans d'attaque détaillés.

Ce module est découpé en plusieurs fichiers pour une meilleure maintenabilité:
- engine.py: Classe principale StrategistEngine
- parser.py: Extraction JSON et validation des injection points
- context.py: Récupération du contexte RAG/Knowledge/Security
- fallback.py: Payloads par défaut et plans de fallback

Usage:
    from ghost_hunter.core.brain.strategist import StrategistEngine
"""

# Re-export depuis le module engine pour compatibilité totale
from ghost_hunter.core.brain.strategist.engine import (
    StrategistEngine,
    AIClient,
    GROQ_CLIENT_AVAILABLE,
    OPENROUTER_CLIENT_AVAILABLE,
    KNOWLEDGE_AVAILABLE,
    RAG_AVAILABLE,
    WAF_EVASION_AVAILABLE,
)

# Re-export des sous-modules pour accès direct si nécessaire
from ghost_hunter.core.brain.strategist.fallback import (
    DEFAULT_PAYLOADS,
    get_quick_payloads,
    create_fallback_plan,
    apply_waf_evasion,
)

from ghost_hunter.core.brain.strategist.parser import (
    extract_json,
    validate_injection_points,
    collect_nested_keys,
)

from ghost_hunter.core.brain.strategist.context import (
    build_request_data,
    build_triage_result,
    get_knowledge_context,
    get_rag_context,
    get_security_context,
)

__all__ = [
    # Main class
    "StrategistEngine",
    # Type aliases
    "AIClient",
    # Availability flags
    "GROQ_CLIENT_AVAILABLE",
    "OPENROUTER_CLIENT_AVAILABLE", 
    "KNOWLEDGE_AVAILABLE",
    "RAG_AVAILABLE",
    "WAF_EVASION_AVAILABLE",
    # Fallback functions
    "DEFAULT_PAYLOADS",
    "get_quick_payloads",
    "create_fallback_plan",
    "apply_waf_evasion",
    # Parser functions
    "extract_json",
    "validate_injection_points",
    "collect_nested_keys",
    # Context functions
    "build_request_data",
    "build_triage_result",
    "get_knowledge_context",
    "get_rag_context",
    "get_security_context",
]

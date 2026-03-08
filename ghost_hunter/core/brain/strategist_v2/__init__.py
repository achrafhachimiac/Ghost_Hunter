"""
Second Round Strategist V2.

Module pour analyser les résultats du Round 1 et générer des payloads
plus intelligents basés sur l'apprentissage des blocages WAF.
"""

from .contracts import (
    OriginalContext,
    AttemptResult,
    RoundResult,
    CumulativeKnowledge,
    RoundNPlan,
    PayloadSpec,
    SecurityProfile,
)
from .engine import StrategistV2Engine
from .history import AttackHistory

__all__ = [
    "OriginalContext",
    "AttemptResult",
    "RoundResult",
    "CumulativeKnowledge",
    "RoundNPlan",
    "PayloadSpec",
    "SecurityProfile",
    "StrategistV2Engine",
    "AttackHistory",
]

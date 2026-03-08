"""
Common Pydantic models for the Dashboard API.
"""

from typing import List
from pydantic import BaseModel


class RequestSummary(BaseModel):
    """Résumé d'une requête pour l'affichage."""
    id: str
    method: str
    url: str = ""
    host: str
    path: str
    score: int = 0
    status: str = "pending"
    timestamp: float
    potential_vulns: List[str] = []


class FindingSummary(BaseModel):
    """Résumé d'un finding."""
    id: str
    endpoint: str
    vuln_type: str
    severity: str
    confidence: int
    status: str
    discovered_at: float


class ServiceAction(BaseModel):
    """Action sur un service."""
    action: str  # start, stop, restart


class ScanConfig(BaseModel):
    """Configuration de scan."""
    target_scope: List[str]
    vuln_types: List[str] = ["all"]
    max_requests_per_second: int = 10
    use_ai_triage: bool = True

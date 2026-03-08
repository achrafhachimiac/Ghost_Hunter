"""
Dashboard Pydantic Schemas
==========================
Tous les modèles Pydantic pour l'API.
"""

from dashboard.schemas.common import (
    RequestSummary,
    FindingSummary,
    ServiceAction,
    ScanConfig,
)
from dashboard.schemas.burp import (
    BurpResponseData,
    BurpRequestData,
    BurpImportRequest,
    BurpImportResponse,
)
from dashboard.schemas.pivot import PivotRunRequest
from dashboard.schemas.security import ScanDomainRequest

__all__ = [
    # Common
    "RequestSummary",
    "FindingSummary",
    "ServiceAction",
    "ScanConfig",
    # Burp
    "BurpResponseData",
    "BurpRequestData",
    "BurpImportRequest",
    "BurpImportResponse",
    # Pivot
    "PivotRunRequest",
    # Security
    "ScanDomainRequest",
]

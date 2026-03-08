"""
Security scan Pydantic models.
"""

from typing import Optional, List
from pydantic import BaseModel


class ScanDomainRequest(BaseModel):
    """Request pour scanner un domaine."""
    domain: str
    protocols: Optional[List[str]] = None  # ["http", "https"]

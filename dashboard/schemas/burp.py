"""
Burp Import Pydantic models.
"""

from typing import Optional, List, Dict
from pydantic import BaseModel


class BurpResponseData(BaseModel):
    """Response data from Burp."""
    status_code: int
    headers: Dict[str, str] = {}
    body: Optional[str] = None


class BurpRequestData(BaseModel):
    """Single request from Burp extension."""
    method: str
    url: str
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    response: Optional[BurpResponseData] = None


class BurpImportRequest(BaseModel):
    """Batch import from Burp extension."""
    requests: List[BurpRequestData]
    scope: Optional[List[str]] = None


class BurpImportResponse(BaseModel):
    """Response for Burp import."""
    imported: int
    deduplicated: int
    new_endpoints: int
    queued_for_analysis: int
    errors: List[str] = []

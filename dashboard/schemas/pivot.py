"""
Pivot Agent Pydantic models.
"""

from typing import Optional
from pydantic import BaseModel


class PivotRunRequest(BaseModel):
    """Request model for pivot agent run."""
    goal: Optional[str] = None  # Optional focus, e.g., "Focus on IDOR"
    max_iterations: Optional[int] = 10

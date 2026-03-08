"""
Requests routes - Raw requests management.

Routes:
- GET /api/requests - List all requests
- GET /api/requests/{request_id} - Get request details
- POST /api/requests - Add a request (from proxy)
- POST /api/triage - Add triage result (from proxy)
"""

from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import APIRouter, HTTPException, Query
import logging

from dashboard.deps import get_pipeline
from dashboard.utils.storage import storage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["requests"])


@router.get("/requests")
async def list_requests(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    min_score: Optional[int] = Query(None, ge=0, le=100),
):
    """Liste les requêtes capturées."""
    reqs = list(storage["requests"].values())
    
    # Aussi récupérer depuis le pipeline si disponible
    try:
        pipeline = get_pipeline()
        if pipeline and hasattr(pipeline, 'requests_store'):
            for req_id, req in pipeline.requests_store.items():
                if req_id not in storage["requests"]:
                    reqs.append(req)
    except:
        pass
    
    if status:
        reqs = [r for r in reqs if r.get("status") == status]
    if min_score is not None:
        reqs = [r for r in reqs if r.get("score", 0) >= min_score]
    reqs.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return reqs[offset:offset + limit]


@router.get("/requests/{request_id}")
async def get_request(request_id: str):
    """Récupère les détails d'une requête."""
    try:
        pipeline = get_pipeline()
        if pipeline and request_id in pipeline.requests_store:
            return pipeline.requests_store[request_id]
    except:
        pass
    
    if request_id in storage["requests"]:
        return storage["requests"][request_id]
    raise HTTPException(status_code=404, detail="Request not found")


@router.post("/requests")
async def add_request(request: Dict[str, Any]):
    """Ajoute une requête (appelé par le proxy)."""
    req_id = request.get("id", str(datetime.now().timestamp()))
    storage["requests"][req_id] = {
        "id": req_id,
        "method": request.get("method", "GET"),
        "url": request.get("url", ""),
        "host": request.get("host", ""),
        "path": request.get("path", ""),
        "score": request.get("score", 0),
        "status": request.get("status", "pending"),
        "timestamp": request.get("timestamp", datetime.now().timestamp()),
        "potential_vulns": request.get("potential_vulns", []),
        "response_status": request.get("response_status"),
    }
    return {"status": "ok", "id": req_id}


@router.post("/triage")
async def add_triage(triage: Dict[str, Any]):
    """Ajoute un résultat de triage IA (appelé par le proxy)."""
    req_id = triage.get("request_id")
    if req_id and req_id in storage["requests"]:
        storage["requests"][req_id]["triage"] = {
            "interesting": triage.get("interesting", False),
            "confidence": triage.get("confidence", 0),
            "suggested_vulns": triage.get("suggested_vulns", []),
            "reason": triage.get("reason", ""),
        }
        storage["requests"][req_id]["status"] = "triaged"
    return {"status": "ok"}

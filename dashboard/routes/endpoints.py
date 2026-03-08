"""
Endpoints tracking routes.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from dashboard.deps import get_pipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/endpoints", tags=["endpoints"])


@router.get("")
async def list_endpoints(
    status: Optional[str] = Query(None, description="Filter by status"),
    sort_by: str = Query("score", description="Sort by: score, last_seen, seen_count, triaged_at"),
    sort_desc: bool = Query(True, description="Sort descending"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None, description="Search in path/host"),
    exclude: Optional[str] = Query(None, description="Exclude paths containing these keywords (comma-separated)"),
    never_triaged: bool = Query(False, description="Only show endpoints never triaged"),
):
    """
    Liste tous les endpoints trackés avec leur status.
    
    Pagination côté serveur avec tri par score par défaut.
    
    Filters:
    - status: Filter by status (pending, triaged, interesting, tested, etc.)
    - search: Search in path/host/params
    - exclude: Exclude paths containing keywords (comma-separated, e.g. "event-logs,analytics")
    - never_triaged: Only show endpoints that have never been triaged
    
    Status possibles:
    - pending: en attente
    - out_of_scope: hors scope
    - static_asset: asset statique (js/css)
    - low_score: score trop bas
    - triaged: passé le triage
    - interesting: marqué intéressant par l'IA
    - tested: testé avec findings
    """
    try:
        pipeline = get_pipeline()
        if not pipeline:
            return {"total": 0, "endpoints": [], "page": 1, "pages": 0, "error": "Pipeline not available"}
        
        endpoints = pipeline.dedup.get_all_endpoints_data()
        
        # Filtrer par status si demandé
        if status:
            endpoints = [e for e in endpoints if e.get("status") == status]
        
        # Filtrer par "jamais triagé" (basé sur le status, pas le timestamp)
        if never_triaged:
            triaged_statuses = {'triaged', 'interesting', 'tested'}
            endpoints = [e for e in endpoints if e.get('status') not in triaged_statuses]
        
        # Filtrer par recherche
        if search:
            search_lower = search.lower()
            endpoints = [e for e in endpoints if 
                search_lower in e.get("path_template", "").lower() or
                search_lower in e.get("host", "").lower() or
                any(search_lower in p.lower() for p in e.get("param_names", []))
            ]
        
        # Filtrer par exclusion (mots-clés à exclure dans path OU host)
        if exclude:
            exclude_keywords = [kw.strip().lower() for kw in exclude.split(",") if kw.strip()]
            if exclude_keywords:
                def should_exclude(ep):
                    path = ep.get("path_template", "").lower()
                    host = ep.get("host", "").lower()
                    return any(kw in path or kw in host for kw in exclude_keywords)
                endpoints = [e for e in endpoints if not should_exclude(e)]
        
        # Trier
        sort_key_map = {
            "score": lambda x: x.get("heuristic_score", 0),
            "last_seen": lambda x: x.get("last_seen", 0),
            "seen_count": lambda x: x.get("seen_count", 0),
            "triaged_at": lambda x: x.get("triaged_at") or 0,
        }
        sort_key = sort_key_map.get(sort_by, sort_key_map["score"])
        endpoints.sort(key=sort_key, reverse=sort_desc)
        
        total = len(endpoints)
        pages = (total + limit - 1) // limit
        current_page = (offset // limit) + 1
        
        return {
            "total": total,
            "page": current_page,
            "pages": pages,
            "limit": limit,
            "offset": offset,
            "endpoints": endpoints[offset:offset + limit]
        }
    except Exception as e:
        return {"total": 0, "endpoints": [], "page": 1, "pages": 0, "error": str(e)}


@router.get("/summary")
async def get_endpoints_summary():
    """Retourne un résumé des endpoints par status."""
    try:
        pipeline = get_pipeline()
        if not pipeline:
            return {"summary": {}, "error": "Pipeline not available"}
        
        summary = pipeline.dedup.get_endpoints_summary()
        dedup_stats = pipeline.dedup.stats()
        
        return {
            "summary": summary,
            "dedup_backend": dedup_stats.get("backend", "memory"),
            "dedup_entries": dedup_stats.get("entries", 0),
        }
    except Exception as e:
        return {"summary": {}, "error": str(e)}


@router.get("/{endpoint_hash}")
async def get_endpoint_details(endpoint_hash: str):
    """Récupère les détails d'un endpoint spécifique."""
    try:
        pipeline = get_pipeline()
        if not pipeline:
            raise HTTPException(status_code=503, detail="Pipeline not available")
        
        endpoints = pipeline.dedup.get_all_endpoints_data()
        for ep in endpoints:
            if ep.get("hash") == endpoint_hash:
                return ep
        
        raise HTTPException(status_code=404, detail="Endpoint not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

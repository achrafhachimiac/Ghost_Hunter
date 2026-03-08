"""
Triage routes - AI Triage endpoints.

Routes:
- POST /api/endpoints/{endpoint_hash}/triage - Force AI triage on endpoint
- GET /api/triage/history - Get triage history
- DELETE /api/triage/history - Clear triage history
"""

from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, BackgroundTasks
import logging

from dashboard.deps import get_pipeline, get_redis_store
from dashboard.utils.storage import storage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["triage"])


@router.post("/endpoints/{endpoint_hash}/triage")
async def triage_endpoint(endpoint_hash: str, background_tasks: BackgroundTasks):
    """Force le triage IA d'un endpoint."""
    try:
        pipeline = get_pipeline()
        if not pipeline:
            raise HTTPException(status_code=503, detail="Pipeline not available")
        
        if not pipeline.triage_engine:
            raise HTTPException(status_code=503, detail="AI Triage not available - check API key")
        
        # Trouver l'endpoint
        endpoints = pipeline.dedup.get_all_endpoints_data()
        endpoint = None
        for ep in endpoints:
            if ep.get("hash") == endpoint_hash:
                endpoint = ep
                break
        
        if not endpoint:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        
        # Créer une requête simulée pour le triage
        from ghost_hunter.core.contracts import (
            InterceptedRequest, FilteredRequest, ScoredRequest
        )
        
        # ═══════════════════════════════════════════════════════════════
        # RÉCUPÉRER LA REQUÊTE COMPLÈTE STOCKÉE - NE RIEN RATER!
        # ═══════════════════════════════════════════════════════════════
        stored_url = endpoint.get("example_url", "")
        stored_headers = endpoint.get("example_headers", {})
        stored_cookies = endpoint.get("example_cookies", {})
        stored_body = endpoint.get("example_body", "")
        stored_body_json = endpoint.get("example_body_json")
        stored_query_params = endpoint.get("example_query_params", {})
        example_path = endpoint.get("example_paths", [""])[0]
        
        # URL complète
        base_url = stored_url or f"https://{endpoint.get('host', '')}{example_path}"
        
        # Reconstruire les objets nécessaires pour le triage
        intercepted = InterceptedRequest(
            id=f"triage_{endpoint_hash}",
            method=endpoint.get("method", "GET"),
            url=base_url,
            host=endpoint.get("host", ""),
            path=example_path,
            # TOUT transmettre!
            headers=stored_headers,
            cookies=stored_cookies,
            body=stored_body,
            body_json=stored_body_json,
            query_params=stored_query_params,
            timestamp=datetime.now().timestamp(),
        )
        
        filtered = FilteredRequest(
            request=intercepted,
            in_scope=True,
            is_static=False,
            scope_match=endpoint.get("host", ""),
            domain=endpoint.get("host", ""),
        )
        
        scored = ScoredRequest(
            request=filtered,
            score=endpoint.get("heuristic_score", 0),
            potential_vulns=endpoint.get("potential_vulns", []),
        )
        
        # Lancer le triage DIRECT (sans quick_triage)
        logger.info(f"🤖 Manual triage for {endpoint.get('method')} {endpoint.get('path')}")
        logger.info(f"   - Headers: {list(stored_headers.keys())}")
        logger.info(f"   - Cookies: {list(stored_cookies.keys())}")
        
        if not pipeline.triage_engine:
            raise HTTPException(status_code=500, detail="Triage engine not available")
        
        triage = pipeline.triage_engine.full_triage(scored)
        logger.info(f"🤖 Triage result: interesting={triage.interesting}, confidence={triage.confidence}, reason={triage.reason[:100] if triage.reason else 'N/A'}")
        
        # full_triage retourne toujours un TriageDecision (jamais None)
        # Mettre à jour l'endpoint avec le résultat du triage
        from ghost_hunter.core.interceptor.dedup import EndpointStatus
        new_status = EndpointStatus.INTERESTING if triage.interesting else EndpointStatus.TRIAGED
        pipeline.dedup.update_endpoint_status(
            filtered,
            new_status,
            f"AI Triage: {'Interesting' if triage.interesting else 'Not interesting'} ({triage.confidence}%)"
        )
        
        # Sauvegarder dans l'historique persistant
        triage_entry = {
            "timestamp": datetime.now().isoformat(),
            "hash": endpoint_hash,
            "method": endpoint.get("method", "GET"),
            "host": endpoint.get("host", ""),
            "path": endpoint.get("path_template", "") or endpoint.get("example_paths", [""])[0],
            "interesting": triage.interesting,
            "confidence": triage.confidence,
            "reason": triage.reason,
            "suggested_vulns": triage.suggested_vulns,
            "attack_surface_hints": triage.attack_surface_hints,  # NEW: Attack surface expansion hints
            "new_status": new_status.value,
            "model": triage.model_used,
            "tokens": triage.tokens_input + triage.tokens_output,
            "tested": False,
            "test_result": None,
            # ═══════════════════════════════════════════════════════════════
            # DEBUG: Prompt et réponse IA pour inspection
            # ═══════════════════════════════════════════════════════════════
            "debug_prompt": triage.debug_prompt,
            "debug_response": triage.debug_response,
            # ═══════════════════════════════════════════════════════════════
            # REQUÊTE/RÉPONSE ORIGINALE CAPTURÉE (via Burp/proxy)
            # ═══════════════════════════════════════════════════════════════
            "original_request": {
                "url": stored_url or base_url,
                "method": endpoint.get("method", "GET"),
                "headers": stored_headers,
                "cookies": stored_cookies,
                "body": stored_body,
                "body_json": stored_body_json,
                "query_params": stored_query_params,
                "content_type": endpoint.get("example_content_type", ""),
            },
            "original_response": {
                "status_code": endpoint.get("example_response_status"),
                "headers": endpoint.get("example_response_headers", {}),
                "body": endpoint.get("example_response_body", ""),
                "time_ms": endpoint.get("example_response_time_ms"),
            },
        }
        # Sauvegarder dans Redis
        get_redis_store().add_triage(triage_entry)
        # Aussi dans storage local pour compatibilité
        storage["triage_history"].insert(0, triage_entry)
        storage["triage_history"] = storage["triage_history"][:100]
        
        return {
            "status": "ok",
            "interesting": triage.interesting,
            "confidence": triage.confidence,
            "suggested_vulns": triage.suggested_vulns,
            "attack_surface_hints": triage.attack_surface_hints,  # NEW
            "reason": triage.reason,
            "new_status": new_status.value,
            "model": triage.model_used,
            "tokens": triage.tokens_input + triage.tokens_output,
        }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Triage error")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/triage/history")
async def get_triage_history():
    """Récupère l'historique des triages AI depuis Redis, avec les résultats multi-round."""
    # Priorité Redis, fallback storage local
    history = get_redis_store().get_triage_history(limit=100)
    if not history:
        history = storage["triage_history"]
    
    # Enrichir avec les résultats multi-round sauvegardés
    redis_store = get_redis_store()
    if redis_store and redis_store.connected:
        try:
            import json
            for item in history:
                endpoint_hash = item.get("hash")
                if endpoint_hash:
                    # Charger le résultat multi-round depuis Redis
                    multi_round_data = redis_store._redis.hget("multi_round_results", endpoint_hash)
                    if multi_round_data:
                        item["multiRoundResult"] = json.loads(multi_round_data)
        except Exception as e:
            logger.warning(f"Failed to load multi-round results: {e}")
    
    return {"history": history}


@router.delete("/triage/history")
async def clear_triage_history():
    """Efface l'historique des triages (via reset général)."""
    storage["triage_history"] = []
    # Note: Le reset Redis se fait via /api/reset
    return {"status": "ok"}

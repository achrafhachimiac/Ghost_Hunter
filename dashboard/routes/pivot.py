"""
Pivot Agent routes - Autonomous IDOR testing agent.

Routes:
- POST /api/pivot/run/{log_id} - Start pivot agent on endpoint
- GET /api/pivot/logs/{log_id} - Get pivot agent logs
- GET /api/pivot/status/{log_id} - Check pivot agent status
- POST /api/pivot/stop/{log_id} - Emergency stop pivot agent
- DELETE /api/pivot/logs/{log_id} - Clear logs for session
- DELETE /api/pivot/logs - Clear ALL pivot agent logs
"""

from typing import Dict, Any, Optional
import time

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
import logging

from dashboard.deps import get_pipeline, get_redis_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/pivot", tags=["pivot"])


class PivotRunRequest(BaseModel):
    """Request model for pivot agent run."""
    goal: Optional[str] = None  # Optional focus, e.g., "Focus on IDOR"
    max_iterations: Optional[int] = 10


@router.post("/run/{log_id}")
async def run_pivot_agent(
    log_id: str,
    request: PivotRunRequest,
    background_tasks: BackgroundTasks
):
    """
    Lance le Pivot Agent sur un log spécifique.
    
    Le log_id correspond à un endpoint ou une requête dans Redis.
    L'agent publiera ses "pensées" en temps réel dans le canal Redis agent:logs:{log_id}
    
    Args:
        log_id: ID du log/endpoint à analyser
        request.goal: Objectif optionnel (ex: "Focus sur IDOR")
        request.max_iterations: Nombre max d'itérations
    
    Returns:
        Status de lancement avec le canal Redis à écouter
    """
    try:
        # Récupérer les données de l'endpoint depuis le pipeline (dedup)
        log_data = None
        pipeline = get_pipeline()
        
        if pipeline and pipeline.dedup:
            # Chercher dans les endpoints du dedup
            all_endpoints = pipeline.dedup.get_all_endpoints_data()
            for ep in all_endpoints:
                if ep.get("hash") == log_id:
                    log_data = ep
                    break
        
        # Fallback: essayer Redis
        if not log_data:
            log_data = get_redis_store().get_endpoint(log_id)
        
        if not log_data:
            # Essayer comme finding_id
            log_data = get_redis_store().get_finding(log_id)
        
        if not log_data:
            raise HTTPException(status_code=404, detail=f"Endpoint {log_id} not found. Make sure you have captured traffic via the proxy.")
        
        # Importer le pivot agent
        from pivot_agent import get_pivot_agent
        from pivot_agent.state import create_initial_state
        from pivot_agent.redis_logger import set_agent_logger
        
        # Créer le logger Redis pour ce run
        agent_logger = set_agent_logger(log_id)
        agent_logger.session_start(
            target=log_data.get("url", log_id),
            goal=request.goal
        )
        
        # Créer l'état initial
        target = log_data.get("host", log_data.get("example_url", log_id))
        initial_state = create_initial_state(target)
        
        # =========================================================================
        # CRITICAL: Build FULL URL with query parameters
        # The LLM needs the complete URL to understand the request structure
        # =========================================================================
        base_url = log_data.get("example_url", "")
        query_params = log_data.get("example_query_params", {})
        
        # DEBUG: Log what we got from log_data
        logger.info(f"📋 DEBUG log_data keys: {list(log_data.keys())}")
        logger.info(f"📋 DEBUG base_url: {base_url}")
        logger.info(f"📋 DEBUG query_params from log_data: {query_params}")
        
        # =========================================================================
        # FALLBACK: Extract query params from URL if not in dict
        # The dedup may have stored the full URL but not parsed the params
        # =========================================================================
        if not query_params and "?" in base_url:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(base_url)
            # parse_qs returns lists, convert to single values
            query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}
            # Also fix the base_url to be without query params
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            logger.info(f"📋 EXTRACTED query_params from URL: {query_params}")
        
        logger.info(f"📋 DEBUG param_names: {log_data.get('param_names', [])}")
        
        # Build full URL with query params
        full_url = base_url
        if query_params:
            from urllib.parse import urlencode
            qs = urlencode(query_params, doseq=True)
            full_url = f"{base_url}?{qs}" if "?" not in base_url else f"{base_url}&{qs}"
        
        logger.info(f"📋 Full URL with params: {full_url}")
        
        # Injecter les données de l'endpoint
        initial_state["target_lead"] = {
            "endpoint_id": log_id,
            "url": full_url,  # FULL URL with query params!
            "base_url": base_url,  # Path only (for reference)
            "query_params": query_params,  # Original query params (for IDOR testing)
            "method": log_data.get("method", "GET"),
            "path": log_data.get("path_template", ""),
            "host": log_data.get("host", ""),
            "vulnerability_type": "IDOR",  # Default focus
            "pivotable_params": log_data.get("param_names", []),
            "confidence_score": log_data.get("heuristic_score", 0) / 100,
            "source": "dashboard",
            "has_auth": log_data.get("has_auth", False),
            "body": log_data.get("example_body", ""),
            "body_json": log_data.get("example_body_json", {}),
        }
        
        # Injecter les headers/cookies du log original pour le replay
        headers = log_data.get("example_headers") or log_data.get("example_request_headers", {})
        cookies = log_data.get("example_cookies", {})
        
        # DEBUG: Log what headers we have
        logger.info(f"📋 Session context - Headers keys: {list(headers.keys()) if headers else 'NONE'}")
        logger.info(f"📋 Session context - Cookies keys: {list(cookies.keys()) if cookies else 'NONE'}")
        
        initial_state["session_context"] = {
            "headers": headers,
            "cookies": cookies,
        }
        
        # Injecter le goal si spécifié
        if request.goal:
            initial_state["user_goal"] = request.goal
        
        initial_state["max_iterations"] = request.max_iterations or 10
        
        logger.info(f"🚀 Starting Pivot Agent for endpoint {log_id}: {log_data.get('method')} {full_url}")
        
        # Fonction async pour exécuter l'agent en background
        async def run_agent_task():
            try:
                agent = get_pivot_agent()
                
                # Exécuter le graphe
                final_state = await agent.ainvoke(initial_state)
                
                # Log la fin de session
                findings_count = len(final_state.get("confirmed_vulns", []))
                iterations = final_state.get("iteration", 0)
                agent_logger.session_end(findings_count, iterations)
                
                # Sauvegarder les findings
                for vuln in final_state.get("confirmed_vulns", []):
                    finding_id = f"pivot-{log_id}-{vuln.get('type', 'unknown')}"
                    get_redis_store().save_finding(finding_id, {
                        "type": vuln.get("type"),
                        "url": vuln.get("url"),
                        "severity": vuln.get("severity"),
                        "evidence": vuln.get("evidence"),
                        "discovered_by": "pivot_agent",
                        "source_log_id": log_id
                    })
                
                logger.info(f"Pivot agent completed for {log_id}: {findings_count} findings")
                
            except Exception as e:
                agent_logger.log_error("system", f"Agent crashed: {str(e)}")
                logger.exception(f"Pivot agent error for {log_id}")
        
        # Lancer en background
        background_tasks.add_task(run_agent_task)
        
        return {
            "status": "started",
            "log_id": log_id,
            "redis_channel": f"agent:logs:{log_id}",
            "message": f"Pivot agent started. Subscribe to Redis channel 'agent:logs:{log_id}' for live updates.",
            "target": log_data.get("url", ""),
            "goal": request.goal
        }
        
    except HTTPException:
        raise
    except ImportError as e:
        logger.error(f"Failed to import pivot_agent: {e}")
        raise HTTPException(status_code=500, detail="Pivot agent not available")
    except Exception as e:
        logger.exception("Failed to start pivot agent")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs/{log_id}")
async def get_pivot_logs(log_id: str, limit: int = 50):
    """
    Récupère l'historique des logs du pivot agent.
    
    Les logs sont stockés dans Redis: agent:logs:{log_id}:history
    Retourne aussi http_requests et llm_responses pour les panels de debug
    """
    try:
        from pivot_agent.redis_logger import AgentLogger
        
        agent_logger = AgentLogger(log_id)
        history = agent_logger.get_history(limit)
        http_requests = agent_logger.get_http_requests(50)
        llm_responses = agent_logger.get_llm_responses(20)
        
        return {
            "log_id": log_id,
            "channel": f"agent:logs:{log_id}",
            "entries": history,
            "count": len(history),
            "http_requests": http_requests,
            "llm_responses": llm_responses
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{log_id}")
async def get_pivot_status(log_id: str):
    """
    Vérifie si un pivot agent est actif pour ce log_id.
    """
    try:
        # Vérifier s'il y a des logs récents
        from pivot_agent.redis_logger import AgentLogger
        agent_logger = AgentLogger(log_id)
        history = agent_logger.get_history(5)
        
        if history:
            latest = history[0]
            age = time.time() - latest.get("timestamp", 0)
            is_active = age < 60  # Considéré actif si log < 60s
            
            return {
                "log_id": log_id,
                "is_active": is_active,
                "last_activity": latest.get("timestamp"),
                "last_node": latest.get("node"),
                "last_message": latest.get("message"),
                "iteration": latest.get("iteration", 0)
            }
        
        return {
            "log_id": log_id,
            "is_active": False,
            "message": "No pivot agent activity found"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop/{log_id}")
async def stop_pivot_agent(log_id: str):
    """
    🛑 EMERGENCY STOP - Arrête immédiatement le pivot agent.
    
    Met un flag dans Redis que l'agent vérifie à chaque itération.
    L'agent s'arrêtera à la prochaine vérification du flag.
    """
    try:
        from pivot_agent.redis_logger import stop_agent
        
        success = stop_agent(log_id)
        
        if success:
            logger.warning(f"🛑 EMERGENCY STOP activated for agent {log_id}")
            return {
                "status": "stopped",
                "log_id": log_id,
                "message": "Stop signal sent. Agent will stop at next iteration."
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to send stop signal")
            
    except ImportError as e:
        logger.error(f"Failed to import pivot_agent: {e}")
        raise HTTPException(status_code=500, detail="Pivot agent module not available")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Failed to stop pivot agent {log_id}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/logs/{log_id}")
async def clear_pivot_agent_logs(log_id: str):
    """
    🗑️ Clear all logs for a specific Pivot Agent session.
    
    Removes: thought history, HTTP requests, LLM responses, stop flag.
    """
    try:
        from pivot_agent.redis_logger import AgentLogger
        
        agent_logger = AgentLogger(log_id)
        success = agent_logger.clear_all_logs()
        
        if success:
            logger.info(f"🗑️ Cleared logs for agent {log_id}")
            return {
                "status": "cleared",
                "log_id": log_id,
                "message": "All logs cleared for this session."
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to clear logs (Redis not connected)")
            
    except ImportError as e:
        logger.error(f"Failed to import pivot_agent: {e}")
        raise HTTPException(status_code=500, detail="Pivot agent module not available")
    except Exception as e:
        logger.exception(f"Failed to clear logs for {log_id}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/logs")
async def clear_all_pivot_agent_logs():
    """
    🗑️ Clear ALL Pivot Agent logs (all sessions).
    
    ⚠️ Use with caution - this clears everything!
    """
    try:
        from pivot_agent.redis_logger import AgentLogger
        
        deleted_count = AgentLogger.clear_all_agent_logs()
        
        logger.warning(f"🗑️ Cleared ALL agent logs ({deleted_count} keys deleted)")
        return {
            "status": "cleared",
            "keys_deleted": deleted_count,
            "message": "All agent logs cleared."
        }
            
    except ImportError as e:
        logger.error(f"Failed to import pivot_agent: {e}")
        raise HTTPException(status_code=500, detail="Pivot agent module not available")
    except Exception as e:
        logger.exception("Failed to clear all logs")
        raise HTTPException(status_code=500, detail=str(e))

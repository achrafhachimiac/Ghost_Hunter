"""
Core routes: health, reset, stats.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException

from dashboard.deps import get_pipeline, get_redis_store, get_service_manager
from dashboard.utils.storage import storage

logger = logging.getLogger(__name__)

router = APIRouter(tags=["core"])


@router.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "message": "Ghost Hunter Dashboard API v2.0"}


@router.post("/api/reset")
async def reset_all_data():
    """
    RESET COMPLET - Efface toutes les données via RedisStore centralisé.
    
    Efface:
    - Endpoints
    - Security Profiles  
    - Triage History
    - Findings
    - Dedup hashes
    - Logs ghost_hunter
    
    Ne touche PAS au code/config.
    """
    redis_store = get_redis_store()
    
    try:
        # 1. RESET VIA REDISSTORE (Single Source of Truth)
        redis_results = redis_store.reset_all()
        
        results = {
            "endpoints_cleared": redis_results.get("endpoints", 0),
            "security_profiles_cleared": redis_results.get("security_profiles", 0),
            "triage_cleared": redis_results.get("triages", 0),
            "findings_cleared": redis_results.get("findings", 0),
            "dedup_cleared": redis_results.get("dedup_hashes", 0),
            "redis_keys_deleted": redis_results.get("total_keys", 0),
            "redis_cleared": redis_results.get("total_keys", 0) > 0 or redis_store.connected,
            "logs_cleared": False,
        }
        
        # 2. Vider les caches mémoire locaux
        storage["requests"] = {}
        storage["findings"] = {}
        storage["triage_history"] = []
        
        # 3. Vider les caches du pipeline
        pipeline = get_pipeline()
        if pipeline:
            if pipeline.dedup:
                pipeline.dedup._endpoints = {}
                pipeline.dedup._seen_hashes = set()
                pipeline.dedup._memory_cache = {}
            
            if hasattr(pipeline, 'requests_store'):
                pipeline.requests_store = {}
            if hasattr(pipeline, 'findings_store'):
                pipeline.findings_store = {}
            
            pipeline.stats = {
                "intercepted": 0,
                "in_scope": 0,
                "deduplicated": 0,
                "scored": 0,
                "triaged": 0,
                "findings": 0,
                "start_time": datetime.now().timestamp(),
            }
        
        # 4. Reset le fingerprinter
        try:
            from ghost_hunter.core.intelligence.security_fingerprint import reset_fingerprinter
            reset_fingerprinter()
        except Exception as e:
            logger.warning(f"Fingerprinter reset warning: {e}")
        
        # 5. Effacer les fichiers JSON legacy
        try:
            profiles_dir = Path("data/security_profiles")
            if profiles_dir.exists():
                for f in profiles_dir.glob("*.json"):
                    f.unlink()
        except Exception as e:
            logger.warning(f"JSON cleanup warning: {e}")
        
        # 6. Effacer les logs
        try:
            log_file = Path("data/logs/ghost_hunter.log")
            if log_file.exists():
                log_file.write_text("")
                results["logs_cleared"] = True
        except Exception as e:
            logger.error(f"Log clear error: {e}")
        
        logger.info(f"🗑️ RESET COMPLETE via RedisStore: {results}")
        
        return {
            "status": "ok",
            "message": "All data cleared via RedisStore",
            **results
        }
        
    except Exception as e:
        logger.exception("Reset error")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/stats")
async def get_stats():
    """Retourne les statistiques complètes (depuis le storage du dashboard)."""
    # Compter depuis le storage local (rempli par le proxy)
    requests = storage["requests"]
    total_intercepted = len(requests)
    total_in_scope = sum(1 for r in requests.values() if r.get("score", 0) > 0)
    total_analyzed = sum(1 for r in requests.values() if r.get("triage"))
    interesting = sum(1 for r in requests.values() 
                    if r.get("triage", {}).get("interesting", False))
    
    # Charger la config pour le nom de la cible
    target_name = "Unknown"
    try:
        scope_file = Path("config/scope.json")
        if scope_file.exists():
            with open(scope_file) as f:
                scope = json.load(f)
                target_name = scope.get("target", {}).get("name", "Unknown")
    except:
        pass
    
    # Knowledge Base status
    kb_status = {"available": False, "hacktricks": 0, "payloads": 0, "nuclei": 0}
    try:
        from ghost_hunter.core.intelligence import get_knowledge_loader
        kb = get_knowledge_loader()
        if kb.is_available:
            kb_status["available"] = True
            kb_status["hacktricks"] = len(list(kb.knowledge_dir.glob("hacktricks/**/*.md")))
            kb_status["payloads"] = len(list(kb.knowledge_dir.glob("payloads/**/*")))
            kb_status["nuclei"] = len(list(kb.knowledge_dir.glob("nuclei-templates/**/*.yaml")))
    except:
        pass
    
    # Nuclei Scanner status
    nuclei_status = {"available": False, "scanned": 0, "findings": 0, "findings_by_severity": {}}
    try:
        from ghost_hunter.core.scanner import get_nuclei_scanner
        scanner = get_nuclei_scanner()
        stats = scanner.get_stats()
        nuclei_status = {
            "available": stats.get("available", False),
            "scanned": stats.get("total_scanned", 0),
            "findings": stats.get("total_findings", 0),
            "findings_by_severity": stats.get("findings_by_severity", {}),
            "running": stats.get("running", False),
            "queue_size": stats.get("queue_size", 0)
        }
    except:
        pass
    
    # Count findings by severity from storage
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in storage.get("findings", {}).values():
        sev = finding.get("severity", "info").lower()
        if sev in findings_by_severity:
            findings_by_severity[sev] += 1
    
    return {
        "session_id": "main",
        "target": target_name,
        "started_at": storage["started_at"],
        "duration_seconds": datetime.now().timestamp() - storage["started_at"],
        "total_intercepted": total_intercepted,
        "total_in_scope": total_in_scope,
        "total_analyzed": total_analyzed,
        "total_tested": interesting,
        "findings_by_severity": findings_by_severity,
        "tokens_used": 0,
        "estimated_cost": 0.0,
        "knowledge_base": kb_status,
        "nuclei_scanner": nuclei_status,
    }

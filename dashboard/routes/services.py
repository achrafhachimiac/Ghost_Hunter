"""
Services management routes.
"""

import logging

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks

from dashboard.deps import get_service_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/services", tags=["services"])


@router.get("/health")
async def get_health():
    """Retourne l'état de santé de tous les services."""
    manager = get_service_manager()
    if manager:
        return manager.get_health()
    return {
        "healthy": False,
        "running_services": 0,
        "total_services": 5,
        "target": "Service manager not available",
        "services": {}
    }


@router.get("/{service_name}/logs")
async def get_service_logs(
    service_name: str,
    limit: int = Query(100, ge=1, le=500)
):
    """Retourne les logs d'un service."""
    manager = get_service_manager()
    if manager:
        return manager.get_service_logs(service_name, limit)
    return []


@router.post("/start-all")
async def start_all_services(background_tasks: BackgroundTasks):
    """Démarre tous les services."""
    manager = get_service_manager()
    if manager:
        # Exécuter en background pour ne pas bloquer
        background_tasks.add_task(manager.start_all)
        return {"status": "ok", "message": "Starting all services..."}
    raise HTTPException(status_code=500, detail="Service manager not available")


@router.post("/stop-all")
async def stop_all_services():
    """Arrête tous les services."""
    manager = get_service_manager()
    if manager:
        manager.stop_all()
        return {"status": "ok", "message": "All services stopped"}
    raise HTTPException(status_code=500, detail="Service manager not available")


@router.post("/{service_name}/start")
async def start_service(service_name: str, background_tasks: BackgroundTasks):
    """Démarre un service spécifique."""
    manager = get_service_manager()
    if manager:
        starters = {
            "redis": manager.start_redis,
            "proxy": manager.start_proxy,
            "dashboard": manager.start_dashboard,
            "oob": manager.start_oob_listener,
            "pipeline": manager.start_pipeline_worker,
        }
        if service_name in starters:
            background_tasks.add_task(starters[service_name])
            return {"status": "ok", "message": f"Starting {service_name}..."}
        raise HTTPException(status_code=404, detail=f"Unknown service: {service_name}")
    raise HTTPException(status_code=500, detail="Service manager not available")


@router.post("/{service_name}/stop")
async def stop_service(service_name: str):
    """Arrête un service spécifique."""
    manager = get_service_manager()
    if manager:
        result = manager.stop_service(service_name)
        return {"status": "ok" if result else "error", "service": service_name}
    raise HTTPException(status_code=500, detail="Service manager not available")


@router.post("/{service_name}/restart")
async def restart_service(service_name: str, background_tasks: BackgroundTasks):
    """Redémarre un service."""
    manager = get_service_manager()
    if manager:
        background_tasks.add_task(manager.restart_service, service_name)
        return {"status": "ok", "message": f"Restarting {service_name}..."}
    raise HTTPException(status_code=500, detail="Service manager not available")

"""
Config routes - Scope and scan configuration.

Routes:
- GET /api/config/scope - Get scope configuration
- PUT /api/config/scope - Update scope configuration
- GET /api/scan/status - Get scan status
- POST /api/scan/start - Start scan
- POST /api/scan/stop - Stop scan
- DELETE /api/clear - Clear all data
"""

from datetime import datetime
from typing import Dict, Any
from pathlib import Path
import json
import os

import yaml

from fastapi import APIRouter, HTTPException
import logging

from dashboard.deps import get_pipeline
from dashboard.utils.storage import storage
from dashboard.schemas import ScanConfig

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["config"])

# Config directory
config_dir = Path("config")


@router.get("/config/scope")
async def get_scope():
    """Retourne la configuration du scope."""
    scope_file = config_dir / "scope.json"
    if scope_file.exists():
        with open(scope_file) as f:
            return json.load(f)
    return {"in_scope": [], "out_of_scope": [], "target": {}}


@router.put("/config/scope")
async def update_scope(scope: Dict[str, Any]):
    """Met à jour la configuration du scope."""
    scope_file = config_dir / "scope.json"
    with open(scope_file, "w") as f:
        json.dump(scope, f, indent=2)
    return {"status": "ok"}


@router.get("/config/api-keys")
async def get_api_keys():
    """Retourne la configuration locale des clés API."""
    api_keys_file = config_dir / "api_keys.yaml"

    config: Dict[str, Any] = {}
    if api_keys_file.exists():
        with open(api_keys_file) as f:
            config = yaml.safe_load(f) or {}

    # Fallback environment variables if local file is missing/incomplete
    config.setdefault("groq", {})
    config.setdefault("openrouter", {})
    config.setdefault("openai", {})

    config["groq"].setdefault("api_key", os.getenv("GROQ_API_KEY", ""))
    config["openrouter"].setdefault("api_key", os.getenv("OPENROUTER_API_KEY", ""))
    config["openai"].setdefault("api_key", os.getenv("OPENAI_API_KEY", ""))

    return config


@router.put("/config/api-keys")
async def update_api_keys(api_keys: Dict[str, Any]):
    """Met à jour la configuration locale des clés API."""
    api_keys_file = config_dir / "api_keys.yaml"

    existing: Dict[str, Any] = {}
    if api_keys_file.exists():
        with open(api_keys_file) as f:
            existing = yaml.safe_load(f) or {}

    # Merge while preserving optional model settings already present
    for provider in ["groq", "openrouter", "openai"]:
        existing.setdefault(provider, {})
        incoming = api_keys.get(provider, {}) or {}
        if "api_key" in incoming:
            existing[provider]["api_key"] = incoming.get("api_key", "")

    with open(api_keys_file, "w") as f:
        yaml.safe_dump(existing, f, sort_keys=False)

    return {"status": "ok", "message": "API keys updated"}


@router.get("/scan/status")
async def scan_status():
    """Retourne le statut du scan."""
    return {
        "active": storage.get("scan_active", False),
        "started_at": storage.get("started_at"),
    }


@router.post("/scan/start")
async def start_scan(config: ScanConfig):
    """Démarre un scan."""
    storage["scan_active"] = True
    storage["started_at"] = datetime.now().timestamp()
    return {"status": "ok", "message": "Scan started"}


@router.post("/scan/stop")
async def stop_scan():
    """Arrête le scan."""
    storage["scan_active"] = False
    return {"status": "ok", "message": "Scan stopped"}


@router.delete("/clear")
async def clear_all():
    """Efface toutes les données."""
    storage["requests"].clear()
    storage["findings"].clear()
    storage["scan_active"] = False
    
    # Clear pipeline aussi
    try:
        pipeline = get_pipeline()
        if pipeline:
            pipeline.requests_store.clear()
            pipeline.findings_store.clear()
    except:
        pass
    
    return {"status": "ok", "message": "All data cleared"}

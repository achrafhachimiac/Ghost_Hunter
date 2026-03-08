"""
Security routes - WAF/CDN/Anti-bot detection and security profiles.

Routes:
- GET /api/security - Get all security profiles
- GET /api/security/{domain} - Get security profile for domain
- GET /api/security/{domain}/recommendations - Get evasion recommendations
- POST /api/security/scan/domain - Scan single domain
- POST /api/security/scan/scope - Scan all scope domains
"""

from typing import Dict, Any, Optional, List
from pathlib import Path
import json

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security", tags=["security"])


class ScanDomainRequest(BaseModel):
    """Request pour scanner un domaine."""
    domain: str
    protocols: Optional[List[str]] = None  # ["http", "https"]


@router.get("")
async def get_all_security_profiles():
    """Récupère tous les profils de sécurité détectés."""
    try:
        from ghost_hunter.core.intelligence import get_fingerprinter
        fingerprinter = get_fingerprinter()
        return {
            "profiles": fingerprinter.get_profiles_summary(),
            "total": len(fingerprinter.get_all_profiles())
        }
    except Exception as e:
        logger.exception("Failed to get security profiles")
        return {"profiles": [], "total": 0, "error": str(e)}


@router.get("/{domain}")
async def get_security_profile(domain: str):
    """Récupère le profil de sécurité détaillé d'un domaine."""
    try:
        from ghost_hunter.core.intelligence import get_fingerprinter
        fingerprinter = get_fingerprinter()
        profile = fingerprinter.get_profile(domain)
        
        if profile:
            return profile.to_dict()
        
        raise HTTPException(status_code=404, detail=f"No security profile for {domain}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{domain}/recommendations")
async def get_evasion_recommendations(domain: str):
    """Récupère les recommandations d'évasion pour un domaine."""
    try:
        from ghost_hunter.core.intelligence import get_fingerprinter
        fingerprinter = get_fingerprinter()
        profile = fingerprinter.get_profile(domain)
        
        if not profile:
            return {"domain": domain, "recommendations": [], "message": "No profile yet"}
        
        security_profile = profile.to_security_profile()
        
        return {
            "domain": domain,
            "waf_detected": security_profile.waf_detected,
            "waf_provider": security_profile.waf_provider,
            "recommendations": security_profile.recommended_evasion,
            "rate_limit_detected": security_profile.rate_limit_detected,
            "auth_type": security_profile.auth_type,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/domain")
async def scan_single_domain(request: ScanDomainRequest):
    """
    Scan activement un domaine pour détecter WAF, CDN, anti-bot, etc.
    
    Envoie une requête HTTP et HTTPS vers le domaine et analyse les headers/cookies.
    """
    try:
        from ghost_hunter.core.intelligence import get_fingerprinter
        fingerprinter = get_fingerprinter()
        
        result = await fingerprinter.scan_domain(
            request.domain,
            protocols=request.protocols
        )
        return result
    except Exception as e:
        logger.exception(f"Failed to scan domain {request.domain}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/scope")
async def scan_scope_domains(background_tasks: BackgroundTasks):
    """
    Scan tous les domaines du scope (HTTP et HTTPS).
    
    Extrait les domaines de in_scope dans scope.json et les scanne
    pour détecter les protections de sécurité.
    """
    try:
        # Charger le scope
        scope_file = Path("config/scope.json")
        if not scope_file.exists():
            raise HTTPException(status_code=404, detail="scope.json not found")
        
        scope_config = json.loads(scope_file.read_text())
        
        from ghost_hunter.core.intelligence import get_fingerprinter
        fingerprinter = get_fingerprinter()
        
        result = await fingerprinter.scan_scope_domains(scope_config)
        
        return {
            "status": "completed",
            "program": scope_config.get("program", "Unknown"),
            **result
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to scan scope domains")
        raise HTTPException(status_code=500, detail=str(e))

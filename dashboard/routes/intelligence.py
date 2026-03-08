"""
Intelligence routes - Knowledge base, OSINT, and tech profiling.

Routes:
- GET /api/intelligence/status - Get intelligence modules status
- GET /api/intelligence/knowledge/search - Search knowledge base
- GET /api/intelligence/knowledge/vuln-context/{vuln_type} - Get vuln context
- GET /api/intelligence/knowledge/patterns - Get business logic patterns
- POST /api/intelligence/knowledge/match-patterns - Match request against patterns
- GET /api/intelligence/knowledge/wordlists - List wordlists
- GET /api/intelligence/osint/subdomains/{domain} - Enumerate subdomains
- GET /api/intelligence/osint/host/{ip} - Get host info from Shodan
- GET /api/intelligence/fingerprint - Fingerprint URL technologies
- GET /api/intelligence/attack-surface - Analyze attack surface
"""

from typing import Dict, Any, Optional

from fastapi import APIRouter, HTTPException, Query
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/intelligence", tags=["intelligence"])


@router.get("/status")
async def get_intelligence_status():
    """Retourne le status des modules d'intelligence."""
    result = {
        "knowledge_base": {"available": False},
        "osint": {"available": False},
        "tech_profiler": {"available": True}
    }
    
    try:
        from ghost_hunter.core.intelligence import get_knowledge_loader
        kb = get_knowledge_loader()
        result["knowledge_base"] = kb.get_status()
    except Exception as e:
        result["knowledge_base"]["error"] = str(e)
    
    try:
        from ghost_hunter.core.intelligence import get_osint_collector
        osint = get_osint_collector()
        result["osint"] = osint.get_status()
    except Exception as e:
        result["osint"]["error"] = str(e)
    
    return result


@router.get("/knowledge/search")
async def search_knowledge(
    query: str = Query(..., min_length=2),
    source: str = Query("hacktricks", pattern="^(hacktricks|payloads|nuclei)$"),
    limit: int = Query(10, ge=1, le=50)
):
    """Recherche dans la Knowledge Base."""
    try:
        from ghost_hunter.core.intelligence import get_knowledge_loader
        kb = get_knowledge_loader()
        
        if source == "hacktricks":
            entries = kb.search_hacktricks(query, max_results=limit)
            return [{
                "title": e.title,
                "category": e.category,
                "source": e.source,
                "relevance": e.relevance_score,
                "file_path": e.file_path,
                "content_preview": e.content[:500] if e.content else ""
            } for e in entries]
        
        elif source == "payloads":
            payloads = kb.get_payloads(query, limit=limit)
            return {"vuln_type": query, "payloads": payloads}
        
        elif source == "nuclei":
            templates = kb.search_nuclei_templates(query, max_results=limit)
            return templates
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/knowledge/vuln-context/{vuln_type}")
async def get_vuln_context(vuln_type: str):
    """Récupère le contexte complet pour un type de vulnérabilité."""
    try:
        from ghost_hunter.core.intelligence import get_knowledge_loader
        kb = get_knowledge_loader()
        context = kb.get_vuln_context(vuln_type)
        
        return {
            "vuln_type": context.vuln_type,
            "description": context.description,
            "techniques": context.techniques[:3],  # Limiter la taille
            "payloads": context.payloads[:20],
            "test_cases": context.test_cases,
            "references": context.references,
            "cheatsheet_available": context.cheatsheet is not None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/knowledge/patterns")
async def get_patterns(category: Optional[str] = None):
    """Récupère les patterns business logic."""
    try:
        from ghost_hunter.core.intelligence import get_knowledge_loader
        kb = get_knowledge_loader()
        
        if category:
            return kb.get_patterns(category)
        return kb.get_all_patterns()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/knowledge/match-patterns")
async def match_patterns(request_data: Dict[str, Any]):
    """Match une requête contre les patterns connus."""
    try:
        from ghost_hunter.core.intelligence import get_knowledge_loader
        kb = get_knowledge_loader()
        matches = kb.match_patterns(request_data)
        return {"matches": matches}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/knowledge/wordlists")
async def list_wordlists():
    """Liste les wordlists disponibles."""
    try:
        from ghost_hunter.core.intelligence import get_knowledge_loader
        kb = get_knowledge_loader()
        return kb.list_wordlists()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/osint/subdomains/{domain}")
async def enumerate_subdomains(
    domain: str,
    quick: bool = Query(True, description="Quick mode (crt.sh only)")
):
    """Énumère les subdomains d'un domaine."""
    try:
        from ghost_hunter.core.intelligence import get_osint_collector
        collector = get_osint_collector()
        
        if quick:
            result = await collector.quick_recon(domain)
            return result
        else:
            intel = await collector.collect_domain_intel(domain)
            return {
                "domain": intel.domain,
                "subdomain_count": len(intel.subdomains),
                "subdomains": [s.subdomain for s in intel.subdomains],
                "sources": list(set(s.source for s in intel.subdomains)),
                "collected_at": intel.collected_at
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/osint/host/{ip}")
async def get_host_info(ip: str):
    """Récupère les informations Shodan sur un host."""
    try:
        from ghost_hunter.core.intelligence import get_osint_collector
        collector = get_osint_collector()
        
        host = await collector.get_host_details(ip)
        if host:
            return {
                "ip": host.ip,
                "hostnames": host.hostnames,
                "ports": host.ports,
                "os": host.os,
                "org": host.org,
                "country": host.country,
                "services": host.services,
                "vulns": host.vulns
            }
        raise HTTPException(status_code=404, detail="Host not found in Shodan")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/fingerprint")
async def fingerprint_url(url: str = Query(..., pattern="^https?://")):
    """Fingerprint les technologies d'une URL."""
    try:
        from ghost_hunter.core.intelligence import get_tech_profiler
        profiler = get_tech_profiler()
        profile = await profiler.profile(url)
        return profile.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-surface")
async def get_attack_surface(url: str = Query(..., pattern="^https?://")):
    """Analyse la surface d'attaque d'une URL."""
    try:
        from ghost_hunter.core.intelligence import get_tech_profiler
        profiler = get_tech_profiler()
        surface = await profiler.get_attack_surface(url)
        return surface
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

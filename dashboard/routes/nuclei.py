"""
Nuclei and Knowledge Base status routes.
"""

import logging
from pathlib import Path

from fastapi import APIRouter

logger = logging.getLogger(__name__)

router = APIRouter(tags=["nuclei"])


@router.get("/api/nuclei")
async def get_nuclei_status():
    """Retourne le statut et les findings du scanner Nuclei."""
    try:
        from ghost_hunter.core.scanner import get_nuclei_scanner
        scanner = get_nuclei_scanner()
        
        return {
            "available": scanner.is_available,
            "stats": scanner.get_stats(),
            "findings": [
                {
                    "template_id": f.template_id,
                    "name": f.name,
                    "severity": f.severity,
                    "url": f.url,
                    "matched_at": f.matched_at,
                    "description": f.description,
                    "timestamp": f.timestamp
                }
                for f in scanner.get_findings()
            ]
        }
    except Exception as e:
        return {"available": False, "error": str(e), "findings": []}


@router.get("/api/knowledge")
async def get_knowledge_status():
    """Retourne le statut détaillé de la Knowledge Base."""
    try:
        from ghost_hunter.core.intelligence import get_knowledge_loader
        kb = get_knowledge_loader()
        
        if not kb.is_available:
            return {"available": False, "message": "Knowledge Base not found"}
        
        return {
            "available": True,
            "path": str(kb.knowledge_dir),
            "sources": {
                "hacktricks": {
                    "files": len(list(kb.knowledge_dir.glob("hacktricks/**/*.md"))),
                    "description": "Pentesting techniques & methodologies"
                },
                "payloads": {
                    "files": len(list(kb.knowledge_dir.glob("payloads/**/*"))),
                    "description": "Attack payloads for various vulns"
                },
                "nuclei": {
                    "files": len(list(kb.knowledge_dir.glob("nuclei-templates/**/*.yaml"))),
                    "description": "Nuclei scanning templates"
                }
            },
            "vuln_types_supported": list(kb.VULN_MAPPING.keys())
        }
    except Exception as e:
        return {"available": False, "error": str(e)}

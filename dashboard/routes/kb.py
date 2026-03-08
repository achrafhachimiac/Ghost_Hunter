"""
Knowledge Base (RAG) routes - Sync, search, and manage knowledge base.

Routes:
- GET /api/kb/status - Get KB status and chunk counts
- POST /api/kb/sync - Sync a knowledge base source
- POST /api/kb/sync-disclosures - Sync HackerOne disclosures
- GET /api/kb/search - Search the knowledge base
- POST /api/kb/add-report - Add personal report
- POST /api/kb/rebuild - Rebuild entire KB
"""

from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Query
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/kb", tags=["knowledge-base"])


@router.get("/status")
async def get_kb_status():
    """
    Get Knowledge Base status.
    
    Returns chunk counts, sync times, and health info.
    """
    try:
        from ghost_hunter.cli.kb_commands import get_kb_status as get_status
        status = get_status()
        return status.to_dict()
    except Exception as e:
        logger.exception("Failed to get KB status")
        return {
            "total_chunks": 0,
            "chunks_by_source": {},
            "last_sync": {},
            "vector_store_healthy": False,
            "errors": [str(e)]
        }


@router.post("/sync")
async def sync_kb(source: str = "all", force: bool = False):
    """
    Sync a knowledge base source.
    
    Args:
        source: Source to sync (cve, hacktricks, nuclei, personal, disclosures, all)
        force: Force re-sync even if recently synced
    """
    try:
        from ghost_hunter.cli.kb_commands import sync_source
        
        if source == "all":
            # Sync all sources
            results = {}
            total_chunks = 0
            errors = []
            
            for src in ['cve', 'hacktricks', 'nuclei', 'personal', 'disclosures']:
                result = sync_source(src, force=force)
                results[src] = {
                    'success': result['success'],
                    'chunks_added': result['chunks_added']
                }
                total_chunks += result['chunks_added']
                errors.extend(result['errors'])
            
            return {
                "source": "all",
                "success": len(errors) == 0,
                "results": results,
                "total_chunks_added": total_chunks,
                "errors": errors
            }
        else:
            result = sync_source(source, force=force)
            return result
            
    except Exception as e:
        logger.exception(f"Failed to sync KB source: {source}")
        return {
            "source": source,
            "success": False,
            "chunks_added": 0,
            "errors": [str(e)]
        }


@router.post("/sync-disclosures")
async def sync_kb_disclosures(
    force: bool = False,
    min_upvotes: int = Query(10, ge=0, description="Minimum upvotes filter"),
    max_reports: int = Query(5000, ge=100, le=50000, description="Max reports to process")
):
    """
    Sync HackerOne public disclosures with custom filters.
    
    Args:
        force: Force re-sync even if recently synced
        min_upvotes: Minimum upvotes to include (quality filter)
        max_reports: Maximum number of reports to process
    """
    try:
        from ghost_hunter.cli.kb_commands import sync_disclosures
        
        result = sync_disclosures(
            force=force,
            min_upvotes=min_upvotes,
            max_reports=max_reports
        )
        return result
            
    except Exception as e:
        logger.exception("Failed to sync disclosures")
        return {
            "source": "disclosures",
            "success": False,
            "chunks_added": 0,
            "errors": [str(e)]
        }


@router.get("/search")
async def search_kb(q: str = Query(..., description="Search query"), limit: int = Query(10, ge=1, le=100)):
    """
    Search the knowledge base.
    
    Args:
        q: Search query string
        limit: Maximum number of results (1-100)
    """
    try:
        from ghost_hunter.cli.kb_commands import search_kb as kb_search
        result = kb_search(q, limit=limit)
        return result
    except Exception as e:
        logger.exception(f"Failed to search KB")
        return {
            "query": q,
            "results": [],
            "total": 0,
            "errors": [str(e)]
        }


@router.post("/add-report")
async def add_kb_report(path: str):
    """
    Add a personal report to the knowledge base.
    
    Args:
        path: Path to the markdown report file
    """
    try:
        from ghost_hunter.cli.kb_commands import add_report
        result = add_report(path)
        return result
    except Exception as e:
        logger.exception(f"Failed to add report: {path}")
        return {
            "file": path,
            "success": False,
            "chunks_added": 0,
            "errors": [str(e)]
        }


@router.post("/rebuild")
async def rebuild_kb():
    """
    Rebuild the entire knowledge base from scratch.
    
    Warning: This will clear and re-sync all sources.
    """
    try:
        from ghost_hunter.cli.kb_commands import rebuild_kb as kb_rebuild
        result = kb_rebuild()
        return result
    except Exception as e:
        logger.exception("Failed to rebuild KB")
        return {
            "success": False,
            "total_chunks": 0,
            "chunks_by_source": {},
            "errors": [str(e)]
        }

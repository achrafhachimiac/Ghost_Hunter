"""
Ghost-Hunter Knowledge Base CLI Commands
=========================================
Commands for managing the RAG knowledge base.

Usage:
    python -m ghost_hunter.cli.kb_commands status
    python -m ghost_hunter.cli.kb_commands sync-cve
    python -m ghost_hunter.cli.kb_commands sync-hacktricks
    python -m ghost_hunter.cli.kb_commands add-report <path>
    python -m ghost_hunter.cli.kb_commands search <query>
    python -m ghost_hunter.cli.kb_commands rebuild
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)

# Constants
DEFAULT_SEARCH_LIMIT = 10


@dataclass
class KBStatus:
    """Knowledge Base status information."""
    total_chunks: int
    chunks_by_source: Dict[str, int]
    last_sync: Dict[str, Optional[str]]  # source -> ISO timestamp or None
    vector_store_healthy: bool
    errors: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


def get_kb_status() -> KBStatus:
    """
    Get the current status of the knowledge base.
    
    Returns:
        KBStatus with chunk counts, sync times, and health info
    """
    errors = []
    chunks_by_source = {}
    last_sync = {}
    total_chunks = 0
    healthy = False
    
    try:
        from ghost_hunter.core.rag.vector_store import get_vector_store
        store = get_vector_store()
        
        if store is None:
            errors.append("Vector store not initialized")
            return KBStatus(
                total_chunks=0,
                chunks_by_source={},
                last_sync={},
                vector_store_healthy=False,
                errors=errors
            )
        
        healthy = True
        
        # Get all chunks and count by source
        try:
            # Use the stats() method and count()
            if hasattr(store, 'stats'):
                stats = store.stats()
                total_chunks = stats.get('total_chunks', store.count())
            else:
                total_chunks = store.count()
            
            # For chunks_by_source, we'd need to query - skip for now
            chunks_by_source = {"total": total_chunks}
        except Exception as e:
            errors.append(f"Error counting chunks: {e}")
        
        # Get last sync times - simplified (skip cache check)
        try:
            last_sync = {}  # Could be loaded from a metadata file if needed
        except Exception as e:
            errors.append(f"Error getting sync times: {e}")
            
    except ImportError as e:
        errors.append(f"RAG module not available: {e}")
    except Exception as e:
        errors.append(f"Unexpected error: {e}")
    
    return KBStatus(
        total_chunks=total_chunks,
        chunks_by_source=chunks_by_source,
        last_sync=last_sync,
        vector_store_healthy=healthy,
        errors=errors
    )


def sync_source(source: str, force: bool = False) -> Dict[str, Any]:
    """
    Synchronize a specific source.
    
    Args:
        source: Source name ('cve', 'hacktricks', 'nuclei', 'personal')
        force: Force re-sync even if recently synced
        
    Returns:
        Dict with sync results
    """
    result = {
        'source': source,
        'success': False,
        'chunks_added': 0,
        'errors': []
    }
    
    try:
        from ghost_hunter.core.rag.vector_store import get_vector_store
        store = get_vector_store()
        
        if store is None:
            result['errors'].append("Vector store not initialized")
            return result
        
        # Map source names to ingestors
        source_map = {
            'cve': 'nvd',
            'nvd': 'nvd',
            'hacktricks': 'hacktricks',
            'nuclei': 'nuclei',
            'personal': 'personal',
            'disclosures': 'disclosures',
            'h1': 'disclosures',
            'hackerone': 'disclosures'
        }
        
        source_key = source_map.get(source.lower())
        if not source_key:
            result['errors'].append(f"Unknown source: {source}")
            return result
        
        # Import and run the appropriate ingestor
        chunks = []
        
        if source_key == 'nvd':
            from ghost_hunter.core.rag.ingestors.nvd import NVDIngestor
            from ghost_hunter.core.rag.ingestors.base import IngestorConfig
            config = IngestorConfig(name="nvd", enabled=True)
            ingestor = NVDIngestor(config)
            chunks = list(ingestor.ingest())
            
        elif source_key == 'hacktricks':
            from ghost_hunter.core.rag.ingestors.hacktricks import HackTricksIngestor
            from ghost_hunter.core.rag.ingestors.base import IngestorConfig
            config = IngestorConfig(name="hacktricks", enabled=True)
            ingestor = HackTricksIngestor(config)
            chunks = list(ingestor.ingest())
            
        elif source_key == 'nuclei':
            from ghost_hunter.core.rag.ingestors.nuclei import NucleiTemplatesIngestor
            ingestor = NucleiTemplatesIngestor()
            chunks = list(ingestor.ingest())
            
        elif source_key == 'personal':
            from ghost_hunter.core.rag.ingestors.personal import PersonalReportsIngestor
            from ghost_hunter.core.rag.ingestors.base import IngestorConfig
            config = IngestorConfig(name="personal", enabled=True)
            ingestor = PersonalReportsIngestor(config)
            chunks = list(ingestor.ingest())
        
        elif source_key == 'disclosures':
            # Use sync_disclosures with default params
            disc_result = sync_disclosures(force=force)
            return disc_result
        
        if chunks:
            store.add_chunks(chunks)
            result['chunks_added'] = len(chunks)
            result['success'] = True
            logger.info(f"Synced {source}: {len(chunks)} chunks added")
        else:
            result['success'] = True
            result['chunks_added'] = 0
            logger.info(f"Synced {source}: no new chunks")
            
    except ImportError as e:
        result['errors'].append(f"Ingestor not available: {e}")
    except Exception as e:
        result['errors'].append(f"Sync error: {e}")
        logger.error(f"Error syncing {source}: {e}")
    
    return result


def sync_disclosures(
    force: bool = False,
    min_upvotes: int = 10,
    max_reports: int = 5000,
    vuln_types: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Synchronize HackerOne public disclosures.
    
    Args:
        force: Force re-sync even if recently synced
        min_upvotes: Minimum upvotes to include a report (quality filter)
        max_reports: Maximum number of reports to process
        vuln_types: Optional list of vuln types to filter (e.g., ['xss', 'sqli'])
        
    Returns:
        Dict with sync results
    """
    result = {
        'source': 'disclosures',
        'success': False,
        'chunks_added': 0,
        'reports_processed': 0,
        'errors': []
    }
    
    try:
        from ghost_hunter.core.rag.vector_store import get_vector_store
        from ghost_hunter.core.rag.ingestors.disclosures import HackerOneDisclosureIngestor
        from ghost_hunter.core.rag.ingestors.base import IngestorConfig
        
        store = get_vector_store()
        
        if store is None:
            result['errors'].append("Vector store not initialized")
            return result
        
        # Build config with custom params
        params = {
            "min_upvotes": min_upvotes,
            "max_reports": max_reports,
            "enrich": False  # Don't fetch full reports (expensive)
        }
        if vuln_types:
            params["vuln_types"] = vuln_types
            
        config = IngestorConfig(
            name="disclosures",
            enabled=True,
            params=params
        )
        
        ingestor = HackerOneDisclosureIngestor(config)
        
        # Sync CSV from GitHub
        logger.info(f"Syncing HackerOne disclosures (min_upvotes={min_upvotes}, max={max_reports})")
        ingestor.sync()
        
        # Get stats after sync
        stats = ingestor.get_stats()
        result['reports_processed'] = stats.get('total_reports', 0)
        
        # Ingest chunks
        chunks = list(ingestor.ingest())
        
        if chunks:
            store.add_chunks(chunks)
            result['chunks_added'] = len(chunks)
            result['success'] = True
            logger.info(f"Synced disclosures: {len(chunks)} chunks added from {result['reports_processed']} reports")
        else:
            result['success'] = True
            result['chunks_added'] = 0
            logger.info("Synced disclosures: no new chunks")
            
    except ImportError as e:
        result['errors'].append(f"Disclosure ingestor not available: {e}")
    except Exception as e:
        result['errors'].append(f"Sync error: {e}")
        logger.error(f"Error syncing disclosures: {e}")
    
    return result


def add_report(file_path: str) -> Dict[str, Any]:
    """
    Add a personal report to the knowledge base.
    
    Args:
        file_path: Path to the markdown report file
        
    Returns:
        Dict with ingestion results
    """
    result = {
        'file': file_path,
        'success': False,
        'chunks_added': 0,
        'errors': []
    }
    
    path = Path(file_path)
    if not path.exists():
        result['errors'].append(f"File not found: {file_path}")
        return result
    
    if path.suffix.lower() not in ['.md', '.markdown']:
        result['errors'].append(f"Not a markdown file: {file_path}")
        return result
    
    try:
        from ghost_hunter.core.rag.vector_store import get_vector_store
        from ghost_hunter.core.rag.ingestors.personal import PersonalReportsIngestor
        
        store = get_vector_store()
        if store is None:
            result['errors'].append("Vector store not initialized")
            return result
        
        ingestor = PersonalReportsIngestor()
        chunks = ingestor.ingest_file(path)
        
        if chunks:
            store.add_chunks(chunks)
            result['chunks_added'] = len(chunks)
            result['success'] = True
            logger.info(f"Added report {path.name}: {len(chunks)} chunks")
        else:
            result['success'] = True
            logger.info(f"Added report {path.name}: no chunks generated")
            
    except Exception as e:
        result['errors'].append(f"Ingestion error: {e}")
        logger.error(f"Error adding report {file_path}: {e}")
    
    return result


def search_kb(query: str, limit: int = DEFAULT_SEARCH_LIMIT) -> Dict[str, Any]:
    """
    Search the knowledge base.
    
    Args:
        query: Search query string
        limit: Maximum number of results
        
    Returns:
        Dict with search results
    """
    result = {
        'query': query,
        'results': [],
        'total': 0,
        'errors': []
    }
    
    if not query.strip():
        result['errors'].append("Empty query")
        return result
    
    try:
        from ghost_hunter.core.rag.vector_store import get_vector_store
        
        store = get_vector_store()
        if store is None:
            result['errors'].append("Vector store not available")
            return result
        
        # Use store's search method if available, else query_sync
        if hasattr(store, 'search'):
            raw_results = store.search(query, top_k=limit)
        elif hasattr(store, 'query_sync'):
            raw_results = store.query_sync(query, top_k=limit)
        else:
            # Fallback: get all chunks and filter (basic)
            all_chunks = store.get_all_chunks() if hasattr(store, 'get_all_chunks') else []
            query_lower = query.lower()
            raw_results = [
                (chunk, 0.5)  # Basic relevance score
                for chunk in all_chunks
                if query_lower in chunk.content.lower()
            ][:limit]
        
        results = []
        for item in raw_results:
            # Handle both (chunk, score) and chunk-only returns
            if isinstance(item, tuple):
                chunk, score = item
            else:
                chunk = item
                score = chunk.metadata.get('score', 0) if hasattr(chunk, 'metadata') else 0
            
            content = chunk.content if hasattr(chunk, 'content') else str(chunk)
            metadata = chunk.metadata if hasattr(chunk, 'metadata') else {}
            
            results.append({
                'content': content[:500] + '...' if len(content) > 500 else content,
                'source': metadata.get('source', 'unknown'),
                'score': score,
                'metadata': {
                    k: v for k, v in metadata.items() 
                    if k not in ['content', 'embedding']
                }
            })
        
        result['results'] = results
        result['total'] = len(results)
        
    except ImportError as e:
        result['errors'].append(f"RAG module not available: {e}")
    except Exception as e:
        result['errors'].append(f"Search error: {e}")
        logger.error(f"Error searching KB: {e}")
    
    return result


def rebuild_kb() -> Dict[str, Any]:
    """
    Rebuild the entire knowledge base from scratch.
    
    Returns:
        Dict with rebuild results
    """
    result = {
        'success': False,
        'total_chunks': 0,
        'chunks_by_source': {},
        'errors': []
    }
    
    try:
        from ghost_hunter.core.rag.vector_store import get_vector_store
        
        # Clear existing store
        store = get_vector_store()
        if store and hasattr(store, 'clear'):
            store.clear()
            logger.info("Cleared existing vector store")
        
        # Re-sync all sources
        sources = ['nvd', 'hacktricks', 'nuclei', 'personal']
        
        for source in sources:
            try:
                sync_result = sync_source(source, force=True)
                if sync_result['success']:
                    result['chunks_by_source'][source] = sync_result['chunks_added']
                    result['total_chunks'] += sync_result['chunks_added']
                else:
                    result['errors'].extend(sync_result['errors'])
            except Exception as e:
                result['errors'].append(f"Error syncing {source}: {e}")
        
        result['success'] = len(result['errors']) == 0
        
    except Exception as e:
        result['errors'].append(f"Rebuild error: {e}")
        logger.error(f"Error rebuilding KB: {e}")
    
    return result


# ==================== CLI Entry Point ====================

def print_json(data: Any):
    """Print data as formatted JSON."""
    print(json.dumps(data, indent=2, default=str))


def print_status(status: KBStatus):
    """Pretty print KB status."""
    print("\n" + "=" * 50)
    print("🧠 Knowledge Base Status")
    print("=" * 50)
    
    # Health
    health_icon = "✅" if status.vector_store_healthy else "❌"
    print(f"\n{health_icon} Vector Store: {'Healthy' if status.vector_store_healthy else 'Unhealthy'}")
    
    # Total chunks
    print(f"\n📊 Total Chunks: {status.total_chunks:,}")
    
    # Chunks by source
    if status.chunks_by_source:
        print("\n📁 Chunks by Source:")
        for source, count in sorted(status.chunks_by_source.items()):
            print(f"   • {source}: {count:,}")
    
    # Last sync times
    if status.last_sync:
        print("\n🕐 Last Sync:")
        for source, timestamp in sorted(status.last_sync.items()):
            if timestamp:
                print(f"   • {source}: {timestamp}")
            else:
                print(f"   • {source}: Never")
    
    # Errors
    if status.errors:
        print("\n⚠️  Errors:")
        for error in status.errors:
            print(f"   • {error}")
    
    print()


def print_search_results(results: Dict[str, Any]):
    """Pretty print search results."""
    print("\n" + "=" * 50)
    print(f"🔍 Search Results for: {results['query']}")
    print("=" * 50)
    
    if results['errors']:
        print("\n⚠️  Errors:")
        for error in results['errors']:
            print(f"   • {error}")
        return
    
    if not results['results']:
        print("\n❌ No results found")
        return
    
    print(f"\n📊 Found {results['total']} results:\n")
    
    for i, result in enumerate(results['results'], 1):
        source = result.get('source', 'unknown')
        score = result.get('score', 0)
        content = result.get('content', '')
        
        print(f"--- Result {i} [{source}] (score: {score:.3f}) ---")
        print(content[:300] + '...' if len(content) > 300 else content)
        print()


def main(args: Optional[List[str]] = None):
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Ghost-Hunter Knowledge Base CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Output as JSON'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # status command
    status_parser = subparsers.add_parser('status', help='Show KB status')
    
    # sync-cve command
    sync_cve_parser = subparsers.add_parser('sync-cve', help='Sync CVE/NVD data')
    sync_cve_parser.add_argument('--force', '-f', action='store_true', help='Force re-sync')
    
    # sync-hacktricks command
    sync_ht_parser = subparsers.add_parser('sync-hacktricks', help='Sync HackTricks data')
    sync_ht_parser.add_argument('--force', '-f', action='store_true', help='Force re-sync')
    
    # sync-disclosures command
    sync_disc_parser = subparsers.add_parser('sync-disclosures', help='Sync HackerOne public disclosures')
    sync_disc_parser.add_argument('--force', '-f', action='store_true', help='Force re-sync')
    sync_disc_parser.add_argument('--min-upvotes', type=int, default=10, help='Minimum upvotes filter (default: 10)')
    sync_disc_parser.add_argument('--max-reports', type=int, default=5000, help='Maximum reports to sync (default: 5000)')
    
    # sync command (generic)
    sync_parser = subparsers.add_parser('sync', help='Sync a specific source')
    sync_parser.add_argument('source', help='Source to sync (cve, hacktricks, nuclei, personal)')
    sync_parser.add_argument('--force', '-f', action='store_true', help='Force re-sync')
    
    # add-report command
    add_parser = subparsers.add_parser('add-report', help='Add a personal report')
    add_parser.add_argument('path', help='Path to markdown report file')
    
    # search command
    search_parser = subparsers.add_parser('search', help='Search the knowledge base')
    search_parser.add_argument('query', nargs='+', help='Search query')
    search_parser.add_argument('--limit', '-n', type=int, default=10, help='Max results')
    
    # rebuild command
    rebuild_parser = subparsers.add_parser('rebuild', help='Rebuild entire KB')
    rebuild_parser.add_argument('--confirm', action='store_true', help='Confirm rebuild')
    
    parsed_args = parser.parse_args(args)
    
    if not parsed_args.command:
        parser.print_help()
        return 1
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s' if not parsed_args.json else '%(levelname)s: %(message)s'
    )
    
    # Execute command
    if parsed_args.command == 'status':
        status = get_kb_status()
        if parsed_args.json:
            print_json(status.to_dict())
        else:
            print_status(status)
        return 0 if status.vector_store_healthy else 1
    
    elif parsed_args.command == 'sync-cve':
        result = sync_source('cve', force=parsed_args.force)
        if parsed_args.json:
            print_json(result)
        else:
            if result['success']:
                print(f"✅ CVE sync complete: {result['chunks_added']} chunks added")
            else:
                print(f"❌ CVE sync failed: {', '.join(result['errors'])}")
        return 0 if result['success'] else 1
    
    elif parsed_args.command == 'sync-hacktricks':
        result = sync_source('hacktricks', force=parsed_args.force)
        if parsed_args.json:
            print_json(result)
        else:
            if result['success']:
                print(f"✅ HackTricks sync complete: {result['chunks_added']} chunks added")
            else:
                print(f"❌ HackTricks sync failed: {', '.join(result['errors'])}")
        return 0 if result['success'] else 1
    
    elif parsed_args.command == 'sync-disclosures':
        result = sync_disclosures(
            force=parsed_args.force,
            min_upvotes=parsed_args.min_upvotes,
            max_reports=parsed_args.max_reports
        )
        if parsed_args.json:
            print_json(result)
        else:
            if result['success']:
                print(f"✅ HackerOne disclosures sync complete: {result['chunks_added']} chunks added")
            else:
                print(f"❌ Disclosures sync failed: {', '.join(result['errors'])}")
        return 0 if result['success'] else 1
    
    elif parsed_args.command == 'sync':
        result = sync_source(parsed_args.source, force=parsed_args.force)
        if parsed_args.json:
            print_json(result)
        else:
            if result['success']:
                print(f"✅ {parsed_args.source} sync complete: {result['chunks_added']} chunks added")
            else:
                print(f"❌ {parsed_args.source} sync failed: {', '.join(result['errors'])}")
        return 0 if result['success'] else 1
    
    elif parsed_args.command == 'add-report':
        result = add_report(parsed_args.path)
        if parsed_args.json:
            print_json(result)
        else:
            if result['success']:
                print(f"✅ Report added: {result['chunks_added']} chunks")
            else:
                print(f"❌ Failed to add report: {', '.join(result['errors'])}")
        return 0 if result['success'] else 1
    
    elif parsed_args.command == 'search':
        query = ' '.join(parsed_args.query)
        result = search_kb(query, limit=parsed_args.limit)
        if parsed_args.json:
            print_json(result)
        else:
            print_search_results(result)
        return 0 if not result['errors'] else 1
    
    elif parsed_args.command == 'rebuild':
        if not parsed_args.confirm:
            print("⚠️  This will rebuild the entire knowledge base.")
            print("   Use --confirm to proceed.")
            return 1
        
        print("🔄 Rebuilding knowledge base...")
        result = rebuild_kb()
        if parsed_args.json:
            print_json(result)
        else:
            if result['success']:
                print(f"✅ Rebuild complete: {result['total_chunks']} total chunks")
                for source, count in result['chunks_by_source'].items():
                    print(f"   • {source}: {count}")
            else:
                print(f"❌ Rebuild failed: {', '.join(result['errors'])}")
        return 0 if result['success'] else 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

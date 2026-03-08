#!/usr/bin/env python3
"""
CVE Sync Script - À exécuter via cron.

Synchronise les CVE récents depuis NVD vers le RAG.
Ne s'exécute PAS si le pipeline est actif.

Usage:
    python scripts/sync_cve.py           # Sync dernier jour
    python scripts/sync_cve.py --days 7  # Sync dernière semaine
    python scripts/sync_cve.py --full    # Sync 1 an (LONG!)

Cron setup:
    0 4 * * * cd /path/to/Ghost_Hunter && ./venv/bin/python scripts/sync_cve.py >> data/logs/cve_sync.log 2>&1
"""

import sys
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Ajouter le projet au path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ghost_hunter.core.rag.ingestors.nvd import (
    NVDSyncService,
    is_pipeline_active,
)


# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Sync CVE depuis NVD")
    parser.add_argument(
        "--days",
        type=int,
        default=1,
        help="Nombre de jours à synchroniser (default: 1)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Sync complète (1 an, ATTENTION: très long!)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force la sync même si pipeline actif",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="Clé API NVD (optionnel, augmente le rate limit)",
    )
    parser.add_argument(
        "--min-cvss",
        type=float,
        default=5.0,
        help="Score CVSS minimum (default: 5.0)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Affiche ce qui serait fait sans sync",
    )
    
    args = parser.parse_args()
    
    # Vérifier pipeline actif
    if not args.force and is_pipeline_active():
        logger.info("Pipeline actif, sync reportée. Utilisez --force pour forcer.")
        sys.exit(0)
    
    # Déterminer la période
    days = 365 if args.full else args.days
    
    logger.info(f"=== CVE Sync Started ===")
    logger.info(f"Days: {days}, Min CVSS: {args.min_cvss}")
    
    if args.dry_run:
        logger.info("DRY RUN - Pas de sync effectuée")
        sys.exit(0)
    
    try:
        service = NVDSyncService(
            api_key=args.api_key,
            min_cvss=args.min_cvss,
        )
        
        chunks = service.sync_recent(days=days)
        stats = service.get_stats()
        
        logger.info(f"=== CVE Sync Complete ===")
        logger.info(f"Fetched: {stats['fetched']}")
        logger.info(f"Filtered (CWE non-web): {stats['filtered_cwe']}")
        logger.info(f"Filtered (CVSS < {args.min_cvss}): {stats['filtered_cvss']}")
        logger.info(f"Indexed: {stats['indexed']}")
        
        # TODO: Upsert dans VectorStore
        # from ghost_hunter.core.rag.vector_store import VectorStore
        # store = VectorStore()
        # store.upsert_batch(chunks)
        
    except Exception as e:
        logger.error(f"Sync failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

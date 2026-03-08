"""
Dashboard shared dependencies.
==============================
Singletons et dépendances partagées entre les routes.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ==================== Singleton Instances ====================

_dedup_engine = None
_pipeline = None
_service_manager = None


def get_dedup():
    """Retourne l'instance DedupEngine (singleton connecté à Redis)."""
    global _dedup_engine
    if _dedup_engine is None:
        from ghost_hunter.core.interceptor.dedup import DedupEngine
        _dedup_engine = DedupEngine()
        logger.info("DedupEngine initialized (Redis backend)")
    return _dedup_engine


def get_pipeline():
    """
    Retourne le pipeline complet.
    
    IMPORTANT: Utilise l'instance globale de ghost_hunter.main pour éviter
    les doubles instances entre le proxy et le dashboard.
    """
    try:
        from ghost_hunter.main import get_pipeline as _get_main_pipeline
        return _get_main_pipeline()
    except Exception as e:
        logger.warning(f"Could not get pipeline from main: {e}")
        # Fallback: créer une instance locale
        global _pipeline
        if _pipeline is None:
            try:
                from ghost_hunter.main import GhostHunterPipeline
                _pipeline = GhostHunterPipeline()
                logger.info("Pipeline initialized (local fallback)")
            except Exception as e2:
                logger.warning(f"Could not initialize pipeline: {e2}")
                return None
        return _pipeline


def get_service_manager():
    """Retourne le ServiceManager (singleton)."""
    global _service_manager
    if _service_manager is None:
        try:
            from ghost_hunter.service_manager import get_service_manager as _get_sm
            _service_manager = _get_sm()
        except Exception as e:
            logger.error(f"Failed to load service manager: {e}")
            return None
    return _service_manager


def get_redis_store():
    """Retourne le RedisStore centralisé."""
    from ghost_hunter.core.redis_store import get_redis_store as _get_rs
    return _get_rs()

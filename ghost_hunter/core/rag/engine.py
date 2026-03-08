"""
Ghost-Hunter RAG Engine
=======================
Moteur RAG principal avec interface SYNC pour le pipeline.

Features:
- Lazy loading du vector store (pas de chargement au démarrage)
- Interface synchrone pour compatibilité pipeline
- Fallback vers KnowledgeLoader si RAG indisponible
- Cache LRU agressif sur les queries
- Système de pondération (source, recency, severity)
"""

import logging
import time
import hashlib
from functools import lru_cache
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass

from ghost_hunter.core.rag.contracts import (
    Chunk, RAGQuery, RAGResult, RAGContext
)

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class RAGConfig:
    """Configuration du RAG Engine."""
    
    # Token budget
    max_tokens: int = 1000
    max_chunks: int = 10
    
    # Cache
    cache_size: int = 200
    cache_ttl_seconds: int = 300  # 5 minutes
    
    # Weighting
    personal_weight: float = 1.5
    recency_boost_days: int = 30
    recency_boost_factor: float = 1.3
    severity_boost_critical: float = 1.4
    severity_boost_high: float = 1.2
    
    # Performance
    query_timeout_ms: int = 100
    min_score: float = 0.4  # Raised to filter irrelevant results (was 0.05)


DEFAULT_CONFIG = RAGConfig()


# ============================================================================
# Token Utilities
# ============================================================================

def estimate_tokens(text: str) -> int:
    """
    Estime le nombre de tokens (approximation: 4 chars = 1 token).
    
    Cette approximation est conservatrice pour éviter de dépasser le budget.
    """
    return len(text) // 4


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """
    Tronque un texte pour tenir dans un budget de tokens.
    
    Args:
        text: Texte à tronquer
        max_tokens: Nombre max de tokens
        
    Returns:
        Texte tronqué avec "..." si nécessaire
    """
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    
    # Tronquer et ajouter "..."
    truncated = text[:max_chars - 3].rsplit(" ", 1)[0]
    return truncated + "..."


# ============================================================================
# RAG Engine
# ============================================================================

class RAGEngine:
    """
    Engine RAG principal avec interface SYNC pour le pipeline.
    
    Usage:
        engine = RAGEngine()
        
        # Lazy load - rien n'est chargé encore
        if engine.is_available():
            context = engine.get_context_sync(scored_request)
            # Utiliser context.formatted_context dans le prompt
    """
    
    def __init__(self, config: Optional[RAGConfig] = None):
        """
        Args:
            config: Configuration RAG (optionnel)
        """
        self.config = config or DEFAULT_CONFIG
        
        # Lazy load state
        self._store = None
        self._knowledge_loader = None
        
        # Cache pour les queries
        self._cache: Dict[str, Tuple[RAGContext, float]] = {}
        
        # Stats
        self._stats = {
            "queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "fallbacks": 0,
            "total_time_ms": 0.0,
        }
    
    # =========================================================================
    # Properties (Lazy Loading)
    # =========================================================================
    
    @property
    def store(self):
        """Lazy load du VectorStoreManager."""
        if self._store is None:
            try:
                from ghost_hunter.core.rag.vector_store import VectorStoreManager
                self._store = VectorStoreManager()
                logger.info("RAG VectorStore loaded lazily")
            except Exception as e:
                logger.warning(f"Failed to load VectorStore: {e}")
                self._store = None
        return self._store
    
    @property
    def knowledge_loader(self):
        """Lazy load du KnowledgeLoader (fallback)."""
        if self._knowledge_loader is None:
            try:
                from ghost_hunter.core.intelligence.knowledge import get_knowledge_loader
                self._knowledge_loader = get_knowledge_loader()
                logger.debug("KnowledgeLoader loaded for fallback")
            except Exception as e:
                logger.warning(f"Failed to load KnowledgeLoader: {e}")
                self._knowledge_loader = None
        return self._knowledge_loader
    
    # =========================================================================
    # Availability Check
    # =========================================================================
    
    def is_available(self) -> bool:
        """
        Vérifie si le RAG est disponible et a des données.
        
        Returns:
            True si le RAG peut être utilisé
        """
        try:
            if self.store is None:
                return False
            
            # Vérifier que la collection a des documents
            count = self.store.count()
            return count > 0
            
        except Exception as e:
            logger.debug(f"RAG availability check failed: {e}")
            return False
    
    # =========================================================================
    # Main Query Interface (SYNC)
    # =========================================================================
    
    def get_context_sync(
        self,
        request: Any,  # ScoredRequest ou similaire
        tech_profile: Optional[Any] = None,  # TechProfile
        max_chunks: Optional[int] = None,
        max_tokens: Optional[int] = None,
        include_payloads: bool = False,
    ) -> RAGContext:
        """
        Récupère le contexte RAG de manière synchrone.
        
        Cette méthode est conçue pour le pipeline actuel qui est synchrone.
        Elle inclut un fallback automatique vers KnowledgeLoader.
        
        Args:
            request: ScoredRequest ou objet avec path, params, potential_vulns
            tech_profile: TechProfile optionnel pour le tech stack
            max_chunks: Override du nombre max de chunks
            max_tokens: Override du budget tokens
            include_payloads: Inclure les payloads dans les résultats
            
        Returns:
            RAGContext avec les résultats et le contexte formaté
        """
        start_time = time.time()
        self._stats["queries"] += 1
        
        max_chunks = max_chunks or self.config.max_chunks
        max_tokens = max_tokens or self.config.max_tokens
        
        # Construire la query
        query = self._build_query(request, tech_profile, include_payloads)
        
        # Vérifier le cache
        cache_key = self._cache_key(query, max_chunks)
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return cached
        
        self._stats["cache_misses"] += 1
        
        # Essayer le RAG
        if self.is_available():
            try:
                context = self._query_vector_store(
                    query, max_chunks, max_tokens
                )
                
                # Mettre en cache
                self._put_in_cache(cache_key, context)
                
                elapsed_ms = (time.time() - start_time) * 1000
                self._stats["total_time_ms"] += elapsed_ms
                
                return context
                
            except Exception as e:
                logger.warning(f"RAG query failed, falling back: {e}")
        
        # Fallback vers KnowledgeLoader
        self._stats["fallbacks"] += 1
        return self._fallback_knowledge_loader(request, max_tokens)
    
    # =========================================================================
    # Query Building
    # =========================================================================
    
    def _build_query(
        self,
        request: Any,
        tech_profile: Optional[Any],
        include_payloads: bool = False,
    ) -> RAGQuery:
        """
        Construit une RAGQuery contextuelle à partir d'un ScoredRequest.
        
        Builds a semantic query focusing on:
        - Vulnerability types (primary focus)
        - Attack techniques and patterns
        - NOT raw paths (poor semantic match)
        """
        parts = []
        vuln_types = []
        
        # Extract vulnerability types - PRIMARY FOCUS
        if hasattr(request, 'potential_vulns') and request.potential_vulns:
            vuln_types.extend(request.potential_vulns)
            # Add semantic context for each vuln type
            vuln_context = {
                'IDOR': 'insecure direct object reference access control bypass',
                'BOLA': 'broken object level authorization API access',
                'SQLi': 'SQL injection database query manipulation',
                'XSS': 'cross-site scripting javascript injection',
                'SSRF': 'server-side request forgery internal access',
                'Mass Assignment': 'parameter pollution privilege escalation role',
                'LFI': 'local file inclusion path traversal',
                'RCE': 'remote code execution command injection',
                'XXE': 'XML external entity injection',
                'AuthZ Bypass': 'authorization bypass access control',
            }
            for vuln in request.potential_vulns:
                if vuln in vuln_context:
                    parts.append(vuln_context[vuln])
                else:
                    parts.append(vuln)
        
        # Add interesting params with context
        if hasattr(request, 'interesting_params') and request.interesting_params:
            # Only add params that suggest attack type
            id_params = [p for p in request.interesting_params if 'id' in p.lower()]
            if id_params and 'IDOR' not in parts:
                parts.append('IDOR access control')
        
        # Add tech stack context (useful for framework-specific vulns)
        if tech_profile:
            if hasattr(tech_profile, 'technologies'):
                parts.extend(tech_profile.technologies)
            elif isinstance(tech_profile, dict):
                parts.extend(tech_profile.get('technologies', []))
        
        # Fallback: if no vuln detected, add generic query
        if not parts:
            parts.append('web application security testing')
        
        query_text = " ".join(str(p) for p in parts if p)
        
        return RAGQuery(
            text=query_text,
            vuln_types=vuln_types if vuln_types else None,
            top_k=self.config.max_chunks * 2,  # Récupérer plus pour filtrer
            min_score=self.config.min_score,
            include_payloads=include_payloads,
        )
    
    # =========================================================================
    # Vector Store Query
    # =========================================================================
    
    def _query_vector_store(
        self,
        query: RAGQuery,
        max_chunks: int,
        max_tokens: int,
    ) -> RAGContext:
        """
        Exécute la query sur le vector store.
        
        Args:
            query: RAGQuery à exécuter
            max_chunks: Nombre max de chunks
            max_tokens: Budget tokens
            
        Returns:
            RAGContext avec résultats pondérés et formatés
        """
        start_time = time.time()
        
        # Query le vector store - retourne un RAGContext
        # Note: Filters disabled for now as they may filter out too much
        raw_context = self.store.query_sync(
            query.text,
            top_k=query.top_k,
            filters=None,  # query.to_filters() - disabled for broader results
            min_score=self.config.min_score,
        )
        
        # Appliquer weighting aux résultats existants
        results = []
        for rag_result in raw_context.results:
            weighted_score = self._apply_weighting(rag_result.chunk, rag_result.score)
            results.append(RAGResult(
                chunk=rag_result.chunk,
                score=rag_result.score,
                weighted_score=weighted_score,
            ))
        
        # Trier par score pondéré et limiter
        results.sort(key=lambda r: r.weighted_score, reverse=True)
        results = results[:max_chunks]
        
        # Check if results are relevant enough
        best_score = results[0].weighted_score if results else 0
        if not results or best_score < self.config.min_score:
            # No relevant results - return helpful message instead of noise
            elapsed_ms = (time.time() - start_time) * 1000
            return RAGContext(
                query=query,
                results=[],
                formatted_context="### Knowledge Base:\nNo directly relevant techniques found for this endpoint pattern. Analyze based on request structure and parameter names.",
                retrieval_time_ms=elapsed_ms,
            )
        
        # Formater le contexte avec budget tokens
        formatted = self._format_context(results, max_tokens)
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        return RAGContext(
            query=query,
            results=results,
            formatted_context=formatted,
            retrieval_time_ms=elapsed_ms,
        )
    
    # =========================================================================
    # Weighting System
    # =========================================================================
    
    def _apply_weighting(self, chunk: Chunk, base_score: float) -> float:
        """
        Applique le système de pondération au score.
        
        Facteurs:
        - Source (personal = 1.5x)
        - Recency (CVE < 30j = 1.3x)
        - Severity (critical = 1.4x, high = 1.2x)
        """
        score = base_score
        
        # 1. Source weight
        source = chunk.metadata.get("source", "")
        if source in ("personal", "personal_report"):
            score *= self.config.personal_weight
        
        # 2. Recency boost (pour CVE)
        if source == "nvd":
            date_str = chunk.metadata.get("date") or chunk.metadata.get("indexed_at", "")
            if date_str:
                try:
                    # Parser la date
                    if "T" in date_str:
                        date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    else:
                        date = datetime.strptime(date_str[:10], "%Y-%m-%d")
                    
                    days_old = (datetime.now() - date.replace(tzinfo=None)).days
                    if days_old < self.config.recency_boost_days:
                        score *= self.config.recency_boost_factor
                except (ValueError, TypeError):
                    pass
        
        # 3. Severity boost
        severity = chunk.metadata.get("severity", "").lower()
        if severity == "critical":
            score *= self.config.severity_boost_critical
        elif severity == "high":
            score *= self.config.severity_boost_high
        
        # 4. Custom weight dans metadata
        custom_weight = chunk.metadata.get("weight", 1.0)
        score *= custom_weight
        
        return score
    
    # =========================================================================
    # Context Formatting
    # =========================================================================
    
    def _format_context(
        self,
        results: List[RAGResult],
        max_tokens: int,
    ) -> str:
        """
        Formate le contexte avec un budget strict de tokens.
        
        Args:
            results: Résultats triés par score
            max_tokens: Budget max de tokens
            
        Returns:
            Contexte formaté pour le prompt
        """
        if not results:
            return ""
        
        formatted = []
        current_tokens = 0
        
        # Header
        header = "### Relevant Knowledge:\n"
        current_tokens += estimate_tokens(header)
        formatted.append(header)
        
        for i, result in enumerate(results):
            # Construire le header du chunk
            chunk_header = f"\n**[{i+1}] {result.chunk.source} ({result.chunk.vuln_type})**\n"
            header_tokens = estimate_tokens(chunk_header)
            
            # Calculer le budget restant pour le texte
            remaining = max_tokens - current_tokens - header_tokens - 10  # 10 tokens de marge
            
            if remaining <= 0:
                break
            
            chunk_tokens = estimate_tokens(result.chunk.text)
            
            if current_tokens + header_tokens + chunk_tokens > max_tokens:
                # Tronquer le chunk pour rentrer dans le budget
                truncated = truncate_to_tokens(result.chunk.text, remaining)
                formatted.append(chunk_header)
                formatted.append(truncated)
                break
            
            formatted.append(chunk_header)
            formatted.append(result.chunk.text)
            current_tokens += header_tokens + chunk_tokens
        
        return "".join(formatted)
    
    # =========================================================================
    # Fallback (KnowledgeLoader)
    # =========================================================================
    
    def _fallback_knowledge_loader(
        self,
        request: Any,
        max_tokens: int,
    ) -> RAGContext:
        """
        Fallback vers KnowledgeLoader (keyword matching).
        
        Utilisé quand le RAG n'est pas disponible ou échoue.
        """
        if self.knowledge_loader is None:
            # Retourner un contexte vide
            return RAGContext(
                query=RAGQuery(text="", top_k=0),
                results=[],
                formatted_context="",
            )
        
        try:
            # Extraire les vuln types pour le keyword matching
            vuln_types = []
            if hasattr(request, 'potential_vulns'):
                vuln_types = request.potential_vulns
            
            # Utiliser KnowledgeLoader
            context_text = ""
            for vuln_type in vuln_types[:3]:  # Limiter à 3 types
                tips = self.knowledge_loader.get_tips(vuln_type)
                if tips:
                    context_text += f"\n### {vuln_type}:\n{tips[:300]}\n"
            
            # Tronquer si nécessaire
            if estimate_tokens(context_text) > max_tokens:
                context_text = truncate_to_tokens(context_text, max_tokens)
            
            return RAGContext(
                query=RAGQuery(text=" ".join(vuln_types), top_k=0),
                results=[],
                formatted_context=context_text,
            )
            
        except Exception as e:
            logger.error(f"KnowledgeLoader fallback failed: {e}")
            return RAGContext(
                query=RAGQuery(text="", top_k=0),
                results=[],
                formatted_context="",
            )
    
    # =========================================================================
    # Cache Management
    # =========================================================================
    
    def _cache_key(self, query: RAGQuery, max_chunks: int) -> str:
        """Génère une clé de cache unique pour la query."""
        key_parts = [
            query.text,
            str(query.vuln_types),
            str(query.sources),
            str(max_chunks),
        ]
        key_str = "|".join(key_parts)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _get_from_cache(self, key: str) -> Optional[RAGContext]:
        """Récupère un résultat du cache si valide."""
        if key not in self._cache:
            return None
        
        context, timestamp = self._cache[key]
        
        # Vérifier TTL
        age = time.time() - timestamp
        if age > self.config.cache_ttl_seconds:
            del self._cache[key]
            return None
        
        return context
    
    def _put_in_cache(self, key: str, context: RAGContext) -> None:
        """Met un résultat en cache."""
        # Limiter la taille du cache
        if len(self._cache) >= self.config.cache_size:
            # Supprimer les plus anciens
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]
        
        self._cache[key] = (context, time.time())
    
    def clear_cache(self) -> None:
        """Vide le cache."""
        self._cache.clear()
    
    # =========================================================================
    # Stats
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du RAG Engine."""
        stats = self._stats.copy()
        stats["cache_entries"] = len(self._cache)
        
        if stats["queries"] > 0:
            stats["avg_time_ms"] = stats["total_time_ms"] / stats["queries"]
            stats["cache_hit_rate"] = stats["cache_hits"] / stats["queries"]
            stats["fallback_rate"] = stats["fallbacks"] / stats["queries"]
        
        return stats


# ============================================================================
# Singleton Instance
# ============================================================================

_rag_engine: Optional[RAGEngine] = None


def get_rag_engine(config: Optional[RAGConfig] = None) -> RAGEngine:
    """
    Retourne l'instance singleton du RAG Engine.
    
    Args:
        config: Configuration optionnelle (utilisée seulement à la première création)
        
    Returns:
        Instance RAGEngine
    """
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine(config=config)
    return _rag_engine


def reset_rag_engine() -> None:
    """Reset l'instance singleton (pour tests)."""
    global _rag_engine
    _rag_engine = None

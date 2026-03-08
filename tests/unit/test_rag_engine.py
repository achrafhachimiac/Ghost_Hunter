"""
Tests pour le RAG Engine.

Teste:
- Lazy loading
- Interface SYNC
- Fallback vers KnowledgeLoader
- Cache LRU
- Système de pondération
- Budget tokens
"""

import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from typing import List, Optional

from ghost_hunter.core.rag.engine import (
    RAGEngine,
    RAGConfig,
    estimate_tokens,
    truncate_to_tokens,
    get_rag_engine,
    reset_rag_engine,
)
from ghost_hunter.core.rag.contracts import (
    Chunk, RAGQuery, RAGResult, RAGContext
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def rag_config():
    """Configuration RAG pour tests."""
    return RAGConfig(
        max_tokens=500,
        max_chunks=5,
        cache_size=10,
        cache_ttl_seconds=60,
        personal_weight=1.5,
        recency_boost_days=30,
        recency_boost_factor=1.3,
        severity_boost_critical=1.4,
        severity_boost_high=1.2,
    )


@pytest.fixture
def rag_engine(rag_config):
    """RAG Engine pour tests."""
    reset_rag_engine()
    return RAGEngine(config=rag_config)


@pytest.fixture
def mock_scored_request():
    """Mock d'un ScoredRequest."""
    @dataclass
    class MockRequest:
        path: str = "/api/v1/users/123"
        method: str = "GET"
    
    @dataclass
    class MockFilteredRequest:
        request: MockRequest = None
        
        def __post_init__(self):
            if self.request is None:
                self.request = MockRequest()
    
    @dataclass
    class MockScoredRequest:
        request: MockFilteredRequest = None
        score: float = 35.0
        interesting_params: List[str] = None
        potential_vulns: List[str] = None
        
        def __post_init__(self):
            if self.request is None:
                self.request = MockFilteredRequest()
            if self.interesting_params is None:
                self.interesting_params = ["id", "user_id"]
            if self.potential_vulns is None:
                self.potential_vulns = ["idor", "auth_bypass"]
    
    return MockScoredRequest()


@pytest.fixture
def sample_chunks():
    """Chunks de test."""
    return [
        Chunk.create(
            text="IDOR vulnerability allows accessing other users data.",
            source="hacktricks",
            chunk_type="technique",
            vuln_type="idor",
        ),
        Chunk.create(
            text="SQL injection in login form bypasses authentication.",
            source="personal",
            chunk_type="report",
            vuln_type="sqli",
            severity="critical",
        ),
        Chunk.create(
            text="Recent CVE-2025-1234 affects REST APIs.",
            source="nvd",
            chunk_type="cve",
            vuln_type="auth_bypass",
            date=(datetime.now() - timedelta(days=10)).isoformat(),
        ),
    ]


# ============================================================================
# Tests: Token Utilities
# ============================================================================

class TestEstimateTokens:
    """Tests pour estimate_tokens()."""
    
    def test_empty_string(self):
        assert estimate_tokens("") == 0
    
    def test_short_text(self):
        # 16 chars = 4 tokens
        assert estimate_tokens("0123456789012345") == 4
    
    def test_approximation(self):
        text = "This is a test sentence with some words."
        tokens = estimate_tokens(text)
        # Devrait être environ len(text) / 4
        assert tokens == len(text) // 4


class TestTruncateToTokens:
    """Tests pour truncate_to_tokens()."""
    
    def test_no_truncation_needed(self):
        text = "Short text"
        result = truncate_to_tokens(text, 100)
        assert result == text
    
    def test_truncation_with_ellipsis(self):
        text = "This is a very long text that needs to be truncated to fit the budget."
        result = truncate_to_tokens(text, 5)  # 20 chars max
        assert len(result) <= 20
        assert result.endswith("...")
    
    def test_truncation_at_word_boundary(self):
        text = "Word1 Word2 Word3 Word4 Word5"
        result = truncate_to_tokens(text, 4)  # 16 chars max
        # Should try to truncate at word boundary
        assert "..." in result


# ============================================================================
# Tests: RAG Engine Initialization
# ============================================================================

class TestRAGEngineInit:
    """Tests pour l'initialisation du RAG Engine."""
    
    def test_lazy_load_no_store_at_init(self, rag_engine):
        """Le store ne doit pas être chargé au __init__."""
        assert rag_engine._store is None
    
    def test_lazy_load_no_knowledge_loader_at_init(self, rag_engine):
        """KnowledgeLoader ne doit pas être chargé au __init__."""
        assert rag_engine._knowledge_loader is None
    
    def test_config_applied(self, rag_config):
        engine = RAGEngine(config=rag_config)
        assert engine.config.max_tokens == 500
        assert engine.config.max_chunks == 5
    
    def test_default_config(self):
        engine = RAGEngine()
        assert engine.config is not None
        assert engine.config.max_tokens > 0


# ============================================================================
# Tests: Availability
# ============================================================================

class TestIsAvailable:
    """Tests pour is_available()."""
    
    def test_returns_false_if_store_none(self, rag_engine):
        """Retourne False si le store n'est pas chargeable."""
        rag_engine._store = None
        # Force la propriété à retourner None
        with patch.object(RAGEngine, 'store', new_callable=lambda: property(lambda self: None)):
            engine = RAGEngine()
            assert engine.is_available() is False
    
    def test_returns_false_if_collection_empty(self, rag_engine):
        """Retourne False si la collection est vide."""
        mock_store = Mock()
        mock_store.count.return_value = 0
        rag_engine._store = mock_store
        
        assert rag_engine.is_available() is False
    
    def test_returns_true_if_has_documents(self, rag_engine):
        """Retourne True si la collection a des documents."""
        mock_store = Mock()
        mock_store.count.return_value = 100
        rag_engine._store = mock_store
        
        assert rag_engine.is_available() is True


# ============================================================================
# Tests: Query Building
# ============================================================================

class TestBuildQuery:
    """Tests pour _build_query()."""
    
    def test_extracts_path(self, rag_engine, mock_scored_request):
        query = rag_engine._build_query(mock_scored_request, None)
        assert "/api/v1/users/123" in query.text
    
    def test_extracts_params(self, rag_engine, mock_scored_request):
        query = rag_engine._build_query(mock_scored_request, None)
        assert "id" in query.text or "user_id" in query.text
    
    def test_extracts_vulns(self, rag_engine, mock_scored_request):
        query = rag_engine._build_query(mock_scored_request, None)
        assert query.vuln_types is not None
        assert "idor" in query.vuln_types
    
    def test_includes_tech_profile(self, rag_engine, mock_scored_request):
        tech_profile = {"technologies": ["nodejs", "express"]}
        query = rag_engine._build_query(mock_scored_request, tech_profile)
        assert "nodejs" in query.text or "express" in query.text


# ============================================================================
# Tests: Weighting System
# ============================================================================

class TestWeighting:
    """Tests pour le système de pondération."""
    
    def test_personal_source_boost(self, rag_engine):
        """Source personal doit avoir un boost 1.5x."""
        chunk = Chunk.create(
            text="Personal report",
            source="personal",
            chunk_type="report",
            vuln_type="idor",
        )
        
        weighted = rag_engine._apply_weighting(chunk, 1.0)
        assert weighted == pytest.approx(1.5)
    
    def test_recency_boost_recent_cve(self, rag_engine):
        """CVE récent (<30j) doit avoir un boost 1.3x."""
        recent_date = (datetime.now() - timedelta(days=10)).isoformat()
        chunk = Chunk.create(
            text="Recent CVE",
            source="nvd",
            chunk_type="cve",
            vuln_type="sqli",
            date=recent_date,
        )
        
        weighted = rag_engine._apply_weighting(chunk, 1.0)
        assert weighted == pytest.approx(1.3)
    
    def test_no_recency_boost_old_cve(self, rag_engine):
        """CVE ancien (>30j) ne doit pas avoir de boost recency."""
        old_date = (datetime.now() - timedelta(days=60)).isoformat()
        chunk = Chunk.create(
            text="Old CVE",
            source="nvd",
            chunk_type="cve",
            vuln_type="sqli",
            date=old_date,
        )
        
        weighted = rag_engine._apply_weighting(chunk, 1.0)
        assert weighted == pytest.approx(1.0)
    
    def test_severity_boost_critical(self, rag_engine):
        """Severity critical doit avoir un boost 1.4x."""
        chunk = Chunk.create(
            text="Critical vuln",
            source="hacktricks",
            chunk_type="technique",
            vuln_type="rce",
            severity="critical",
        )
        
        weighted = rag_engine._apply_weighting(chunk, 1.0)
        assert weighted == pytest.approx(1.4)
    
    def test_severity_boost_high(self, rag_engine):
        """Severity high doit avoir un boost 1.2x."""
        chunk = Chunk.create(
            text="High vuln",
            source="hacktricks",
            chunk_type="technique",
            vuln_type="sqli",
            severity="high",
        )
        
        weighted = rag_engine._apply_weighting(chunk, 1.0)
        assert weighted == pytest.approx(1.2)
    
    def test_custom_weight_in_metadata(self, rag_engine):
        """Weight custom dans metadata doit être appliqué."""
        chunk = Chunk.create(
            text="Weighted chunk",
            source="hacktricks",
            chunk_type="technique",
            vuln_type="xss",
            weight=2.0,
        )
        
        weighted = rag_engine._apply_weighting(chunk, 1.0)
        assert weighted == pytest.approx(2.0)


# ============================================================================
# Tests: Context Formatting
# ============================================================================

class TestFormatContext:
    """Tests pour _format_context()."""
    
    def test_empty_results(self, rag_engine):
        result = rag_engine._format_context([], 500)
        assert result == ""
    
    def test_includes_header(self, rag_engine, sample_chunks):
        results = [
            RAGResult(chunk=sample_chunks[0], score=0.9, weighted_score=0.9)
        ]
        formatted = rag_engine._format_context(results, 500)
        assert "Relevant Knowledge" in formatted
    
    def test_respects_max_tokens(self, rag_engine):
        # Créer un chunk très long
        long_text = "x" * 2000
        chunk = Chunk.create(
            text=long_text,
            source="test",
            chunk_type="test",
            vuln_type="test",
        )
        results = [RAGResult(chunk=chunk, score=0.9, weighted_score=0.9)]
        
        formatted = rag_engine._format_context(results, 100)
        tokens = estimate_tokens(formatted)
        
        # Doit respecter le budget (avec petite marge)
        assert tokens <= 110  # 100 + petite marge
    
    def test_truncates_with_ellipsis(self, rag_engine):
        long_text = "word " * 500  # Très long
        chunk = Chunk.create(
            text=long_text,
            source="test",
            chunk_type="test",
            vuln_type="test",
        )
        results = [RAGResult(chunk=chunk, score=0.9, weighted_score=0.9)]
        
        formatted = rag_engine._format_context(results, 50)
        assert "..." in formatted


# ============================================================================
# Tests: Cache
# ============================================================================

class TestCache:
    """Tests pour le cache LRU."""
    
    def test_cache_hit(self, rag_engine, mock_scored_request):
        """Cache hit sur même query."""
        # Préparer un contexte en cache
        query = rag_engine._build_query(mock_scored_request, None)
        cache_key = rag_engine._cache_key(query, 5)
        
        context = RAGContext(
            query=query,
            results=[],
            formatted_context="cached",
        )
        rag_engine._put_in_cache(cache_key, context)
        
        # Vérifier le hit
        cached = rag_engine._get_from_cache(cache_key)
        assert cached is not None
        assert cached.formatted_context == "cached"
    
    def test_cache_miss(self, rag_engine):
        """Cache miss sur query inconnue."""
        cached = rag_engine._get_from_cache("unknown_key")
        assert cached is None
    
    def test_cache_ttl_expiry(self, rag_engine):
        """Cache expire après TTL."""
        # Mettre en cache avec timestamp ancien
        context = RAGContext(
            query=RAGQuery(text="test", top_k=5),
            results=[],
        )
        rag_engine._cache["old_key"] = (context, time.time() - 1000)
        
        # Doit retourner None (expiré)
        cached = rag_engine._get_from_cache("old_key")
        assert cached is None
    
    def test_cache_size_limit(self, rag_engine):
        """Cache respecte la taille max."""
        rag_engine.config.cache_size = 3
        
        # Remplir au-delà de la limite
        for i in range(5):
            context = RAGContext(
                query=RAGQuery(text=f"query_{i}", top_k=5),
                results=[],
            )
            rag_engine._put_in_cache(f"key_{i}", context)
        
        # Doit avoir au plus 3 entrées
        assert len(rag_engine._cache) <= 3
    
    def test_clear_cache(self, rag_engine):
        """clear_cache() vide le cache."""
        context = RAGContext(
            query=RAGQuery(text="test", top_k=5),
            results=[],
        )
        rag_engine._put_in_cache("key", context)
        
        rag_engine.clear_cache()
        assert len(rag_engine._cache) == 0


# ============================================================================
# Tests: Fallback
# ============================================================================

class TestFallback:
    """Tests pour le fallback vers KnowledgeLoader."""
    
    def test_fallback_when_store_unavailable(self, rag_engine, mock_scored_request):
        """Fallback quand le store n'est pas disponible."""
        with patch.object(rag_engine, 'is_available', return_value=False):
            context = rag_engine.get_context_sync(mock_scored_request)
            
            # Doit retourner un contexte (même vide)
            assert context is not None
            assert rag_engine._stats["fallbacks"] > 0
    
    def test_fallback_on_query_exception(self, rag_engine, mock_scored_request):
        """Fallback quand la query échoue."""
        mock_store = Mock()
        mock_store.count.return_value = 100
        mock_store.query_sync.side_effect = Exception("Query failed")
        
        with patch.object(rag_engine, '_store', mock_store):
            context = rag_engine.get_context_sync(mock_scored_request)
            
            assert context is not None
            assert rag_engine._stats["fallbacks"] > 0
    
    def test_fallback_returns_valid_context(self, rag_engine, mock_scored_request):
        """Fallback retourne un RAGContext valide."""
        # Simuler RAG indisponible
        mock_store = Mock()
        mock_store.count.return_value = 0
        rag_engine._store = mock_store
        rag_engine._knowledge_loader = None
        
        context = rag_engine.get_context_sync(mock_scored_request)
        
        assert isinstance(context, RAGContext)
        assert context.query is not None


# ============================================================================
# Tests: get_context_sync
# ============================================================================

class TestGetContextSync:
    """Tests pour get_context_sync()."""
    
    def test_returns_rag_context(self, rag_engine, mock_scored_request, sample_chunks):
        """get_context_sync() retourne un RAGContext."""
        mock_store = Mock()
        mock_store.count.return_value = 100
        mock_store.query_sync.return_value = [
            (sample_chunks[0], 0.9),
            (sample_chunks[1], 0.8),
        ]
        
        with patch.object(rag_engine, '_store', mock_store):
            context = rag_engine.get_context_sync(mock_scored_request)
            
            assert isinstance(context, RAGContext)
            assert len(context.results) <= rag_engine.config.max_chunks
    
    def test_respects_max_chunks(self, rag_engine, mock_scored_request, sample_chunks):
        """Respecte le paramètre max_chunks."""
        mock_store = Mock()
        mock_store.count.return_value = 100
        mock_store.query_sync.return_value = [
            (sample_chunks[i % len(sample_chunks)], 0.9 - i*0.1) 
            for i in range(10)
        ]
        
        with patch.object(rag_engine, '_store', mock_store):
            context = rag_engine.get_context_sync(
                mock_scored_request, 
                max_chunks=3
            )
            
            assert len(context.results) <= 3
    
    def test_respects_max_tokens(self, rag_engine, mock_scored_request):
        """Respecte le budget de tokens."""
        long_text = "word " * 500
        chunk = Chunk.create(
            text=long_text,
            source="test",
            chunk_type="test",
            vuln_type="idor",
        )
        
        mock_store = Mock()
        mock_store.count.return_value = 100
        mock_store.query_sync.return_value = [(chunk, 0.9)]
        
        with patch.object(rag_engine, '_store', mock_store):
            context = rag_engine.get_context_sync(
                mock_scored_request,
                max_tokens=100
            )
            
            tokens = estimate_tokens(context.formatted_context)
            assert tokens <= 120  # 100 + marge


# ============================================================================
# Tests: Stats
# ============================================================================

class TestStats:
    """Tests pour les statistiques."""
    
    def test_stats_tracking(self, rag_engine, mock_scored_request):
        """Les stats sont correctement trackées."""
        with patch.object(rag_engine, 'is_available', return_value=False):
            rag_engine.get_context_sync(mock_scored_request)
            rag_engine.get_context_sync(mock_scored_request)
            
            stats = rag_engine.get_stats()
            assert stats["queries"] == 2
            assert stats["fallbacks"] == 2
    
    def test_cache_hit_rate(self, rag_engine, mock_scored_request):
        """Le taux de cache hit est calculé."""
        # Premier appel = miss
        with patch.object(rag_engine, 'is_available', return_value=False):
            rag_engine.get_context_sync(mock_scored_request)
        
        stats = rag_engine.get_stats()
        assert "cache_hit_rate" in stats


# ============================================================================
# Tests: Singleton
# ============================================================================

class TestSingleton:
    """Tests pour le singleton."""
    
    def test_get_rag_engine_singleton(self):
        """get_rag_engine() retourne la même instance."""
        reset_rag_engine()
        
        engine1 = get_rag_engine()
        engine2 = get_rag_engine()
        
        assert engine1 is engine2
    
    def test_reset_clears_singleton(self):
        """reset_rag_engine() permet une nouvelle instance."""
        engine1 = get_rag_engine()
        reset_rag_engine()
        engine2 = get_rag_engine()
        
        assert engine1 is not engine2


# ============================================================================
# Tests: Import Verification
# ============================================================================

class TestImports:
    """Tests de vérification des imports."""
    
    def test_import_engine_module(self):
        from ghost_hunter.core.rag import engine
        assert hasattr(engine, 'RAGEngine')
        assert hasattr(engine, 'RAGConfig')
        assert hasattr(engine, 'get_rag_engine')
    
    def test_import_classes(self):
        from ghost_hunter.core.rag.engine import RAGEngine, RAGConfig
        assert RAGEngine is not None
        assert RAGConfig is not None

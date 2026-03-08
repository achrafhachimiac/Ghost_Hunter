"""
Tests for Ghost-Hunter RAG Core - Phase 1
=========================================
Tests pour contracts, embedder, vector_store, chunker.
"""

import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import tempfile


# ═══════════════════════════════════════════════════════════════
# CONTRACTS TESTS
# ═══════════════════════════════════════════════════════════════

class TestChunk:
    """Tests pour Chunk dataclass."""
    
    def test_chunk_creation(self):
        """Chunk peut être créé avec les metadata requises."""
        from ghost_hunter.core.rag.contracts import Chunk
        
        chunk = Chunk(
            id="test_1",
            text="Test content",
            metadata={
                "source": "test",
                "type": "technique",
                "vuln_type": "sqli",
                "indexed_at": datetime.now().isoformat()
            }
        )
        assert chunk.id == "test_1"
        assert chunk.source == "test"
        assert chunk.vuln_type == "sqli"
    
    def test_chunk_missing_metadata_raises(self):
        """Chunk sans metadata requise lève une erreur."""
        from ghost_hunter.core.rag.contracts import Chunk
        
        with pytest.raises(ValueError, match="Missing required metadata"):
            Chunk(
                id="test",
                text="content",
                metadata={"source": "test"}
            )
    
    def test_chunk_create_factory(self):
        """Chunk.create() génère un chunk valide."""
        from ghost_hunter.core.rag.contracts import Chunk
        
        chunk = Chunk.create(
            text="SQL injection example",
            source="hacktricks",
            chunk_type="technique",
            vuln_type="sqli"
        )
        assert "hacktricks" in chunk.id
        assert chunk.metadata["source"] == "hacktricks"
        assert "indexed_at" in chunk.metadata
    
    def test_chunk_to_dict(self):
        """Chunk.to_dict() fonctionne."""
        from ghost_hunter.core.rag.contracts import Chunk
        
        chunk = Chunk.create(
            text="Test",
            source="test",
            chunk_type="test",
            vuln_type="xss"
        )
        d = chunk.to_dict()
        assert "id" in d
        assert "text" in d
        assert "metadata" in d


class TestRAGQuery:
    """Tests pour RAGQuery."""
    
    def test_query_creation(self):
        """RAGQuery peut être créée."""
        from ghost_hunter.core.rag.contracts import RAGQuery
        
        query = RAGQuery(
            text="IDOR API endpoint",
            vuln_types=["idor"],
            top_k=5
        )
        assert query.text == "IDOR API endpoint"
        assert query.top_k == 5
    
    def test_query_to_filters_single_vuln(self):
        """to_filters() avec un seul vuln_type."""
        from ghost_hunter.core.rag.contracts import RAGQuery
        
        query = RAGQuery(text="test", vuln_types=["sqli"])
        filters = query.to_filters()
        # Le filtre inclut automatiquement l'exclusion des payloads
        assert "vuln_type" in str(filters)
        assert "sqli" in str(filters)
    
    def test_query_to_filters_multiple_vulns(self):
        """to_filters() avec plusieurs vuln_types."""
        from ghost_hunter.core.rag.contracts import RAGQuery
        
        query = RAGQuery(text="test", vuln_types=["sqli", "xss"])
        filters = query.to_filters()
        assert "$in" in str(filters)
    
    def test_query_to_filters_empty(self):
        """to_filters() retourne None sans filtres."""
        from ghost_hunter.core.rag.contracts import RAGQuery
        
        query = RAGQuery(text="test", include_payloads=True)
        filters = query.to_filters()
        assert filters is None


class TestRAGContext:
    """Tests pour RAGContext."""
    
    def test_context_creation(self):
        """RAGContext peut être créé."""
        from ghost_hunter.core.rag.contracts import RAGContext, RAGQuery, RAGResult, Chunk
        
        chunk = Chunk.create("test", "test", "test", "xss")
        result = RAGResult(chunk=chunk, score=0.8)
        query = RAGQuery(text="test")
        
        context = RAGContext(query=query, results=[result])
        assert len(context.results) == 1
        assert not context.is_empty
    
    def test_context_is_empty(self):
        """is_empty retourne True sans résultats."""
        from ghost_hunter.core.rag.contracts import RAGContext, RAGQuery
        
        context = RAGContext(query=RAGQuery(text="test"), results=[])
        assert context.is_empty
    
    def test_context_top_result(self):
        """top_result retourne le meilleur résultat."""
        from ghost_hunter.core.rag.contracts import RAGContext, RAGQuery, RAGResult, Chunk
        
        chunk1 = Chunk.create("test1", "test", "test", "xss")
        chunk2 = Chunk.create("test2", "test", "test", "sqli")
        results = [
            RAGResult(chunk=chunk1, score=0.6, weighted_score=0.6),
            RAGResult(chunk=chunk2, score=0.9, weighted_score=0.9),
        ]
        
        context = RAGContext(query=RAGQuery(text="test"), results=results)
        assert context.top_result.chunk.id == chunk2.id
    
    def test_context_formatted_context(self):
        """formatted_context génère du texte."""
        from ghost_hunter.core.rag.contracts import RAGContext, RAGQuery, RAGResult, Chunk
        
        chunk = Chunk.create("SQL injection payload", "hacktricks", "technique", "sqli")
        result = RAGResult(chunk=chunk, score=0.8, weighted_score=0.8)
        
        context = RAGContext(query=RAGQuery(text="sqli"), results=[result])
        assert "Relevant Knowledge" in context.formatted_context
        assert "hacktricks" in context.formatted_context


class TestIngestStats:
    """Tests pour IngestStats."""
    
    def test_ingest_stats(self):
        """IngestStats fonctionne."""
        from ghost_hunter.core.rag.contracts import IngestStats
        
        stats = IngestStats(
            source="hacktricks",
            chunks_added=100,
            chunks_updated=10,
            duration_ms=1500.0
        )
        assert stats.total_processed == 110
        assert stats.source == "hacktricks"
    
    def test_ingest_stats_to_dict(self):
        """IngestStats.to_dict() fonctionne."""
        from ghost_hunter.core.rag.contracts import IngestStats
        
        stats = IngestStats(source="test", chunks_added=50)
        d = stats.to_dict()
        assert d["source"] == "test"
        assert d["total_processed"] == 50


# ═══════════════════════════════════════════════════════════════
# CHUNKER TESTS
# ═══════════════════════════════════════════════════════════════

class TestChunker:
    """Tests pour le chunker."""
    
    def test_chunk_markdown_basic(self):
        """chunk_markdown() fonctionne sur du markdown basique."""
        from ghost_hunter.core.rag.chunker import chunk_markdown
        
        # Contenu assez long pour dépasser MIN_CHUNK_SIZE (50 tokens = ~200 chars)
        content = """
# SQL Injection

SQL injection is a code injection technique that might allow an attacker to interfere with 
the queries that an application makes to its database. It generally allows an attacker to view 
data that they are not normally able to retrieve. This might include data belonging to other users,
or any other data that the application itself is able to access.

## Basic SQLi

The most basic form of SQL injection uses single quotes to break out of the query context.
Attackers can then add their own SQL commands to manipulate the database behavior.

```sql
' OR 1=1 --
UNION SELECT username, password FROM users--
```

This payload demonstrates how attackers can bypass authentication or extract sensitive data.
"""
        chunks = chunk_markdown(content, source="test", vuln_type="sqli")
        assert len(chunks) > 0
        # Vérifie qu'on a des chunks
        types = [c.metadata["type"] for c in chunks]
        assert len(types) > 0
    
    def test_chunk_markdown_preserves_source(self):
        """Les chunks gardent la source."""
        from ghost_hunter.core.rag.chunker import chunk_markdown
        
        chunks = chunk_markdown(
            "# Test\n\nSome content here with enough text to be a chunk.",
            source="hacktricks",
            vuln_type="xss"
        )
        if chunks:
            assert all(c.source == "hacktricks" for c in chunks)
    
    def test_chunk_markdown_respects_limit(self):
        """Les chunks respectent la limite de tokens."""
        from ghost_hunter.core.rag.chunker import chunk_markdown, MAX_CHUNK_SIZE, CHARS_PER_TOKEN
        
        # Créer un long document
        long_content = "# Title\n\n" + "word " * 2000
        chunks = chunk_markdown(long_content, source="test", vuln_type="test")
        
        max_chars = MAX_CHUNK_SIZE * CHARS_PER_TOKEN
        for chunk in chunks:
            assert len(chunk.text) <= max_chars + 100  # Petite marge
    
    def test_chunk_yaml(self):
        """chunk_yaml() fonctionne."""
        from ghost_hunter.core.rag.chunker import chunk_yaml
        
        content = """
id: CVE-2021-12345
info:
  name: Test Vulnerability
  severity: high
  description: |
    A test vulnerability description that is long enough
    to be meaningful and will be chunked properly.
"""
        chunks = chunk_yaml(content, source="nuclei", vuln_type="sqli")
        # Peut être 0 si trop court, mais pas d'erreur
        assert isinstance(chunks, list)
    
    def test_chunk_text_basic(self):
        """chunk_text() fonctionne."""
        from ghost_hunter.core.rag.chunker import chunk_text
        
        content = "This is a test. " * 100  # ~300 words
        chunks = chunk_text(content, source="test", vuln_type="test")
        assert len(chunks) >= 1
    
    def test_chunk_empty_content(self):
        """Les fonctions gèrent le contenu vide."""
        from ghost_hunter.core.rag.chunker import chunk_markdown, chunk_yaml, chunk_text
        
        assert chunk_markdown("", "test", "test") == []
        assert chunk_yaml("", "test", "test") == []
        assert chunk_text("", "test", "test") == []
        assert chunk_markdown("   ", "test", "test") == []


class TestChunkerSections:
    """Tests pour l'extraction des sections markdown."""
    
    def test_extract_sections(self):
        """_extract_markdown_sections() extrait les sections."""
        from ghost_hunter.core.rag.chunker import _extract_markdown_sections
        
        content = """
# Title

Introduction text.

## Section 1

Content of section 1.

## Section 2

Content of section 2.
"""
        sections = _extract_markdown_sections(content)
        assert len(sections) >= 2
        titles = [s[0] for s in sections]
        assert "Section 1" in titles or "Title" in titles
    
    def test_extract_code_blocks(self):
        """_extract_code_blocks() extrait les blocs de code."""
        from ghost_hunter.core.rag.chunker import _extract_code_blocks
        
        content = """
Some text.

```python
print("hello")
```

More text.

```sql
SELECT * FROM users
```
"""
        blocks = _extract_code_blocks(content)
        assert len(blocks) == 2
        assert blocks[0][0] == "python"
        assert blocks[1][0] == "sql"


# ═══════════════════════════════════════════════════════════════
# EMBEDDER TESTS (with mocks)
# ═══════════════════════════════════════════════════════════════

class TestEmbedder:
    """Tests pour l'Embedder (avec mocks)."""
    
    def test_embedder_singleton(self):
        """get_instance() retourne un singleton."""
        # Reset first
        from ghost_hunter.core.rag import embedder as emb_module
        emb_module.Embedder._instance = None
        
        with patch.object(emb_module, 'SENTENCE_TRANSFORMERS_AVAILABLE', True):
            with patch.object(emb_module, 'SentenceTransformer'):
                e1 = emb_module.Embedder.get_instance()
                e2 = emb_module.Embedder.get_instance()
                assert e1 is e2
                
                # Cleanup
                emb_module.Embedder.reset_instance()
    
    def test_embedder_lazy_load(self):
        """Le modèle n'est pas chargé à l'instanciation."""
        from ghost_hunter.core.rag import embedder as emb_module
        emb_module.Embedder._instance = None
        
        with patch.object(emb_module, 'SENTENCE_TRANSFORMERS_AVAILABLE', True):
            mock_st = Mock()
            with patch.object(emb_module, 'SentenceTransformer', mock_st):
                e = emb_module.Embedder()
                # Model pas encore chargé
                assert e._model is None
                assert not e.is_loaded
                
                # Cleanup
                emb_module.Embedder.reset_instance()
    
    def test_embedder_constants(self):
        """Les constantes sont définies."""
        from ghost_hunter.core.rag.embedder import Embedder
        
        assert Embedder.DEFAULT_MODEL == "all-MiniLM-L6-v2"
        assert Embedder.EMBEDDING_DIM == 384


# ═══════════════════════════════════════════════════════════════
# VECTOR STORE TESTS (with mocks)
# ═══════════════════════════════════════════════════════════════

class TestVectorStoreManager:
    """Tests pour VectorStoreManager (avec mocks)."""
    
    def test_store_lazy_load(self):
        """Le store n'est pas chargé à l'instanciation."""
        from ghost_hunter.core.rag import vector_store as vs_module
        
        with patch.object(vs_module, 'CHROMADB_AVAILABLE', True):
            with patch.object(vs_module, 'chromadb'):
                store = vs_module.VectorStoreManager()
                assert not store.is_loaded
                assert store._client is None
    
    def test_store_singleton(self):
        """get_vector_store() retourne un singleton."""
        from ghost_hunter.core.rag import vector_store as vs_module
        
        # Reset
        vs_module._store_instance = None
        
        with patch.object(vs_module, 'CHROMADB_AVAILABLE', True):
            with patch.object(vs_module, 'chromadb'):
                s1 = vs_module.get_vector_store()
                s2 = vs_module.get_vector_store()
                assert s1 is s2
                
                # Cleanup
                vs_module.reset_vector_store()
    
    def test_store_stats(self):
        """stats() retourne les bonnes clés."""
        from ghost_hunter.core.rag import vector_store as vs_module
        
        with patch.object(vs_module, 'CHROMADB_AVAILABLE', True):
            with patch.object(vs_module, 'chromadb'):
                store = vs_module.VectorStoreManager()
                # Ne pas charger le store
                store._is_loaded = False
                
                stats = store.stats()
                assert "is_loaded" in stats
                assert "persist_path" in stats
                assert "total_chunks" in stats


class TestVectorStoreIntegration:
    """Tests d'intégration pour VectorStore (si ChromaDB disponible)."""
    
    @pytest.fixture
    def temp_store(self, tmp_path):
        """Crée un store temporaire."""
        try:
            import chromadb
            from ghost_hunter.core.rag.vector_store import VectorStoreManager
            
            store = VectorStoreManager(persist_path=tmp_path / "test_store")
            yield store
            store.close()
        except ImportError:
            pytest.skip("chromadb not installed")
    
    def test_upsert_and_query(self, temp_store):
        """Test upsert puis query."""
        try:
            import chromadb
            from ghost_hunter.core.rag.contracts import Chunk
            from ghost_hunter.core.rag.embedder import SENTENCE_TRANSFORMERS_AVAILABLE
            
            if not SENTENCE_TRANSFORMERS_AVAILABLE:
                pytest.skip("sentence-transformers not installed")
            
            # Créer des chunks
            chunks = [
                Chunk.create(
                    text="SQL injection is a code injection technique",
                    source="test",
                    chunk_type="technique",
                    vuln_type="sqli"
                ),
                Chunk.create(
                    text="XSS allows attackers to inject scripts",
                    source="test",
                    chunk_type="technique",
                    vuln_type="xss"
                ),
            ]
            
            # Upsert
            temp_store.upsert(chunks)
            
            # Verify count
            assert temp_store.count() == 2
            
            # Query
            context = temp_store.query_sync("SQL injection attack", top_k=2)
            assert len(context.results) > 0
            # Le premier résultat devrait être le chunk SQLi
            
        except ImportError:
            pytest.skip("Dependencies not installed")


# ═══════════════════════════════════════════════════════════════
# IMPORT TESTS
# ═══════════════════════════════════════════════════════════════

class TestRAGImports:
    """Tests d'imports du module RAG."""
    
    def test_import_contracts(self):
        """Contracts s'importent correctement."""
        from ghost_hunter.core.rag.contracts import (
            Chunk, RAGQuery, RAGResult, RAGContext,
            VulnType, SourceType, IngestStats
        )
        assert Chunk is not None
        assert RAGQuery is not None
    
    def test_import_chunker(self):
        """Chunker s'importe correctement."""
        from ghost_hunter.core.rag.chunker import (
            chunk_markdown, chunk_yaml, chunk_text, chunk_file
        )
        assert chunk_markdown is not None
    
    def test_import_main_module(self):
        """Le module principal s'importe."""
        from ghost_hunter.core import rag
        assert hasattr(rag, '__all__')
        assert "Chunk" in rag.__all__
        assert "get_vector_store" in rag.__all__


class TestVulnTypeEnum:
    """Tests pour l'enum VulnType."""
    
    def test_vuln_types_exist(self):
        """Les types de vulns communs existent."""
        from ghost_hunter.core.rag.contracts import VulnType
        
        assert VulnType.SQLI.value == "sqli"
        assert VulnType.XSS.value == "xss"
        assert VulnType.IDOR.value == "idor"
        assert VulnType.SSRF.value == "ssrf"
        assert VulnType.RCE.value == "rce"

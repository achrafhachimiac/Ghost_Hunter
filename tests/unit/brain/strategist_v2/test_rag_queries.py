"""
Tests pour rag_queries.py

TDD: Validation des queries RAG spécialisées.
Note: Ces tests mockent le RAGEngine pour éviter la dépendance au VectorStore.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from ghost_hunter.core.brain.strategist_v2.rag_queries import (
    RAGChunk,
    RAGQueryResult,
    get_waf_bypass_context,
    get_encoding_evasion_context,
    get_vuln_technique_context,
    get_combined_context,
    _execute_rag_query,
    _extract_keywords_from_patterns,
)


class TestRAGChunk:
    """Tests pour RAGChunk."""
    
    def test_creation(self):
        """Création d'un chunk."""
        chunk = RAGChunk(
            content="Some WAF bypass technique...",
            source="hacktricks/waf.md",
            relevance=0.85
        )
        assert chunk.content == "Some WAF bypass technique..."
        assert chunk.source == "hacktricks/waf.md"
        assert chunk.relevance == 0.85
    
    def test_str_truncates(self):
        """__str__ tronque le contenu."""
        chunk = RAGChunk(
            content="x" * 200,
            source="test.md"
        )
        result = str(chunk)
        assert len(result) < 200
        assert "test.md" in result


class TestRAGQueryResult:
    """Tests pour RAGQueryResult."""
    
    def test_empty_result(self):
        """Résultat vide formaté correctement."""
        result = RAGQueryResult(chunks=[], query="test")
        formatted = result.to_formatted_string()
        assert "_No relevant context found_" in formatted
    
    def test_with_chunks(self):
        """Résultat avec chunks formaté correctement."""
        result = RAGQueryResult(
            chunks=[
                RAGChunk(content="Technique 1", source="source1.md"),
                RAGChunk(content="Technique 2", source="source2.md"),
            ],
            query="test",
            total_tokens=50
        )
        formatted = result.to_formatted_string()
        
        assert "Source 1" in formatted
        assert "source1.md" in formatted
        assert "Technique 1" in formatted
        assert "Source 2" in formatted


class TestExtractKeywords:
    """Tests pour _extract_keywords_from_patterns."""
    
    def test_extracts_sql_keywords(self):
        """Extrait les mots-clés SQL."""
        patterns = ["url:SELECT * FROM users", "none:UNION ALL"]
        keywords = _extract_keywords_from_patterns(patterns)
        
        assert "SELECT" in keywords or "UNION" in keywords
    
    def test_extracts_xss_keywords(self):
        """Extrait les mots-clés XSS."""
        patterns = ["none:<script>alert(1)</script>"]
        keywords = _extract_keywords_from_patterns(patterns)
        
        assert "script" in keywords or "alert" in keywords
    
    def test_limits_keywords(self):
        """Limite le nombre de mots-clés."""
        patterns = [
            "SELECT UNION INSERT UPDATE DELETE script alert onerror"
        ]
        keywords = _extract_keywords_from_patterns(patterns)
        
        assert len(keywords) <= 5
    
    def test_empty_patterns(self):
        """Gère les patterns vides."""
        keywords = _extract_keywords_from_patterns([])
        assert keywords == []


class TestGetWafBypassContext:
    """Tests pour get_waf_bypass_context."""
    
    @patch('ghost_hunter.core.brain.strategist_v2.rag_queries._execute_rag_query')
    def test_queries_with_provider(self, mock_execute):
        """Query avec provider WAF spécifique."""
        mock_execute.return_value = RAGQueryResult(chunks=[], query="")
        
        get_waf_bypass_context(
            waf_provider="cloudflare",
            blocked_patterns=["pattern1"],
            max_chunks=5
        )
        
        # Vérifier que la query contient cloudflare
        call_args = mock_execute.call_args
        query = call_args[0][0]
        assert "cloudflare" in query.lower()
        assert "WAF bypass" in query
    
    @patch('ghost_hunter.core.brain.strategist_v2.rag_queries._execute_rag_query')
    def test_queries_without_provider(self, mock_execute):
        """Query sans provider WAF spécifique."""
        mock_execute.return_value = RAGQueryResult(chunks=[], query="")
        
        get_waf_bypass_context(
            waf_provider=None,
            blocked_patterns=[],
            max_chunks=3
        )
        
        call_args = mock_execute.call_args
        query = call_args[0][0]
        assert "WAF bypass" in query


class TestGetEncodingEvasionContext:
    """Tests pour get_encoding_evasion_context."""
    
    @patch('ghost_hunter.core.brain.strategist_v2.rag_queries._execute_rag_query')
    def test_suggests_alternatives(self, mock_execute):
        """Suggère des alternatives aux encodings échoués."""
        mock_execute.return_value = RAGQueryResult(chunks=[], query="")
        
        get_encoding_evasion_context(
            failed_encodings=["url"],
            vuln_class="SQLi",
            max_chunks=3
        )
        
        call_args = mock_execute.call_args
        query = call_args[0][0]
        # Doit suggérer des alternatives à URL encoding
        assert "encoding" in query.lower()
        assert "SQLi" in query


class TestGetVulnTechniqueContext:
    """Tests pour get_vuln_technique_context."""
    
    @patch('ghost_hunter.core.brain.strategist_v2.rag_queries._execute_rag_query')
    def test_includes_vuln_keywords(self, mock_execute):
        """Inclut les mots-clés spécifiques à la vuln."""
        mock_execute.return_value = RAGQueryResult(chunks=[], query="")
        
        get_vuln_technique_context(
            vuln_class="IDOR",
            working_techniques=["ID decrement"],
            max_chunks=5
        )
        
        call_args = mock_execute.call_args
        query = call_args[0][0]
        assert "IDOR" in query
        # Peut contenir des mots-clés IDOR
        assert "privilege" in query.lower() or "object" in query.lower() or "IDOR" in query


class TestGetCombinedContext:
    """Tests pour get_combined_context."""
    
    @patch('ghost_hunter.core.brain.strategist_v2.rag_queries.get_waf_bypass_context')
    @patch('ghost_hunter.core.brain.strategist_v2.rag_queries.get_encoding_evasion_context')
    @patch('ghost_hunter.core.brain.strategist_v2.rag_queries.get_vuln_technique_context')
    def test_combines_all_contexts(
        self, mock_vuln, mock_encoding, mock_waf
    ):
        """Combine tous les contextes."""
        mock_waf.return_value = RAGQueryResult(
            chunks=[RAGChunk(content="WAF bypass", source="waf.md")],
            query=""
        )
        mock_encoding.return_value = RAGQueryResult(
            chunks=[RAGChunk(content="Encoding trick", source="enc.md")],
            query=""
        )
        mock_vuln.return_value = RAGQueryResult(
            chunks=[RAGChunk(content="Vuln technique", source="vuln.md")],
            query=""
        )
        
        result = get_combined_context(
            waf_provider="cloudflare",
            vuln_class="SQLi",
            blocked_patterns=["pattern"],
            failed_encodings=["url"],
            working_techniques=["unicode"],
            max_total_chunks=10
        )
        
        assert "WAF Bypass" in result
        assert "WAF bypass" in result
        assert "Encoding" in result
        assert "SQLi" in result
    
    @patch('ghost_hunter.core.brain.strategist_v2.rag_queries.get_waf_bypass_context')
    @patch('ghost_hunter.core.brain.strategist_v2.rag_queries.get_encoding_evasion_context')
    @patch('ghost_hunter.core.brain.strategist_v2.rag_queries.get_vuln_technique_context')
    def test_handles_empty_results(
        self, mock_vuln, mock_encoding, mock_waf
    ):
        """Gère les résultats vides."""
        mock_waf.return_value = RAGQueryResult(chunks=[], query="")
        mock_encoding.return_value = RAGQueryResult(chunks=[], query="")
        mock_vuln.return_value = RAGQueryResult(chunks=[], query="")
        
        result = get_combined_context(
            waf_provider=None,
            vuln_class="XSS",
            blocked_patterns=[],
            failed_encodings=[],
            working_techniques=[],
        )
        
        assert "No relevant context" in result


class TestExecuteRAGQuery:
    """Tests pour _execute_rag_query."""
    
    @patch('ghost_hunter.core.rag.engine.RAGEngine')
    def test_returns_empty_when_unavailable(self, mock_engine_class):
        """Retourne vide si RAG indisponible."""
        mock_engine = MagicMock()
        mock_engine.is_available.return_value = False
        mock_engine_class.return_value = mock_engine
        
        result = _execute_rag_query("test query", 5, "test")
        
        assert result.chunks == []
        assert result.query == "test query"
    
    @patch('ghost_hunter.core.rag.engine.RAGEngine')
    def test_returns_chunks_when_available(self, mock_engine_class):
        """Retourne des chunks si RAG disponible."""
        mock_engine = MagicMock()
        mock_engine.is_available.return_value = True
        mock_engine.store.query.return_value = {
            "documents": [["Doc 1", "Doc 2"]],
            "metadatas": [[{"source": "s1.md"}, {"source": "s2.md"}]],
            "distances": [[0.1, 0.2]],
        }
        mock_engine_class.return_value = mock_engine
        
        result = _execute_rag_query("test query", 5, "test")
        
        assert len(result.chunks) == 2
        assert result.chunks[0].content == "Doc 1"
        assert result.chunks[0].source == "s1.md"
    
    @patch('ghost_hunter.core.rag.engine.RAGEngine')
    def test_handles_exception(self, mock_engine_class):
        """Gère les exceptions."""
        mock_engine_class.side_effect = Exception("RAG error")
        
        result = _execute_rag_query("test query", 5, "test")
        
        assert result.chunks == []

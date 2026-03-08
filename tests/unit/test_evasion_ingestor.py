"""
Tests Phase 7: WAF Evasion RAG Ingestor
=======================================
Intégration des patterns d'évasion dans le RAG.
"""

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path


class TestEvasionIngestorInit:
    """Test initialisation de l'ingesteur."""
    
    def test_ingestor_import(self):
        """Ingesteur peut être importé."""
        from ghost_hunter.core.rag.ingestors.evasion import EvasionIngestor
        assert EvasionIngestor is not None
    
    def test_ingestor_create(self):
        """Ingesteur peut être instancié."""
        from ghost_hunter.core.rag.ingestors.evasion import EvasionIngestor
        ingestor = EvasionIngestor()
        assert ingestor is not None


class TestEvasionChunkGeneration:
    """Test génération des chunks."""
    
    def test_generate_chunks_from_transforms(self):
        """Génère chunks depuis transforms."""
        from ghost_hunter.core.rag.ingestors.evasion import EvasionIngestor
        ingestor = EvasionIngestor()
        
        chunks = ingestor.generate_transform_chunks()
        
        assert len(chunks) > 0
        # Chaque chunk a le bon format
        for chunk in chunks:
            assert "content" in chunk
            assert "metadata" in chunk
    
    def test_chunks_have_vuln_type_metadata(self):
        """Chunks ont le type de vuln en metadata."""
        from ghost_hunter.core.rag.ingestors.evasion import EvasionIngestor
        ingestor = EvasionIngestor()
        
        chunks = ingestor.generate_transform_chunks()
        
        for chunk in chunks:
            assert "vuln_type" in chunk["metadata"] or "vuln_types" in chunk["metadata"]
    
    def test_generate_waf_pattern_chunks(self, tmp_path):
        """Génère chunks depuis patterns WAF."""
        from ghost_hunter.core.rag.ingestors.evasion import EvasionIngestor
        
        # Crée un fichier YAML de test minimal
        test_yaml = tmp_path / "test_patterns.yaml"
        test_yaml.write_text("""
patterns:
  - id: test1
    pattern: "UNION.*SELECT"
    vuln_type: sqli
  - id: test2
    pattern: "<script>"
    vuln_type: xss
""")
        
        ingestor = EvasionIngestor(patterns_path=test_yaml)
        chunks = ingestor.generate_waf_pattern_chunks(max_patterns=100)
        
        assert isinstance(chunks, list)
        assert len(chunks) >= 1  # Au moins sqli et xss


class TestRAGIntegration:
    """Test intégration RAG."""
    
    def test_chunks_format_for_rag(self):
        """Format compatible avec RAG Engine."""
        from ghost_hunter.core.rag.ingestors.evasion import EvasionIngestor
        ingestor = EvasionIngestor()
        
        chunks = ingestor.generate_transform_chunks()
        
        # Format attendu par RAG
        for chunk in chunks:
            assert isinstance(chunk["content"], str)
            assert isinstance(chunk["metadata"], dict)
            assert len(chunk["content"]) > 0
    
    def test_query_evasion_techniques(self):
        """Peut requêter les techniques d'évasion."""
        from ghost_hunter.core.rag.ingestors.evasion import EvasionIngestor
        ingestor = EvasionIngestor()
        
        # Simule une requête
        chunks = ingestor.generate_transform_chunks()
        
        # Cherche SQLi evasion
        sqli_chunks = [
            c for c in chunks 
            if "sqli" in str(c.get("metadata", {})).lower()
        ]
        
        assert len(sqli_chunks) > 0

"""
Tests for Ghost-Hunter RAG Setup (Phase 0)
==========================================
Vérifie que la structure de base du RAG est correctement installée.
"""

import pytest
import yaml
from pathlib import Path


class TestRAGDirectoryStructure:
    """Tests pour la structure des dossiers."""
    
    @pytest.fixture
    def knowledge_dir(self):
        return Path(__file__).parent.parent.parent / "knowledge"
    
    def test_knowledge_dir_exists(self, knowledge_dir):
        """knowledge/ doit exister."""
        assert knowledge_dir.exists(), "knowledge/ directory missing"
    
    def test_embeddings_dir_exists(self, knowledge_dir):
        """knowledge/embeddings/ doit exister."""
        embeddings_dir = knowledge_dir / "embeddings"
        assert embeddings_dir.exists(), "knowledge/embeddings/ missing"
    
    def test_config_dir_exists(self, knowledge_dir):
        """knowledge/config/ doit exister."""
        config_dir = knowledge_dir / "config"
        assert config_dir.exists(), "knowledge/config/ missing"
    
    def test_personal_reports_dir_exists(self, knowledge_dir):
        """knowledge/personal_reports/ doit exister."""
        reports_dir = knowledge_dir / "personal_reports"
        assert reports_dir.exists(), "knowledge/personal_reports/ missing"
    
    def test_sources_dir_exists(self, knowledge_dir):
        """knowledge/sources/ doit exister."""
        sources_dir = knowledge_dir / "sources"
        assert sources_dir.exists(), "knowledge/sources/ missing"
    
    def test_gitkeep_in_embeddings(self, knowledge_dir):
        """knowledge/embeddings/.gitkeep doit exister."""
        gitkeep = knowledge_dir / "embeddings" / ".gitkeep"
        assert gitkeep.exists(), ".gitkeep missing in embeddings/"


class TestRAGConfigFiles:
    """Tests pour les fichiers de configuration YAML."""
    
    @pytest.fixture
    def config_dir(self):
        return Path(__file__).parent.parent.parent / "knowledge" / "config"
    
    def test_sources_yaml_exists(self, config_dir):
        """sources.yaml doit exister."""
        sources_file = config_dir / "sources.yaml"
        assert sources_file.exists(), "sources.yaml missing"
    
    def test_sources_yaml_parsable(self, config_dir):
        """sources.yaml doit être parsable."""
        sources_file = config_dir / "sources.yaml"
        with open(sources_file, 'r') as f:
            data = yaml.safe_load(f)
        assert "sources" in data, "sources.yaml missing 'sources' key"
    
    def test_sources_yaml_has_nvd(self, config_dir):
        """sources.yaml doit avoir la source NVD."""
        sources_file = config_dir / "sources.yaml"
        with open(sources_file, 'r') as f:
            data = yaml.safe_load(f)
        assert "nvd" in data["sources"], "NVD source missing"
    
    def test_sources_yaml_has_hacktricks(self, config_dir):
        """sources.yaml doit avoir la source HackTricks."""
        sources_file = config_dir / "sources.yaml"
        with open(sources_file, 'r') as f:
            data = yaml.safe_load(f)
        assert "hacktricks" in data["sources"], "HackTricks source missing"
    
    def test_weights_yaml_exists(self, config_dir):
        """weights.yaml doit exister."""
        weights_file = config_dir / "weights.yaml"
        assert weights_file.exists(), "weights.yaml missing"
    
    def test_weights_yaml_parsable(self, config_dir):
        """weights.yaml doit être parsable."""
        weights_file = config_dir / "weights.yaml"
        with open(weights_file, 'r') as f:
            data = yaml.safe_load(f)
        assert "source_weights" in data, "weights.yaml missing 'source_weights'"
    
    def test_vuln_taxonomy_yaml_exists(self, config_dir):
        """vuln_taxonomy.yaml doit exister."""
        taxonomy_file = config_dir / "vuln_taxonomy.yaml"
        assert taxonomy_file.exists(), "vuln_taxonomy.yaml missing"
    
    def test_vuln_taxonomy_has_sqli(self, config_dir):
        """vuln_taxonomy.yaml doit avoir SQLi."""
        taxonomy_file = config_dir / "vuln_taxonomy.yaml"
        with open(taxonomy_file, 'r') as f:
            data = yaml.safe_load(f)
        assert "sqli" in data.get("vuln_types", {}), "SQLi missing from taxonomy"
    
    def test_cwe_web_filter_yaml_exists(self, config_dir):
        """cwe_web_filter.yaml doit exister."""
        cwe_file = config_dir / "cwe_web_filter.yaml"
        assert cwe_file.exists(), "cwe_web_filter.yaml missing"
    
    def test_cwe_web_filter_has_injection(self, config_dir):
        """cwe_web_filter.yaml doit avoir les CWE injection."""
        cwe_file = config_dir / "cwe_web_filter.yaml"
        with open(cwe_file, 'r') as f:
            data = yaml.safe_load(f)
        assert "injection" in data.get("web_cwe", {}), "Injection CWEs missing"


class TestRAGModuleImports:
    """Tests pour les imports du module RAG."""
    
    def test_import_rag_module(self):
        """ghost_hunter.core.rag doit s'importer."""
        from ghost_hunter.core import rag
        assert rag is not None
    
    def test_import_get_rag_engine(self):
        """get_rag_engine doit être importable."""
        from ghost_hunter.core.rag import get_rag_engine
        assert callable(get_rag_engine)
    
    def test_import_ingestors_module(self):
        """ghost_hunter.core.rag.ingestors doit s'importer."""
        from ghost_hunter.core.rag import ingestors
        assert ingestors is not None
    
    def test_import_base_ingestor(self):
        """BaseIngestor doit être importable."""
        from ghost_hunter.core.rag.ingestors import BaseIngestor
        assert BaseIngestor is not None
    
    def test_import_ingestor_registry(self):
        """IngestorRegistry doit être importable."""
        from ghost_hunter.core.rag.ingestors import IngestorRegistry
        assert IngestorRegistry is not None
    
    def test_import_ingestor_config(self):
        """IngestorConfig doit être importable."""
        from ghost_hunter.core.rag.ingestors import IngestorConfig
        assert IngestorConfig is not None


class TestGitignore:
    """Tests pour le .gitignore."""
    
    @pytest.fixture
    def gitignore_path(self):
        return Path(__file__).parent.parent.parent / "knowledge" / ".gitignore"
    
    def test_gitignore_exists(self, gitignore_path):
        """.gitignore doit exister dans knowledge/."""
        assert gitignore_path.exists(), "knowledge/.gitignore missing"
    
    def test_gitignore_excludes_sources(self, gitignore_path):
        """.gitignore doit exclure sources/."""
        content = gitignore_path.read_text()
        assert "sources/" in content, "sources/ not in .gitignore"
    
    def test_gitignore_excludes_sqlite(self, gitignore_path):
        """.gitignore doit exclure *.sqlite3."""
        content = gitignore_path.read_text()
        assert "sqlite3" in content.lower(), "sqlite3 not in .gitignore"

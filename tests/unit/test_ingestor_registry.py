"""
Tests for Ghost-Hunter Ingestor Registry (Phase 0)
==================================================
Vérifie le système de plugins pour les ingestors.
"""

import pytest
from pathlib import Path
from typing import Generator, Dict, Any
from datetime import datetime

from ghost_hunter.core.rag.ingestors import (
    BaseIngestor,
    IngestorConfig,
    IngestorRegistry,
)
from ghost_hunter.core.rag.ingestors.base import Chunk


class TestIngestorConfig:
    """Tests pour IngestorConfig."""
    
    def test_config_creation(self):
        """IngestorConfig peut être créé."""
        config = IngestorConfig(
            name="test",
            enabled=True,
            weight=1.0,
            sync_interval="daily"
        )
        assert config.name == "test"
        assert config.enabled == True
        assert config.weight == 1.0
    
    def test_config_from_dict(self):
        """IngestorConfig.from_dict() fonctionne."""
        data = {
            "enabled": True,
            "weight": 1.5,
            "sync_interval": "weekly",
            "custom_param": "value"
        }
        config = IngestorConfig.from_dict("test_source", data)
        assert config.name == "test_source"
        assert config.weight == 1.5
        assert config.params["custom_param"] == "value"
    
    def test_config_defaults(self):
        """IngestorConfig a des valeurs par défaut."""
        config = IngestorConfig(name="test")
        assert config.enabled == True
        assert config.weight == 1.0
        assert config.sync_interval == "manual"


class TestChunk:
    """Tests pour Chunk dataclass."""
    
    def test_chunk_creation(self):
        """Chunk peut être créé avec les metadata requises."""
        chunk = Chunk(
            id="test_chunk_1",
            text="Test content",
            metadata={
                "source": "test",
                "type": "technique",
                "vuln_type": "sqli",
                "indexed_at": datetime.now().isoformat()
            }
        )
        assert chunk.id == "test_chunk_1"
        assert chunk.text == "Test content"
    
    def test_chunk_missing_metadata_raises(self):
        """Chunk sans metadata requise lève une erreur."""
        with pytest.raises(ValueError, match="Missing required metadata"):
            Chunk(
                id="test",
                text="content",
                metadata={"source": "test"}  # Missing type, vuln_type, indexed_at
            )
    
    def test_chunk_create_factory(self):
        """Chunk.create() génère un chunk valide."""
        chunk = Chunk.create(
            text="SQL injection example",
            source="hacktricks",
            chunk_type="technique",
            vuln_type="sqli"
        )
        assert "hacktricks" in chunk.id
        assert "sqli" in chunk.id
        assert chunk.metadata["source"] == "hacktricks"
        assert "indexed_at" in chunk.metadata


class TestBaseIngestor:
    """Tests pour BaseIngestor interface."""
    
    def test_base_ingestor_is_abstract(self):
        """BaseIngestor ne peut pas être instancié directement."""
        config = IngestorConfig(name="test")
        with pytest.raises(TypeError):
            BaseIngestor(config)
    
    def test_base_ingestor_requires_sync(self):
        """Une sous-classe doit implémenter sync()."""
        class IncompleteIngestor(BaseIngestor):
            source_type = "test"
            def ingest(self):
                pass
            def get_stats(self):
                pass
        
        config = IngestorConfig(name="test")
        with pytest.raises(TypeError):
            IncompleteIngestor(config)
    
    def test_concrete_ingestor_works(self):
        """Un ingestor concret peut être instancié."""
        class ConcreteIngestor(BaseIngestor):
            source_type = "test"
            
            def sync(self) -> None:
                pass
            
            def ingest(self) -> Generator[Chunk, None, None]:
                yield Chunk.create(
                    text="test",
                    source="test",
                    chunk_type="test",
                    vuln_type="test"
                )
            
            def get_stats(self) -> Dict[str, Any]:
                return {"chunks_count": 1}
        
        config = IngestorConfig(name="test")
        ingestor = ConcreteIngestor(config)
        assert ingestor.name == "test"
        assert ingestor.is_enabled == True


class TestIngestorRegistry:
    """Tests pour IngestorRegistry."""
    
    def setup_method(self):
        """Clear registry before each test."""
        IngestorRegistry.clear()
    
    def teardown_method(self):
        """Clear registry after each test."""
        IngestorRegistry.clear()
    
    def test_register_decorator(self):
        """@IngestorRegistry.register() enregistre un ingestor."""
        @IngestorRegistry.register("test_source")
        class TestIngestor(BaseIngestor):
            source_type = "test"
            def sync(self): pass
            def ingest(self): yield from []
            def get_stats(self): return {}
        
        assert "test_source" in IngestorRegistry.list_available()
    
    def test_get_registered_ingestor(self):
        """IngestorRegistry.get() retourne la classe enregistrée."""
        @IngestorRegistry.register("my_source")
        class MyIngestor(BaseIngestor):
            source_type = "test"
            def sync(self): pass
            def ingest(self): yield from []
            def get_stats(self): return {}
        
        cls = IngestorRegistry.get("my_source")
        assert cls == MyIngestor
    
    def test_get_unregistered_returns_none(self):
        """IngestorRegistry.get() retourne None pour un nom inconnu."""
        result = IngestorRegistry.get("nonexistent")
        assert result is None
    
    def test_list_available(self):
        """IngestorRegistry.list_available() liste les ingestors."""
        @IngestorRegistry.register("source_a")
        class IngestorA(BaseIngestor):
            source_type = "test"
            def sync(self): pass
            def ingest(self): yield from []
            def get_stats(self): return {}
        
        @IngestorRegistry.register("source_b")
        class IngestorB(BaseIngestor):
            source_type = "test"
            def sync(self): pass
            def ingest(self): yield from []
            def get_stats(self): return {}
        
        available = IngestorRegistry.list_available()
        assert "source_a" in available
        assert "source_b" in available
    
    def test_clear_registry(self):
        """IngestorRegistry.clear() vide le registry."""
        @IngestorRegistry.register("to_clear")
        class ToClearIngestor(BaseIngestor):
            source_type = "test"
            def sync(self): pass
            def ingest(self): yield from []
            def get_stats(self): return {}
        
        assert len(IngestorRegistry.list_available()) > 0
        IngestorRegistry.clear()
        assert len(IngestorRegistry.list_available()) == 0
    
    def test_load_from_config(self, tmp_path):
        """IngestorRegistry.load_from_config() charge depuis YAML."""
        # Créer un ingestor test
        @IngestorRegistry.register("test_yaml_source")
        class YamlTestIngestor(BaseIngestor):
            source_type = "test"
            def sync(self): pass
            def ingest(self): yield from []
            def get_stats(self): return {}
        
        # Créer un fichier YAML temporaire
        yaml_content = """
sources:
  test_yaml_source:
    enabled: true
    weight: 1.2
    sync_interval: daily
  disabled_source:
    enabled: false
    weight: 1.0
"""
        config_file = tmp_path / "sources.yaml"
        config_file.write_text(yaml_content)
        
        # Charger
        ingestors = IngestorRegistry.load_from_config(config_file)
        
        # Vérifier
        assert len(ingestors) == 1
        assert ingestors[0].name == "test_yaml_source"
        assert ingestors[0].weight == 1.2
    
    def test_unregister(self):
        """IngestorRegistry.unregister() supprime un ingestor."""
        @IngestorRegistry.register("to_remove")
        class ToRemoveIngestor(BaseIngestor):
            source_type = "test"
            def sync(self): pass
            def ingest(self): yield from []
            def get_stats(self): return {}
        
        assert "to_remove" in IngestorRegistry.list_available()
        IngestorRegistry.unregister("to_remove")
        assert "to_remove" not in IngestorRegistry.list_available()


class TestIngestorExtensibility:
    """Tests pour l'extensibilité du système d'ingestors."""
    
    def setup_method(self):
        IngestorRegistry.clear()
    
    def teardown_method(self):
        IngestorRegistry.clear()
    
    def test_custom_ingestor_inherits_base(self):
        """Un ingestor custom hérite bien de BaseIngestor."""
        @IngestorRegistry.register("custom")
        class CustomIngestor(BaseIngestor):
            source_type = "custom"
            
            def sync(self) -> None:
                self._synced = True
            
            def ingest(self) -> Generator[Chunk, None, None]:
                yield Chunk.create(
                    text="Custom content",
                    source="custom",
                    chunk_type="custom",
                    vuln_type="sqli"
                )
            
            def get_stats(self) -> Dict[str, Any]:
                return {"custom_stat": 42}
        
        config = IngestorConfig(name="custom", weight=1.5)
        ingestor = CustomIngestor(config)
        
        assert isinstance(ingestor, BaseIngestor)
        assert ingestor.weight == 1.5
    
    def test_ingestor_validate_chunk(self):
        """validate_chunk() fonctionne correctement."""
        @IngestorRegistry.register("validator_test")
        class ValidatorIngestor(BaseIngestor):
            source_type = "test"
            def sync(self): pass
            def ingest(self): yield from []
            def get_stats(self): return {}
        
        config = IngestorConfig(name="validator_test")
        ingestor = ValidatorIngestor(config)
        
        # Chunk valide
        valid_chunk = Chunk.create(
            text="Valid content with enough text",
            source="test",
            chunk_type="test",
            vuln_type="xss"
        )
        assert ingestor.validate_chunk(valid_chunk) == True
        
        # Chunk avec texte trop court
        short_chunk = Chunk(
            id="short",
            text="abc",  # < 10 chars
            metadata={
                "source": "test",
                "type": "test",
                "vuln_type": "test",
                "indexed_at": datetime.now().isoformat()
            }
        )
        assert ingestor.validate_chunk(short_chunk) == False
    
    def test_ingestor_apply_weight(self):
        """apply_weight() applique le poids correctement."""
        @IngestorRegistry.register("weight_test")
        class WeightIngestor(BaseIngestor):
            source_type = "test"
            def sync(self): pass
            def ingest(self): yield from []
            def get_stats(self): return {}
        
        config = IngestorConfig(name="weight_test", weight=1.5)
        ingestor = WeightIngestor(config)
        
        weighted_score = ingestor.apply_weight(0.8)
        assert weighted_score == 0.8 * 1.5  # 1.2

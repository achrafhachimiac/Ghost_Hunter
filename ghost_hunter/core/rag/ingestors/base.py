"""
Ghost-Hunter RAG Base Ingestor
==============================
Interface abstraite pour tous les ingestors de sources.

Usage:
    @IngestorRegistry.register("my_source")
    class MySourceIngestor(BaseIngestor):
        source_type = "api"
        
        def sync(self) -> None:
            # Download/update data
            pass
        
        def ingest(self) -> Generator[Chunk, None, None]:
            # Yield chunks
            pass
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Generator, Optional, Any, Dict
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class IngestorConfig:
    """Configuration d'un ingestor chargée depuis sources.yaml."""
    name: str
    enabled: bool = True
    weight: float = 1.0
    sync_interval: str = "manual"  # daily, weekly, monthly, manual, auto
    params: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, name: str, data: dict) -> "IngestorConfig":
        """Crée une config depuis un dict YAML."""
        return cls(
            name=name,
            enabled=data.get("enabled", True),
            weight=data.get("weight", 1.0),
            sync_interval=data.get("sync_interval", "manual"),
            params=data
        )


@dataclass 
class Chunk:
    """
    Un chunk de texte à indexer dans le vector store.
    
    Attributes:
        id: Identifiant unique (format: {source}_{category}_{hash8})
        text: Contenu textuel du chunk
        metadata: Métadonnées obligatoires + optionnelles
    """
    id: str
    text: str
    metadata: Dict[str, Any]
    
    # Metadata obligatoires
    REQUIRED_METADATA = ["source", "type", "vuln_type", "indexed_at"]
    
    def __post_init__(self):
        """Valide les metadata obligatoires."""
        missing = [k for k in self.REQUIRED_METADATA if k not in self.metadata]
        if missing:
            raise ValueError(f"Missing required metadata: {missing}")
    
    @classmethod
    def create(
        cls,
        text: str,
        source: str,
        chunk_type: str,
        vuln_type: str,
        chunk_id: Optional[str] = None,
        **extra_metadata
    ) -> "Chunk":
        """Factory method pour créer un chunk avec les metadata requises."""
        import hashlib
        
        if chunk_id is None:
            hash8 = hashlib.sha256(text.encode()).hexdigest()[:8]
            chunk_id = f"{source}_{vuln_type}_{hash8}"
        
        metadata = {
            "source": source,
            "type": chunk_type,
            "vuln_type": vuln_type,
            "indexed_at": datetime.now().isoformat(),
            **extra_metadata
        }
        
        return cls(id=chunk_id, text=text, metadata=metadata)


class BaseIngestor(ABC):
    """
    Interface abstraite pour tous les ingestors.
    
    Chaque source (NVD, HackTricks, Personal Reports, etc.) 
    implémente cette interface.
    """
    
    # À override dans les sous-classes
    source_type: str = "unknown"  # api, git, local, scraper
    
    def __init__(self, config: IngestorConfig):
        """
        Args:
            config: Configuration chargée depuis sources.yaml
        """
        self.config = config
        self.name = config.name
        self.weight = config.weight
        self._last_sync: Optional[datetime] = None
        self._stats: Dict[str, Any] = {}
    
    @abstractmethod
    def sync(self) -> None:
        """
        Synchronise la source (download, git pull, fetch API, etc.).
        
        Cette méthode doit être idempotente et peut être appelée
        plusieurs fois sans effet de bord.
        
        Raises:
            SyncError: Si la synchronisation échoue
        """
        pass
    
    @abstractmethod
    def ingest(self) -> Generator[Chunk, None, None]:
        """
        Génère les chunks à indexer.
        
        Yields:
            Chunk: Chunks prêts à être indexés
            
        Note:
            Utilise un generator pour le streaming et éviter
            de charger tout en mémoire.
        """
        pass
    
    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """
        Retourne les statistiques de la source.
        
        Returns:
            dict avec au minimum:
            - chunks_count: Nombre de chunks
            - last_sync: Dernière sync (ISO timestamp ou None)
            - size_bytes: Taille approximative
        """
        pass
    
    def validate_chunk(self, chunk: Chunk) -> bool:
        """
        Valide qu'un chunk a toutes les metadata requises.
        
        Args:
            chunk: Chunk à valider
            
        Returns:
            True si valide, False sinon
        """
        try:
            # La validation est faite dans __post_init__
            # Mais on peut ajouter des validations supplémentaires ici
            if not chunk.text or len(chunk.text.strip()) < 10:
                logger.warning(f"Chunk {chunk.id} has empty or too short text")
                return False
            return True
        except Exception as e:
            logger.warning(f"Chunk validation failed: {e}")
            return False
    
    def apply_weight(self, score: float) -> float:
        """
        Applique le poids de la source au score de similarité.
        
        Args:
            score: Score de similarité (0-1)
            
        Returns:
            Score pondéré
        """
        return score * self.weight
    
    @property
    def is_enabled(self) -> bool:
        """Retourne si l'ingestor est activé."""
        return self.config.enabled
    
    @property
    def last_sync(self) -> Optional[datetime]:
        """Retourne la date de dernière sync."""
        return self._last_sync
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} enabled={self.is_enabled}>"


class SyncError(Exception):
    """Erreur lors de la synchronisation d'une source."""
    pass


class IngestError(Exception):
    """Erreur lors de l'ingestion des données."""
    pass

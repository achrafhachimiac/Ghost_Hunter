"""
Ghost-Hunter RAG Ingestor Registry
==================================
Registry pour découvrir et charger les ingestors dynamiquement.

Usage:
    # Enregistrer un ingestor
    @IngestorRegistry.register("hacktricks")
    class HackTricksIngestor(BaseIngestor):
        ...
    
    # Charger depuis config
    ingestors = IngestorRegistry.load_from_config(sources_yaml_path)
    
    # Lister les disponibles
    available = IngestorRegistry.list_available()
"""

from typing import Dict, Type, List, Optional
from pathlib import Path
import yaml
import logging

from .base import BaseIngestor, IngestorConfig

logger = logging.getLogger(__name__)


class IngestorRegistry:
    """
    Registry singleton pour les ingestors.
    
    Permet de:
    - Enregistrer des ingestors via décorateur
    - Charger dynamiquement depuis la config YAML
    - Lister les ingestors disponibles
    """
    
    _ingestors: Dict[str, Type[BaseIngestor]] = {}
    _instances: Dict[str, BaseIngestor] = {}
    
    @classmethod
    def register(cls, name: str):
        """
        Décorateur pour enregistrer un ingestor.
        
        Usage:
            @IngestorRegistry.register("my_source")
            class MySourceIngestor(BaseIngestor):
                ...
        
        Args:
            name: Nom unique de l'ingestor (doit matcher sources.yaml)
        """
        def decorator(ingestor_cls: Type[BaseIngestor]):
            if name in cls._ingestors:
                logger.warning(f"Ingestor '{name}' already registered, overwriting")
            cls._ingestors[name] = ingestor_cls
            logger.debug(f"Registered ingestor: {name} -> {ingestor_cls.__name__}")
            return ingestor_cls
        return decorator
    
    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseIngestor]]:
        """
        Récupère la classe d'un ingestor par son nom.
        
        Args:
            name: Nom de l'ingestor
            
        Returns:
            Classe de l'ingestor ou None si non trouvé
        """
        return cls._ingestors.get(name)
    
    @classmethod
    def get_instance(cls, name: str) -> Optional[BaseIngestor]:
        """
        Récupère l'instance d'un ingestor (lazy loaded).
        
        Args:
            name: Nom de l'ingestor
            
        Returns:
            Instance de l'ingestor ou None
        """
        return cls._instances.get(name)
    
    @classmethod
    def list_available(cls) -> List[str]:
        """
        Liste tous les ingestors enregistrés.
        
        Returns:
            Liste des noms d'ingestors disponibles
        """
        return list(cls._ingestors.keys())
    
    @classmethod
    def list_enabled(cls) -> List[str]:
        """
        Liste les ingestors activés (instances créées et enabled).
        
        Returns:
            Liste des noms d'ingestors activés
        """
        return [name for name, inst in cls._instances.items() if inst.is_enabled]
    
    @classmethod
    def load_from_config(cls, config_path: Path) -> List[BaseIngestor]:
        """
        Charge et instancie les ingestors depuis sources.yaml.
        
        Args:
            config_path: Chemin vers sources.yaml
            
        Returns:
            Liste des ingestors instanciés et activés
        """
        if not config_path.exists():
            logger.warning(f"Config file not found: {config_path}")
            return []
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        sources = config.get("sources", {})
        ingestors = []
        
        for name, params in sources.items():
            # Skip si désactivé
            if not params.get("enabled", True):
                logger.debug(f"Skipping disabled ingestor: {name}")
                continue
            
            # Récupérer la classe
            ingestor_cls = cls.get(name)
            if ingestor_cls is None:
                logger.debug(f"No ingestor registered for: {name} (will be available in future phases)")
                continue
            
            # Créer la config
            ingestor_config = IngestorConfig.from_dict(name, params)
            
            # Instancier
            try:
                instance = ingestor_cls(ingestor_config)
                cls._instances[name] = instance
                ingestors.append(instance)
                logger.info(f"Loaded ingestor: {name} (weight={ingestor_config.weight})")
            except Exception as e:
                logger.error(f"Failed to load ingestor {name}: {e}")
        
        return ingestors
    
    @classmethod
    def clear(cls):
        """
        Efface tous les ingestors enregistrés.
        Utile pour les tests.
        """
        cls._ingestors.clear()
        cls._instances.clear()
    
    @classmethod
    def unregister(cls, name: str):
        """
        Supprime un ingestor du registry.
        
        Args:
            name: Nom de l'ingestor à supprimer
        """
        cls._ingestors.pop(name, None)
        cls._instances.pop(name, None)


def discover_ingestors():
    """
    Découvre et importe automatiquement tous les ingestors.
    
    Appelé au démarrage pour charger tous les ingestors disponibles.
    """
    import importlib
    import pkgutil
    from pathlib import Path
    
    # Chemin du package ingestors
    ingestors_path = Path(__file__).parent
    
    # Importer tous les modules Python dans le dossier
    for _, module_name, _ in pkgutil.iter_modules([str(ingestors_path)]):
        if module_name not in ("base", "registry", "__init__"):
            try:
                importlib.import_module(f".{module_name}", package=__name__.rsplit(".", 1)[0])
                logger.debug(f"Discovered ingestor module: {module_name}")
            except ImportError as e:
                logger.warning(f"Failed to import ingestor {module_name}: {e}")

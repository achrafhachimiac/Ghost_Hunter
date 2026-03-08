"""
Ghost-Hunter RAG Embedder
=========================
Wrapper pour sentence-transformers avec lazy loading.

Usage:
    embedder = Embedder.get_instance()
    vectors = embedder.embed(["text1", "text2"])
"""

import logging
from typing import List, Optional
from functools import lru_cache
import hashlib

logger = logging.getLogger(__name__)

# Import conditionnel de sentence-transformers
try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    SentenceTransformer = None  # type: ignore
    logger.warning("sentence-transformers not installed. Run: pip install sentence-transformers")


class Embedder:
    """
    Singleton embedder avec lazy loading.
    
    Le modèle n'est chargé qu'au premier appel de embed().
    Utilise un cache LRU pour les embeddings fréquents.
    """
    
    _instance: Optional["Embedder"] = None
    
    # Modèle par défaut - rapide et efficace pour les similarités
    DEFAULT_MODEL = "all-MiniLM-L6-v2"
    
    # Dimension des embeddings pour all-MiniLM-L6-v2
    EMBEDDING_DIM = 384
    
    def __init__(self, model_name: str = DEFAULT_MODEL):
        """
        Args:
            model_name: Nom du modèle sentence-transformers
        """
        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            raise ImportError(
                "sentence-transformers not installed. "
                "Run: pip install sentence-transformers"
            )
        
        self.model_name = model_name
        self._model: Optional[SentenceTransformer] = None
        self._is_loaded = False
        self._embed_count = 0
        self._cache_hits = 0
    
    @classmethod
    def get_instance(cls, model_name: str = DEFAULT_MODEL) -> "Embedder":
        """
        Retourne l'instance singleton.
        
        Args:
            model_name: Nom du modèle (ignoré si instance existe)
            
        Returns:
            Instance unique de Embedder
        """
        if cls._instance is None:
            cls._instance = cls(model_name)
        return cls._instance
    
    @classmethod
    def reset_instance(cls):
        """Reset le singleton (utile pour les tests)."""
        cls._instance = None
    
    @property
    def model(self) -> SentenceTransformer:
        """Lazy load le modèle au premier accès."""
        if self._model is None:
            logger.info(f"Loading embedding model: {self.model_name}")
            self._model = SentenceTransformer(self.model_name)
            self._is_loaded = True
            logger.info(f"Model loaded: {self.model_name}")
        return self._model
    
    @property
    def is_loaded(self) -> bool:
        """Retourne True si le modèle est chargé."""
        return self._is_loaded
    
    def embed(self, texts: List[str], show_progress: bool = False) -> List[List[float]]:
        """
        Génère les embeddings pour une liste de textes.
        
        Args:
            texts: Liste de textes à encoder
            show_progress: Afficher une barre de progression
            
        Returns:
            Liste de vecteurs (liste de floats)
        """
        if not texts:
            return []
        
        self._embed_count += len(texts)
        
        # Utiliser le modèle (lazy load)
        embeddings = self.model.encode(
            texts,
            show_progress_bar=show_progress,
            convert_to_numpy=True
        )
        
        # Convertir en liste de listes pour compatibilité
        return embeddings.tolist()
    
    def embed_single(self, text: str) -> List[float]:
        """
        Génère l'embedding pour un seul texte avec cache.
        
        Utilise un cache LRU pour les textes fréquemment embedés.
        
        Args:
            text: Texte à encoder
            
        Returns:
            Vecteur d'embedding
        """
        return self._embed_cached(text)
    
    @lru_cache(maxsize=500)
    def _embed_cached(self, text: str) -> tuple:
        """
        Version cachée de embed_single.
        
        Note: Retourne un tuple pour la compatibilité avec lru_cache.
        """
        # Track cache miss (si on arrive ici, c'est un miss)
        result = self.embed([text])[0]
        return tuple(result)
    
    def embed_query(self, query: str) -> List[float]:
        """
        Embed une query de recherche.
        
        Utilise le cache car les queries sont souvent répétées.
        
        Args:
            query: Query de recherche
            
        Returns:
            Vecteur d'embedding
        """
        cached = self._embed_cached(query)
        return list(cached)
    
    def get_stats(self) -> dict:
        """Retourne les statistiques d'utilisation."""
        cache_info = self._embed_cached.cache_info()
        return {
            "model": self.model_name,
            "is_loaded": self._is_loaded,
            "embedding_dim": self.EMBEDDING_DIM,
            "total_embeds": self._embed_count,
            "cache_size": cache_info.currsize,
            "cache_hits": cache_info.hits,
            "cache_misses": cache_info.misses,
            "cache_hit_rate": (
                cache_info.hits / (cache_info.hits + cache_info.misses)
                if (cache_info.hits + cache_info.misses) > 0
                else 0.0
            )
        }
    
    def clear_cache(self):
        """Vide le cache d'embeddings."""
        self._embed_cached.cache_clear()
    
    def preload(self):
        """Force le chargement du modèle (utile pour warm-up)."""
        _ = self.model  # Trigger lazy load


def get_embedder() -> Embedder:
    """
    Factory function pour obtenir l'embedder singleton.
    
    Returns:
        Instance de Embedder
    """
    return Embedder.get_instance()

"""
Ghost-Hunter RAG Vector Store
=============================
VectorStoreManager avec ChromaDB et lazy loading.

Usage:
    store = VectorStoreManager()
    # Store n'est pas encore chargé
    
    # Premier accès déclenche le lazy load
    store.upsert(chunks)
    
    # Query synchrone pour le pipeline
    results = store.query_sync("IDOR API", top_k=5)
"""

import logging
import time
from pathlib import Path
from typing import List, Optional, Dict, Any

from ghost_hunter.core.rag.contracts import Chunk, RAGQuery, RAGResult, RAGContext

logger = logging.getLogger(__name__)

# Import conditionnel de ChromaDB
try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    chromadb = None  # type: ignore
    logger.warning("chromadb not installed. Run: pip install chromadb")


# Chemin par défaut pour la persistence
# Path: ghost_hunter/core/rag/vector_store.py -> knowledge/embeddings
DEFAULT_PERSIST_PATH = Path(__file__).parent.parent.parent.parent / "knowledge" / "embeddings"
COLLECTION_NAME = "ghost_hunter_kb"


class VectorStoreManager:
    """
    Gestionnaire du vector store ChromaDB.
    
    Caractéristiques:
    - Lazy loading: ne charge pas au démarrage
    - Persistence: sauvegarde sur disque
    - Filtering: support des filtres ChromaDB
    - Sync API: pour compatibilité avec le pipeline actuel
    """
    
    def __init__(
        self,
        persist_path: Optional[Path] = None,
        collection_name: str = COLLECTION_NAME,
        embedding_function: Optional[Any] = None
    ):
        """
        Args:
            persist_path: Chemin pour la persistence (default: knowledge/embeddings)
            collection_name: Nom de la collection ChromaDB
            embedding_function: Fonction d'embedding (optionnel, utilise Embedder par défaut)
        """
        if not CHROMADB_AVAILABLE:
            raise ImportError("chromadb not installed. Run: pip install chromadb")
        
        self.persist_path = persist_path or DEFAULT_PERSIST_PATH
        self.collection_name = collection_name
        self._embedding_function = embedding_function
        
        # Lazy load state
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None
        self._is_loaded = False
        
        # Stats
        self._query_count = 0
        self._upsert_count = 0
        self._total_query_time_ms = 0.0
    
    def _ensure_path(self):
        """Crée le dossier de persistence si nécessaire."""
        self.persist_path.mkdir(parents=True, exist_ok=True)
    
    def _load(self):
        """Charge ChromaDB (appelé au premier accès)."""
        if self._is_loaded:
            return
        
        logger.info(f"Loading vector store from: {self.persist_path}")
        start = time.time()
        
        self._ensure_path()
        
        # Client persistant
        self._client = chromadb.PersistentClient(
            path=str(self.persist_path),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True,
            )
        )
        
        # Get or create collection
        self._collection = self._client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}  # Similarité cosine
        )
        
        self._is_loaded = True
        elapsed = (time.time() - start) * 1000
        logger.info(f"Vector store loaded in {elapsed:.0f}ms (count: {self._collection.count()})")
    
    @property
    def is_loaded(self) -> bool:
        """Retourne True si le store est chargé."""
        return self._is_loaded
    
    @property
    def collection(self):
        """Accès lazy à la collection."""
        if not self._is_loaded:
            self._load()
        return self._collection
    
    def upsert(self, chunks: List[Chunk], embeddings: Optional[List[List[float]]] = None):
        """
        Ajoute ou met à jour des chunks.
        
        Args:
            chunks: Liste de chunks à insérer
            embeddings: Embeddings pré-calculés (optionnel)
        """
        if not chunks:
            return
        
        # Lazy load si pas déjà fait
        if not self._is_loaded:
            self._load()
        
        # Préparer les données pour ChromaDB
        ids = [c.id for c in chunks]
        documents = [c.text for c in chunks]
        metadatas = [c.metadata for c in chunks]
        
        # Générer les embeddings si non fournis
        if embeddings is None:
            from ghost_hunter.core.rag.embedder import get_embedder
            embedder = get_embedder()
            embeddings = embedder.embed(documents)
        
        # Upsert dans ChromaDB
        self.collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
            embeddings=embeddings
        )
        
        self._upsert_count += len(chunks)
        logger.debug(f"Upserted {len(chunks)} chunks")
    
    def add_chunks(self, chunks: List[Chunk]):
        """
        Alias for upsert() - compatibility with kb_commands.
        
        Args:
            chunks: Liste de chunks à ajouter
        """
        self.upsert(chunks)
    
    def query_sync(
        self,
        text: str,
        top_k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
        min_score: float = 0.5
    ) -> RAGContext:
        """
        Query synchrone pour le pipeline.
        
        Args:
            text: Texte de la query
            top_k: Nombre de résultats max
            filters: Filtres ChromaDB (where clause)
            min_score: Score minimum (0-1)
            
        Returns:
            RAGContext avec les résultats
        """
        start = time.time()
        
        # Lazy load
        if not self._is_loaded:
            self._load()
        
        # Générer l'embedding de la query
        from ghost_hunter.core.rag.embedder import get_embedder
        embedder = get_embedder()
        query_embedding = embedder.embed_query(text)
        
        # Query ChromaDB
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=filters,
            include=["documents", "metadatas", "distances"]
        )
        
        elapsed = (time.time() - start) * 1000
        self._query_count += 1
        self._total_query_time_ms += elapsed
        
        # Convertir en RAGResults
        rag_results = []
        
        if results and results['ids'] and results['ids'][0]:
            for i, chunk_id in enumerate(results['ids'][0]):
                # ChromaDB retourne des distances, pas des scores
                # Pour cosine, distance = 1 - similarity
                distance = results['distances'][0][i] if results['distances'] else 0
                score = 1 - distance  # Convertir en similarité
                
                if score < min_score:
                    continue
                
                chunk = Chunk(
                    id=chunk_id,
                    text=results['documents'][0][i],
                    metadata=results['metadatas'][0][i]
                )
                
                rag_results.append(RAGResult(
                    chunk=chunk,
                    score=score,
                    weighted_score=score  # Pondération appliquée plus tard
                ))
        
        # Créer le contexte
        query = RAGQuery(text=text, top_k=top_k, min_score=min_score)
        context = RAGContext(
            query=query,
            results=rag_results,
            retrieval_time_ms=elapsed
        )
        
        logger.debug(f"Query '{text[:50]}...' returned {len(rag_results)} results in {elapsed:.0f}ms")
        return context
    
    def query_with_filters(self, query: RAGQuery) -> RAGContext:
        """
        Query avec un objet RAGQuery.
        
        Args:
            query: RAGQuery avec tous les paramètres
            
        Returns:
            RAGContext avec les résultats
        """
        filters = query.to_filters()
        return self.query_sync(
            text=query.text,
            top_k=query.top_k,
            filters=filters,
            min_score=query.min_score
        )
    
    def delete(self, ids: List[str]):
        """
        Supprime des chunks par ID.
        
        Args:
            ids: Liste des IDs à supprimer
        """
        if not ids:
            return
        
        if not self._is_loaded:
            self._load()
        
        self.collection.delete(ids=ids)
        logger.debug(f"Deleted {len(ids)} chunks")
    
    def delete_by_source(self, source: str):
        """
        Supprime tous les chunks d'une source.
        
        Args:
            source: Nom de la source
        """
        if not self._is_loaded:
            self._load()
        
        # ChromaDB ne supporte pas delete avec where, donc on doit get puis delete
        results = self.collection.get(
            where={"source": {"$eq": source}},
            include=[]
        )
        
        if results and results['ids']:
            self.delete(results['ids'])
            logger.info(f"Deleted {len(results['ids'])} chunks from source: {source}")
    
    def count(self) -> int:
        """Retourne le nombre total de chunks."""
        if not self._is_loaded:
            self._load()
        return self.collection.count()
    
    def stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du store."""
        # count() will lazy load if needed
        count = self.count()
        avg_query_time = (
            self._total_query_time_ms / self._query_count 
            if self._query_count > 0 else 0
        )
        
        return {
            "is_loaded": self._is_loaded,
            "persist_path": str(self.persist_path),
            "collection_name": self.collection_name,
            "total_chunks": count,
            "total_queries": self._query_count,
            "total_upserts": self._upsert_count,
            "avg_query_time_ms": round(avg_query_time, 2),
        }
    
    def reset(self):
        """
        Reset complet du store (supprime toutes les données).
        
        ⚠️ ATTENTION: Destructif!
        """
        if self._client:
            self._client.delete_collection(self.collection_name)
            self._collection = self._client.create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"}
            )
            logger.warning(f"Vector store reset: {self.collection_name}")
    
    def close(self):
        """Ferme la connexion (pour cleanup)."""
        # ChromaDB PersistentClient n'a pas de close explicite
        self._is_loaded = False
        self._client = None
        self._collection = None


# Singleton global (lazy loaded)
_store_instance: Optional[VectorStoreManager] = None


def get_vector_store() -> VectorStoreManager:
    """
    Retourne l'instance singleton du vector store.
    
    Returns:
        VectorStoreManager instance
    """
    global _store_instance
    if _store_instance is None:
        _store_instance = VectorStoreManager()
    return _store_instance


def reset_vector_store():
    """Reset le singleton (utile pour les tests)."""
    global _store_instance
    if _store_instance:
        _store_instance.close()
    _store_instance = None

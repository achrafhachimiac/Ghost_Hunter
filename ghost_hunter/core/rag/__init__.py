"""
Ghost-Hunter RAG Module
=======================
Retrieval-Augmented Generation pour enrichir le triage IA.

Components:
- vector_store: ChromaDB manager avec lazy loading
- embedder: Sentence-Transformers embeddings
- chunker: Découpage intelligent de texte
- contracts: Types partagés (Chunk, RAGContext, etc.)
- ingestors/: Plugins pour différentes sources (CVE, HackTricks, etc.)
"""

from typing import TYPE_CHECKING

# Lazy imports pour éviter le chargement au startup
if TYPE_CHECKING:
    from .vector_store import VectorStoreManager, get_vector_store
    from .embedder import Embedder, get_embedder
    from .chunker import chunk_markdown, chunk_yaml, chunk_text, chunk_file
    from .contracts import (
        Chunk, RAGContext, RAGQuery, RAGResult,
        VulnType, SourceType, IngestStats
    )

__all__ = [
    # Vector Store
    "VectorStoreManager",
    "get_vector_store",
    # Embedder
    "Embedder",
    "get_embedder",
    # Chunker
    "chunk_markdown",
    "chunk_yaml", 
    "chunk_text",
    "chunk_file",
    # Contracts
    "Chunk",
    "RAGContext",
    "RAGQuery",
    "RAGResult",
    "VulnType",
    "SourceType",
    "IngestStats",
    # Engine
    "get_rag_engine",
]

# Singleton pour le RAG Engine
_rag_engine = None


def get_rag_engine():
    """
    Retourne l'instance singleton du RAG Engine.
    Lazy loaded pour ne pas impacter le startup.
    """
    global _rag_engine
    if _rag_engine is None:
        from .engine import RAGEngine
        _rag_engine = RAGEngine()
    return _rag_engine

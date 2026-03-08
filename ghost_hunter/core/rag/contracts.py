"""
Ghost-Hunter RAG Contracts
==========================
Types partagés pour le système RAG.

Ces types sont utilisés par:
- VectorStoreManager
- Embedder
- Ingestors
- RAGEngine
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class VulnType(Enum):
    """Types de vulnérabilités normalisés."""
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    SSRF = "ssrf"
    IDOR = "idor"
    RCE = "rce"
    LFI = "lfi"
    XXE = "xxe"
    CSRF = "csrf"
    AUTH_BYPASS = "auth_bypass"
    OPEN_REDIRECT = "open_redirect"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"
    RACE_CONDITION = "race_condition"
    INFO_DISCLOSURE = "info_disclosure"
    BUSINESS_LOGIC = "business_logic"
    UNKNOWN = "unknown"


class SourceType(Enum):
    """Types de sources de données."""
    NVD = "nvd"
    HACKTRICKS = "hacktricks"
    NUCLEI = "nuclei"
    PERSONAL_REPORT = "personal_report"
    PAYLOAD = "payload"
    PATTERN = "pattern"
    CUSTOM = "custom"


@dataclass
class Chunk:
    """
    Un chunk de texte indexé dans le vector store.
    
    Attributes:
        id: Identifiant unique (format: {source}_{vuln_type}_{hash8})
        text: Contenu textuel du chunk
        metadata: Métadonnées obligatoires + optionnelles
        embedding: Vecteur d'embedding (optionnel, set par Embedder)
    """
    id: str
    text: str
    metadata: Dict[str, Any]
    embedding: Optional[List[float]] = None
    
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
        """Factory method pour créer un chunk avec metadata requises."""
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
    
    @property
    def source(self) -> str:
        """Raccourci pour metadata['source']."""
        return self.metadata.get("source", "unknown")
    
    @property
    def vuln_type(self) -> str:
        """Raccourci pour metadata['vuln_type']."""
        return self.metadata.get("vuln_type", "unknown")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dict pour sérialisation."""
        return {
            "id": self.id,
            "text": self.text,
            "metadata": self.metadata,
        }


@dataclass
class RAGQuery:
    """
    Query pour le RAG avec filtres.
    
    Attributes:
        text: Texte de la requête
        vuln_types: Filtrer par types de vulnérabilités
        sources: Filtrer par sources
        top_k: Nombre de résultats max
        min_score: Score minimum (0-1)
        tech_stack: Tech stack pour boosting
        include_payloads: Inclure les payloads dans les résultats
    """
    text: str
    vuln_types: Optional[List[str]] = None
    sources: Optional[List[str]] = None
    top_k: int = 5
    min_score: float = 0.5
    tech_stack: Optional[List[str]] = None
    include_payloads: bool = False
    
    def to_filters(self) -> Optional[Dict[str, Any]]:
        """
        Convertit les filtres en format ChromaDB.
        
        Returns:
            Dict compatible avec ChromaDB where clause, ou None
        """
        conditions = []
        
        if self.vuln_types:
            if len(self.vuln_types) == 1:
                conditions.append({"vuln_type": {"$eq": self.vuln_types[0]}})
            else:
                conditions.append({"vuln_type": {"$in": self.vuln_types}})
        
        if self.sources:
            if len(self.sources) == 1:
                conditions.append({"source": {"$eq": self.sources[0]}})
            else:
                conditions.append({"source": {"$in": self.sources}})
        
        if not self.include_payloads:
            conditions.append({"type": {"$ne": "payload"}})
        
        if not conditions:
            return None
        
        if len(conditions) == 1:
            return conditions[0]
        
        return {"$and": conditions}


@dataclass
class RAGResult:
    """
    Un résultat de recherche RAG.
    
    Attributes:
        chunk: Le chunk trouvé
        score: Score de similarité (0-1)
        weighted_score: Score après pondération source/recency
    """
    chunk: Chunk
    score: float
    weighted_score: float = 0.0
    
    def __post_init__(self):
        """Initialise weighted_score si non fourni."""
        if self.weighted_score == 0.0:
            self.weighted_score = self.score


@dataclass
class RAGContext:
    """
    Contexte retourné par le RAG pour enrichir un prompt.
    
    Attributes:
        query: La query originale
        results: Liste des résultats
        total_tokens: Estimation du nombre de tokens
        retrieval_time_ms: Temps de récupération
        formatted_context: Contexte formaté pour le prompt
    """
    query: RAGQuery
    results: List[RAGResult]
    total_tokens: int = 0
    retrieval_time_ms: float = 0.0
    formatted_context: str = ""
    
    def __post_init__(self):
        """Calcule le contexte formaté si non fourni."""
        if not self.formatted_context and self.results:
            self.formatted_context = self._format_context()
        if self.total_tokens == 0:
            self.total_tokens = self._estimate_tokens()
    
    def _format_context(self) -> str:
        """Formate les résultats en contexte pour le prompt."""
        if not self.results:
            return ""
        
        lines = ["### Relevant Knowledge:"]
        for i, result in enumerate(self.results, 1):
            source = result.chunk.source
            vuln = result.chunk.vuln_type
            score = result.weighted_score
            lines.append(f"\n**[{i}] {source} ({vuln}) - Score: {score:.2f}**")
            lines.append(result.chunk.text[:500])  # Truncate long chunks
            if len(result.chunk.text) > 500:
                lines.append("...")
        
        return "\n".join(lines)
    
    def _estimate_tokens(self) -> int:
        """Estime le nombre de tokens (approximation: 4 chars = 1 token)."""
        total_chars = sum(len(r.chunk.text) for r in self.results)
        return total_chars // 4
    
    @property
    def is_empty(self) -> bool:
        """Retourne True si aucun résultat."""
        return len(self.results) == 0
    
    @property
    def top_result(self) -> Optional[RAGResult]:
        """Retourne le meilleur résultat."""
        if not self.results:
            return None
        return max(self.results, key=lambda r: r.weighted_score)
    
    def get_sources(self) -> List[str]:
        """Retourne la liste des sources uniques."""
        return list(set(r.chunk.source for r in self.results))
    
    def get_vuln_types(self) -> List[str]:
        """Retourne la liste des vuln_types uniques."""
        return list(set(r.chunk.vuln_type for r in self.results))
    
    def filter_by_score(self, min_score: float) -> "RAGContext":
        """Retourne un nouveau RAGContext avec seulement les résultats >= min_score."""
        filtered = [r for r in self.results if r.weighted_score >= min_score]
        return RAGContext(
            query=self.query,
            results=filtered,
            retrieval_time_ms=self.retrieval_time_ms
        )
    
    def limit(self, n: int) -> "RAGContext":
        """Retourne un nouveau RAGContext limité à n résultats."""
        return RAGContext(
            query=self.query,
            results=self.results[:n],
            retrieval_time_ms=self.retrieval_time_ms
        )


@dataclass
class IngestStats:
    """
    Statistiques d'ingestion.
    
    Attributes:
        source: Nom de la source
        chunks_added: Nombre de chunks ajoutés
        chunks_updated: Nombre de chunks mis à jour
        chunks_deleted: Nombre de chunks supprimés
        errors: Nombre d'erreurs
        duration_ms: Durée de l'ingestion
        timestamp: Timestamp de l'ingestion
    """
    source: str
    chunks_added: int = 0
    chunks_updated: int = 0
    chunks_deleted: int = 0
    errors: int = 0
    duration_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    @property
    def total_processed(self) -> int:
        """Nombre total de chunks traités."""
        return self.chunks_added + self.chunks_updated + self.chunks_deleted
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dict pour logging/storage."""
        return {
            "source": self.source,
            "chunks_added": self.chunks_added,
            "chunks_updated": self.chunks_updated,
            "chunks_deleted": self.chunks_deleted,
            "errors": self.errors,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
            "total_processed": self.total_processed,
        }

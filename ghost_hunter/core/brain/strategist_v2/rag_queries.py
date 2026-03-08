"""
RAG Queries pour le Strategist V2.

Queries spécialisées pour récupérer le contexte WAF bypass,
evasion techniques et patterns du knowledge base.
~150 lignes max selon les règles du projet.
"""

import logging
from typing import List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RAGChunk:
    """Chunk de contexte RAG simplifié."""
    
    content: str
    source: str
    relevance: float = 0.0
    
    def __str__(self) -> str:
        return f"[{self.source}] {self.content[:100]}..."


@dataclass 
class RAGQueryResult:
    """Résultat d'une query RAG."""
    
    chunks: List[RAGChunk]
    query: str
    total_tokens: int = 0
    
    def to_formatted_string(self) -> str:
        """Formate les chunks en string pour le prompt."""
        if not self.chunks:
            return "_No relevant context found_"
        
        lines = []
        for i, chunk in enumerate(self.chunks, 1):
            lines.append(f"### Source {i}: {chunk.source}\n")
            lines.append(chunk.content)
            lines.append("")
        
        return "\n".join(lines)


def get_waf_bypass_context(
    waf_provider: Optional[str],
    blocked_patterns: List[str],
    max_chunks: int = 5,
) -> RAGQueryResult:
    """
    Récupère le contexte pour bypass WAF spécifique.
    
    Args:
        waf_provider: Provider WAF détecté (cloudflare, aws_waf, etc.)
        blocked_patterns: Patterns qui ont été bloqués
        max_chunks: Nombre max de chunks
        
    Returns:
        RAGQueryResult avec techniques de bypass
    """
    # Construire la query
    query_parts = []
    
    if waf_provider:
        query_parts.append(f"{waf_provider} WAF bypass techniques")
    else:
        query_parts.append("WAF bypass techniques")
    
    if blocked_patterns:
        # Extraire les mots-clés des patterns bloqués
        keywords = _extract_keywords_from_patterns(blocked_patterns[:3])
        if keywords:
            query_parts.append(f"bypass {' '.join(keywords)}")
    
    query = " ".join(query_parts)
    
    return _execute_rag_query(query, max_chunks, "waf_bypass")


def get_encoding_evasion_context(
    failed_encodings: List[str],
    vuln_class: str,
    max_chunks: int = 3,
) -> RAGQueryResult:
    """
    Récupère le contexte pour techniques d'evasion par encoding.
    
    Args:
        failed_encodings: Encodings qui ont échoué
        vuln_class: Classe de vulnérabilité (IDOR, SQLi, etc.)
        max_chunks: Nombre max de chunks
        
    Returns:
        RAGQueryResult avec techniques d'encoding
    """
    query_parts = [f"{vuln_class} encoding techniques"]
    
    # Suggérer des alternatives aux encodings qui ont échoué
    encoding_alternatives = {
        "url": "double URL encoding unicode encoding",
        "unicode": "hex encoding HTML entities",
        "none": "URL encoding base64 encoding",
        "double_url": "unicode normalization case variation",
    }
    
    for enc in failed_encodings[:2]:
        if enc in encoding_alternatives:
            query_parts.append(encoding_alternatives[enc])
    
    query = " ".join(query_parts)
    
    return _execute_rag_query(query, max_chunks, "encoding_evasion")


def get_vuln_technique_context(
    vuln_class: str,
    working_techniques: List[str],
    max_chunks: int = 5,
) -> RAGQueryResult:
    """
    Récupère le contexte pour techniques avancées de la vulnérabilité.
    
    Args:
        vuln_class: Classe de vulnérabilité
        working_techniques: Techniques qui ont fonctionné
        max_chunks: Nombre max de chunks
        
    Returns:
        RAGQueryResult avec techniques avancées
    """
    query_parts = [f"advanced {vuln_class} techniques"]
    
    # Enrichir avec les techniques qui marchent
    if working_techniques:
        query_parts.append(f"similar to {' '.join(working_techniques[:2])}")
    
    # Ajouter des mots-clés spécifiques par vuln class
    vuln_keywords = {
        "IDOR": "horizontal privilege escalation indirect object reference",
        "SQLi": "blind SQL injection time-based union-based",
        "XSS": "DOM-based XSS CSP bypass event handlers",
        "SSRF": "SSRF bypass URL schemes DNS rebinding",
        "LFI": "local file inclusion path traversal null byte",
        "RCE": "remote code execution command injection",
    }
    
    if vuln_class.upper() in vuln_keywords:
        query_parts.append(vuln_keywords[vuln_class.upper()])
    
    query = " ".join(query_parts)
    
    return _execute_rag_query(query, max_chunks, "vuln_techniques")


def get_combined_context(
    waf_provider: Optional[str],
    vuln_class: str,
    blocked_patterns: List[str],
    failed_encodings: List[str],
    working_techniques: List[str],
    max_total_chunks: int = 10,
) -> str:
    """
    Récupère et combine le contexte de toutes les sources.
    
    Args:
        waf_provider: Provider WAF détecté
        vuln_class: Classe de vulnérabilité
        blocked_patterns: Patterns bloqués
        failed_encodings: Encodings qui ont échoué
        working_techniques: Techniques qui marchent
        max_total_chunks: Nombre total max de chunks
        
    Returns:
        String formaté avec tout le contexte RAG
    """
    sections = []
    
    # 1. WAF Bypass (prioritaire)
    waf_context = get_waf_bypass_context(
        waf_provider, blocked_patterns, max_chunks=4
    )
    if waf_context.chunks:
        sections.append("## WAF Bypass Techniques\n")
        sections.append(waf_context.to_formatted_string())
    
    # 2. Encoding Evasion
    encoding_context = get_encoding_evasion_context(
        failed_encodings, vuln_class, max_chunks=3
    )
    if encoding_context.chunks:
        sections.append("## Encoding Evasion\n")
        sections.append(encoding_context.to_formatted_string())
    
    # 3. Vulnerability Techniques
    vuln_context = get_vuln_technique_context(
        vuln_class, working_techniques, max_chunks=3
    )
    if vuln_context.chunks:
        sections.append(f"## {vuln_class} Advanced Techniques\n")
        sections.append(vuln_context.to_formatted_string())
    
    if not sections:
        return "_No relevant context found in knowledge base_"
    
    return "\n\n".join(sections)


def _execute_rag_query(
    query: str,
    max_chunks: int,
    query_type: str,
) -> RAGQueryResult:
    """
    Exécute une query RAG et retourne les résultats.
    
    Args:
        query: Query de recherche
        max_chunks: Nombre max de chunks
        query_type: Type de query (pour logging)
        
    Returns:
        RAGQueryResult
    """
    try:
        from ghost_hunter.core.rag.engine import RAGEngine
        
        engine = RAGEngine()
        
        if not engine.is_available():
            logger.warning(f"RAG not available for {query_type} query")
            return RAGQueryResult(chunks=[], query=query)
        
        # Utiliser query_sync() avec l'interface correcte
        rag_context = engine.store.query_sync(
            text=query,
            top_k=max_chunks,
            min_score=0.3  # Score minimum pour filtrer les résultats non pertinents
        )
        
        chunks = []
        for result in rag_context.results:
            # result.chunk.text contient le contenu
            # result.chunk.metadata contient les métadonnées dont 'source'
            chunk = RAGChunk(
                content=result.chunk.text,
                source=result.chunk.metadata.get("source", "unknown"),
                relevance=result.score,
            )
            chunks.append(chunk)
        
        total_tokens = sum(len(c.content) // 4 for c in chunks)
        
        logger.debug(
            f"RAG {query_type}: {len(chunks)} chunks, "
            f"~{total_tokens} tokens for query: {query[:50]}..."
        )
        
        return RAGQueryResult(
            chunks=chunks,
            query=query,
            total_tokens=total_tokens,
        )
        
    except Exception as e:
        logger.error(f"RAG query failed ({query_type}): {e}")
        return RAGQueryResult(chunks=[], query=query)


def _extract_keywords_from_patterns(patterns: List[str]) -> List[str]:
    """Extrait des mots-clés des patterns bloqués."""
    keywords = []
    
    # Mots-clés communs à extraire
    common_keywords = [
        "SELECT", "UNION", "INSERT", "UPDATE", "DELETE",
        "script", "alert", "onerror", "onclick",
        "http://", "https://", "file://",
        "../"
    ]
    
    for pattern in patterns:
        for kw in common_keywords:
            if kw.lower() in pattern.lower():
                keywords.append(kw)
    
    return list(set(keywords))[:5]  # Max 5 keywords

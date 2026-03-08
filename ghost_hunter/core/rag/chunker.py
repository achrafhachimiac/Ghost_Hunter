"""
Ghost-Hunter RAG Chunker
========================
Découpage intelligent de texte en chunks.

Supporte:
- Markdown (avec extraction des sections)
- YAML (parsing et chunking)
- Texte brut

Usage:
    chunks = chunk_markdown(content, source="hacktricks", vuln_type="xss")
    chunks = chunk_yaml(content, source="nuclei", vuln_type="sqli")
"""

import re
import logging
import hashlib
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path

from ghost_hunter.core.rag.contracts import Chunk

logger = logging.getLogger(__name__)


# Configuration par défaut
DEFAULT_CHUNK_SIZE = 500  # tokens (~2000 chars)
DEFAULT_OVERLAP = 50  # tokens overlap
MAX_CHUNK_SIZE = 600  # Limite stricte
MIN_CHUNK_SIZE = 50  # Minimum pour éviter les chunks inutiles

# Approximation: 1 token ≈ 4 caractères
CHARS_PER_TOKEN = 4


def _estimate_tokens(text: str) -> int:
    """Estime le nombre de tokens dans un texte."""
    return len(text) // CHARS_PER_TOKEN


def _truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Tronque un texte à un nombre max de tokens."""
    max_chars = max_tokens * CHARS_PER_TOKEN
    if len(text) <= max_chars:
        return text
    # Tronquer et ajouter "..."
    return text[:max_chars - 3] + "..."


def _split_into_chunks(
    text: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_OVERLAP
) -> List[str]:
    """
    Découpe un texte en chunks avec overlap.
    
    Essaie de couper sur des limites naturelles (paragraphes, phrases).
    """
    if not text or not text.strip():
        return []
    
    max_chars = chunk_size * CHARS_PER_TOKEN
    overlap_chars = overlap * CHARS_PER_TOKEN
    
    # Si le texte tient dans un seul chunk
    if len(text) <= max_chars:
        return [text.strip()] if text.strip() else []
    
    chunks = []
    start = 0
    
    while start < len(text):
        end = start + max_chars
        
        # Si on est à la fin, prendre le reste
        if end >= len(text):
            chunk = text[start:].strip()
            if chunk and len(chunk) >= MIN_CHUNK_SIZE * CHARS_PER_TOKEN:
                chunks.append(chunk)
            break
        
        # Chercher une limite naturelle pour couper
        chunk_text = text[start:end]
        
        # Priorité: paragraphe > phrase > espace
        best_break = -1
        
        # Chercher le dernier double saut de ligne (paragraphe)
        para_break = chunk_text.rfind("\n\n")
        if para_break > len(chunk_text) // 2:  # Au moins à 50% du chunk
            best_break = para_break
        
        # Sinon, chercher la dernière phrase
        if best_break == -1:
            for pattern in [". ", "! ", "? ", ".\n"]:
                sent_break = chunk_text.rfind(pattern)
                if sent_break > len(chunk_text) // 2:
                    best_break = sent_break + len(pattern)
                    break
        
        # Sinon, chercher le dernier espace
        if best_break == -1:
            space_break = chunk_text.rfind(" ")
            if space_break > len(chunk_text) // 2:
                best_break = space_break
        
        # Si aucune limite trouvée, couper au max
        if best_break == -1:
            best_break = max_chars
        
        chunk = chunk_text[:best_break].strip()
        if chunk and len(chunk) >= MIN_CHUNK_SIZE * CHARS_PER_TOKEN:
            chunks.append(chunk)
        
        # Avancer avec overlap
        start = start + best_break - overlap_chars
        if start < 0:
            start = 0
    
    return chunks


def _extract_markdown_sections(content: str) -> List[Tuple[str, str, int]]:
    """
    Extrait les sections d'un document Markdown.
    
    Returns:
        Liste de tuples (titre, contenu, niveau)
    """
    sections = []
    current_title = ""
    current_level = 0
    current_content = []
    
    lines = content.split("\n")
    
    for line in lines:
        # Détecter les headers
        header_match = re.match(r'^(#{1,6})\s+(.+)$', line)
        
        if header_match:
            # Sauvegarder la section précédente
            if current_content:
                text = "\n".join(current_content).strip()
                if text:
                    sections.append((current_title, text, current_level))
            
            # Nouvelle section
            current_level = len(header_match.group(1))
            current_title = header_match.group(2).strip()
            current_content = []
        else:
            current_content.append(line)
    
    # Dernière section
    if current_content:
        text = "\n".join(current_content).strip()
        if text:
            sections.append((current_title, text, current_level))
    
    return sections


def _extract_code_blocks(content: str) -> List[Tuple[str, str]]:
    """
    Extrait les blocs de code d'un document Markdown.
    
    Returns:
        Liste de tuples (langage, code)
    """
    pattern = r'```(\w*)\n(.*?)```'
    matches = re.findall(pattern, content, re.DOTALL)
    return [(lang or "text", code.strip()) for lang, code in matches]


def chunk_markdown(
    content: str,
    source: str,
    vuln_type: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_OVERLAP,
    file_path: Optional[str] = None,
    **extra_metadata
) -> List[Chunk]:
    """
    Découpe un document Markdown en chunks intelligents.
    
    Stratégie:
    1. Extraire les sections (headers)
    2. Extraire les blocs de code séparément
    3. Chunker chaque section
    4. Combiner avec contexte
    
    Args:
        content: Contenu Markdown
        source: Source (hacktricks, personal_report, etc.)
        vuln_type: Type de vulnérabilité
        chunk_size: Taille cible en tokens
        overlap: Overlap en tokens
        file_path: Chemin du fichier (optionnel)
        **extra_metadata: Metadata additionnelles
        
    Returns:
        Liste de Chunks
    """
    if not content or not content.strip():
        return []
    
    chunks = []
    
    # Extraire les sections
    sections = _extract_markdown_sections(content)
    
    # Extraire les code blocks pour référence
    code_blocks = _extract_code_blocks(content)
    
    for title, text, level in sections:
        # Skip les sections trop courtes
        if _estimate_tokens(text) < MIN_CHUNK_SIZE:
            continue
        
        # Préparer le contexte
        context_prefix = f"## {title}\n\n" if title else ""
        
        # Chunker le contenu
        text_chunks = _split_into_chunks(text, chunk_size, overlap)
        
        for i, chunk_text in enumerate(text_chunks):
            # Ajouter le titre au premier chunk de chaque section
            if i == 0 and context_prefix:
                chunk_text = context_prefix + chunk_text
            
            # Créer le chunk
            chunk = Chunk.create(
                text=_truncate_to_tokens(chunk_text, MAX_CHUNK_SIZE),
                source=source,
                chunk_type="technique",
                vuln_type=vuln_type,
                section_title=title,
                section_level=level,
                chunk_index=i,
                file_path=file_path,
                **extra_metadata
            )
            chunks.append(chunk)
    
    # Ajouter les code blocks significatifs comme chunks séparés
    for lang, code in code_blocks:
        if _estimate_tokens(code) >= MIN_CHUNK_SIZE:
            chunk = Chunk.create(
                text=f"```{lang}\n{_truncate_to_tokens(code, MAX_CHUNK_SIZE)}\n```",
                source=source,
                chunk_type="code",
                vuln_type=vuln_type,
                code_language=lang,
                file_path=file_path,
                **extra_metadata
            )
            chunks.append(chunk)
    
    logger.debug(f"Chunked markdown: {len(chunks)} chunks from {source}/{vuln_type}")
    return chunks


def chunk_yaml(
    content: str,
    source: str,
    vuln_type: str,
    file_path: Optional[str] = None,
    **extra_metadata
) -> List[Chunk]:
    """
    Découpe un document YAML en chunks.
    
    Pour les fichiers comme nuclei templates, chaque template = 1 chunk.
    
    Args:
        content: Contenu YAML
        source: Source (nuclei, patterns, etc.)
        vuln_type: Type de vulnérabilité
        file_path: Chemin du fichier
        **extra_metadata: Metadata additionnelles
        
    Returns:
        Liste de Chunks
    """
    if not content or not content.strip():
        return []
    
    try:
        import yaml
        
        # Parser le YAML
        docs = list(yaml.safe_load_all(content))
        
        chunks = []
        for i, doc in enumerate(docs):
            if doc is None:
                continue
            
            # Convertir en texte lisible
            doc_text = yaml.dump(doc, default_flow_style=False, allow_unicode=True)
            
            # Skip si trop court
            if _estimate_tokens(doc_text) < MIN_CHUNK_SIZE:
                continue
            
            # Extraire un ID si disponible
            doc_id = doc.get("id") or doc.get("name") or f"doc_{i}"
            
            chunk = Chunk.create(
                text=_truncate_to_tokens(doc_text, MAX_CHUNK_SIZE),
                source=source,
                chunk_type="template",
                vuln_type=vuln_type,
                template_id=doc_id,
                file_path=file_path,
                **extra_metadata
            )
            chunks.append(chunk)
        
        logger.debug(f"Chunked YAML: {len(chunks)} chunks from {source}/{vuln_type}")
        return chunks
        
    except Exception as e:
        logger.warning(f"Failed to parse YAML: {e}")
        # Fallback: traiter comme texte brut
        return chunk_text(content, source, vuln_type, file_path=file_path, **extra_metadata)


def chunk_text(
    content: str,
    source: str,
    vuln_type: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_OVERLAP,
    file_path: Optional[str] = None,
    **extra_metadata
) -> List[Chunk]:
    """
    Découpe un texte brut en chunks.
    
    Args:
        content: Contenu texte
        source: Source
        vuln_type: Type de vulnérabilité
        chunk_size: Taille cible en tokens
        overlap: Overlap en tokens
        file_path: Chemin du fichier
        **extra_metadata: Metadata additionnelles
        
    Returns:
        Liste de Chunks
    """
    if not content or not content.strip():
        return []
    
    text_chunks = _split_into_chunks(content, chunk_size, overlap)
    
    chunks = []
    for i, chunk_text in enumerate(text_chunks):
        chunk = Chunk.create(
            text=_truncate_to_tokens(chunk_text, MAX_CHUNK_SIZE),
            source=source,
            chunk_type="text",
            vuln_type=vuln_type,
            chunk_index=i,
            file_path=file_path,
            **extra_metadata
        )
        chunks.append(chunk)
    
    logger.debug(f"Chunked text: {len(chunks)} chunks from {source}/{vuln_type}")
    return chunks


def chunk_file(
    file_path: Path,
    source: str,
    vuln_type: str,
    **extra_metadata
) -> List[Chunk]:
    """
    Découpe un fichier en chunks selon son type.
    
    Détecte automatiquement le type (markdown, yaml, text).
    
    Args:
        file_path: Chemin du fichier
        source: Source
        vuln_type: Type de vulnérabilité
        **extra_metadata: Metadata additionnelles
        
    Returns:
        Liste de Chunks
    """
    if not file_path.exists():
        logger.warning(f"File not found: {file_path}")
        return []
    
    content = file_path.read_text(encoding="utf-8", errors="ignore")
    suffix = file_path.suffix.lower()
    
    if suffix in [".md", ".markdown"]:
        return chunk_markdown(
            content, source, vuln_type,
            file_path=str(file_path),
            **extra_metadata
        )
    elif suffix in [".yaml", ".yml"]:
        return chunk_yaml(
            content, source, vuln_type,
            file_path=str(file_path),
            **extra_metadata
        )
    else:
        return chunk_text(
            content, source, vuln_type,
            file_path=str(file_path),
            **extra_metadata
        )

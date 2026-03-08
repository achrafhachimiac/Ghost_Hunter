"""
Ghost-Hunter HackTricks Ingestor
================================
Ingestor pour HackTricks pentesting-web/ seulement.

Usage:
    from ghost_hunter.core.rag.ingestors.hacktricks import HackTricksIngestor
    
    ingestor = HackTricksIngestor(config)
    ingestor.sync()  # Clone/pull
    for chunk in ingestor.ingest():
        store.upsert([chunk])
"""

import subprocess
import logging
import time
from pathlib import Path
from typing import List, Generator, Dict, Any, Optional
from datetime import datetime

from ghost_hunter.core.rag.ingestors.base import BaseIngestor, IngestorConfig, SyncError
from ghost_hunter.core.rag.ingestors.registry import IngestorRegistry
from ghost_hunter.core.rag.contracts import Chunk, IngestStats
from ghost_hunter.core.rag.chunker import chunk_markdown

logger = logging.getLogger(__name__)


# Configuration
HACKTRICKS_URL = "https://github.com/carlospolop/hacktricks.git"
SPARSE_PATHS = ["pentesting-web"]  # Seulement la section web

# Default destination
DEFAULT_DEST = Path(__file__).parent.parent.parent.parent.parent / "knowledge" / "sources" / "hacktricks"


# Mapping path HackTricks → vuln_type normalisé
PATH_VULN_MAPPING = {
    # XSS
    "xss": "xss",
    "cross-site-scripting": "xss",
    "dom-xss": "xss",
    "reflected-xss": "xss",
    "stored-xss": "xss",
    
    # SQL Injection
    "sql-injection": "sqli",
    "sqli": "sqli",
    "sqlmap": "sqli",
    "mysql-injection": "sqli",
    "postgresql-injection": "sqli",
    "mssql-injection": "sqli",
    "oracle-injection": "sqli",
    "nosql-injection": "sqli",
    
    # SSRF
    "ssrf": "ssrf",
    "server-side-request-forgery": "ssrf",
    
    # XXE
    "xxe": "xxe",
    "xml-external-entity": "xxe",
    
    # SSTI
    "ssti": "ssti",
    "server-side-template-injection": "ssti",
    "template-injection": "ssti",
    "jinja2": "ssti",
    "twig": "ssti",
    "freemarker": "ssti",
    
    # IDOR / Access Control
    "idor": "idor",
    "insecure-direct-object-reference": "idor",
    "bola": "idor",
    "broken-access-control": "idor",
    
    # LFI/RFI
    "file-inclusion": "lfi",
    "lfi": "lfi",
    "rfi": "lfi",
    "local-file-inclusion": "lfi",
    "path-traversal": "lfi",
    "directory-traversal": "lfi",
    
    # RCE / Command Injection
    "command-injection": "rce",
    "rce": "rce",
    "remote-code-execution": "rce",
    "code-injection": "rce",
    "os-command-injection": "rce",
    
    # CSRF
    "csrf": "csrf",
    "cross-site-request-forgery": "csrf",
    
    # Auth Bypass
    "authentication": "auth_bypass",
    "auth-bypass": "auth_bypass",
    "oauth": "auth_bypass",
    "jwt": "auth_bypass",
    "session": "auth_bypass",
    "2fa-bypass": "auth_bypass",
    
    # Open Redirect
    "open-redirect": "open_redirect",
    "url-redirect": "open_redirect",
    
    # File Upload
    "file-upload": "file_upload",
    "upload": "file_upload",
    
    # Deserialization
    "deserialization": "deserialization",
    "insecure-deserialization": "deserialization",
    "pickle": "deserialization",
    "java-deserialization": "deserialization",
    
    # Race Condition
    "race-condition": "race_condition",
    "toctou": "race_condition",
    
    # Cache
    "cache-poisoning": "cache_poisoning",
    "web-cache": "cache_poisoning",
    
    # CORS
    "cors": "cors",
    "cross-origin": "cors",
    
    # Clickjacking
    "clickjacking": "clickjacking",
    
    # WebSocket
    "websocket": "websocket",
    
    # GraphQL
    "graphql": "graphql",
    
    # API
    "api": "api",
    "rest-api": "api",
}

# Fichiers à ignorer
IGNORE_PATTERNS = [
    "README.md",
    "SUMMARY.md",
    ".gitbook",
    "_sidebar.md",
    "assets/",
    "images/",
]


def extract_vuln_type(file_path: Path) -> str:
    """
    Extrait le type de vulnérabilité depuis le chemin du fichier.
    
    Args:
        file_path: Chemin du fichier markdown
        
    Returns:
        vuln_type normalisé ou "unknown"
    """
    # Convertir le path en parties lowercase
    parts = [p.lower() for p in file_path.parts]
    
    # Chercher une correspondance dans le mapping
    for part in parts:
        # Nettoyer le nom (enlever .md, remplacer _ par -)
        clean_part = part.replace(".md", "").replace("_", "-")
        
        if clean_part in PATH_VULN_MAPPING:
            return PATH_VULN_MAPPING[clean_part]
        
        # Chercher des correspondances partielles
        for pattern, vuln_type in PATH_VULN_MAPPING.items():
            if pattern in clean_part:
                return vuln_type
    
    return "unknown"


def should_ignore(file_path: Path) -> bool:
    """Vérifie si un fichier doit être ignoré."""
    path_str = str(file_path)
    for pattern in IGNORE_PATTERNS:
        if pattern in path_str:
            return True
    return False


@IngestorRegistry.register("hacktricks")
class HackTricksIngestor(BaseIngestor):
    """
    Ingestor pour HackTricks - pentesting-web/ seulement.
    
    Caractéristiques:
    - Sparse checkout pour économiser l'espace
    - Mapping automatique path → vuln_type
    - Chunking intelligent du markdown
    """
    
    source_type = "git"
    
    def __init__(self, config: IngestorConfig, dest_path: Optional[Path] = None):
        """
        Args:
            config: Configuration de l'ingestor
            dest_path: Chemin de destination (default: knowledge/sources/hacktricks)
        """
        super().__init__(config)
        self.dest_path = dest_path or DEFAULT_DEST
        self.git_url = config.params.get("git_url", HACKTRICKS_URL)
        self.sparse_paths = config.params.get("include_paths", SPARSE_PATHS)
        self._chunks_count = 0
        self._files_processed = 0
    
    def sync(self) -> None:
        """
        Clone ou met à jour le repo HackTricks.
        
        Utilise sparse-checkout pour ne cloner que pentesting-web/.
        """
        try:
            if self.dest_path.exists() and (self.dest_path / ".git").exists():
                # Pull updates
                logger.info(f"Pulling HackTricks updates in {self.dest_path}")
                result = subprocess.run(
                    ["git", "pull", "--depth", "1"],
                    cwd=self.dest_path,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if result.returncode != 0:
                    logger.warning(f"Git pull warning: {result.stderr}")
            else:
                # Clone sparse
                logger.info(f"Cloning HackTricks (sparse) to {self.dest_path}")
                self._clone_sparse()
            
            self._last_sync = datetime.now()
            logger.info("HackTricks sync complete")
            
        except subprocess.TimeoutExpired:
            raise SyncError("Git operation timed out")
        except Exception as e:
            raise SyncError(f"Failed to sync HackTricks: {e}")
    
    def _clone_sparse(self) -> None:
        """Clone avec sparse-checkout."""
        # Créer le dossier parent
        self.dest_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Clone initial (shallow + sparse)
        subprocess.run(
            [
                "git", "clone",
                "--depth", "1",
                "--filter=blob:none",
                "--sparse",
                self.git_url,
                str(self.dest_path)
            ],
            check=True,
            capture_output=True,
            timeout=300
        )
        
        # Configurer sparse-checkout
        subprocess.run(
            ["git", "sparse-checkout", "set"] + self.sparse_paths,
            cwd=self.dest_path,
            check=True,
            capture_output=True,
            timeout=60
        )
        
        logger.info(f"Sparse checkout configured for: {self.sparse_paths}")
    
    def ingest(self) -> Generator[Chunk, None, None]:
        """
        Génère les chunks depuis les fichiers HackTricks.
        
        Yields:
            Chunk: Chunks markdown prêts à indexer
        """
        if not self.dest_path.exists():
            logger.warning(f"HackTricks not found at {self.dest_path}. Run sync() first.")
            return
        
        # Parcourir pentesting-web/
        web_path = self.dest_path / "pentesting-web"
        if not web_path.exists():
            # Essayer sans le sous-dossier (structure peut varier)
            web_path = self.dest_path
        
        self._chunks_count = 0
        self._files_processed = 0
        
        for md_file in web_path.rglob("*.md"):
            if should_ignore(md_file):
                continue
            
            try:
                chunks = self._process_file(md_file)
                self._files_processed += 1
                
                for chunk in chunks:
                    self._chunks_count += 1
                    yield chunk
                    
            except Exception as e:
                logger.warning(f"Failed to process {md_file}: {e}")
                continue
        
        logger.info(f"HackTricks ingestion: {self._files_processed} files, {self._chunks_count} chunks")
    
    def _process_file(self, file_path: Path) -> List[Chunk]:
        """
        Traite un fichier markdown et retourne ses chunks.
        
        Args:
            file_path: Chemin du fichier .md
            
        Returns:
            Liste de Chunks
        """
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        
        # Extraire le vuln_type depuis le path
        vuln_type = extract_vuln_type(file_path)
        
        # Calculer le chemin relatif pour les metadata
        try:
            relative_path = file_path.relative_to(self.dest_path)
        except ValueError:
            relative_path = file_path
        
        # Chunker le markdown
        chunks = chunk_markdown(
            content=content,
            source="hacktricks",
            vuln_type=vuln_type,
            file_path=str(relative_path),
            url=f"https://book.hacktricks.xyz/{relative_path}".replace(".md", ""),
        )
        
        return chunks
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de l'ingestor."""
        # Calculer la taille du repo
        size_bytes = 0
        if self.dest_path.exists():
            for f in self.dest_path.rglob("*"):
                if f.is_file():
                    size_bytes += f.stat().st_size
        
        return {
            "source": "hacktricks",
            "chunks_count": self._chunks_count,
            "files_processed": self._files_processed,
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / (1024 * 1024), 2),
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "dest_path": str(self.dest_path),
            "sparse_paths": self.sparse_paths,
        }
    
    def get_vuln_types_found(self) -> Dict[str, int]:
        """
        Compte les vuln_types trouvés dans le repo.
        
        Returns:
            Dict vuln_type → count
        """
        counts: Dict[str, int] = {}
        
        web_path = self.dest_path / "pentesting-web"
        if not web_path.exists():
            web_path = self.dest_path
        
        for md_file in web_path.rglob("*.md"):
            if should_ignore(md_file):
                continue
            vuln_type = extract_vuln_type(md_file)
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        
        return counts


def clone_hacktricks_sparse(dest: Path = DEFAULT_DEST) -> None:
    """
    Helper function pour cloner HackTricks en sparse.
    
    Args:
        dest: Chemin de destination
    """
    config = IngestorConfig(name="hacktricks")
    ingestor = HackTricksIngestor(config, dest_path=dest)
    ingestor.sync()


def ingest_hacktricks(dest: Path = DEFAULT_DEST) -> IngestStats:
    """
    Helper function pour ingérer HackTricks.
    
    Args:
        dest: Chemin du repo cloné
        
    Returns:
        IngestStats avec les statistiques
    """
    from ghost_hunter.core.rag.vector_store import get_vector_store
    
    config = IngestorConfig(name="hacktricks")
    ingestor = HackTricksIngestor(config, dest_path=dest)
    
    store = get_vector_store()
    
    start = time.time()
    chunks_added = 0
    errors = 0
    
    # Batch pour performance
    batch: List[Chunk] = []
    batch_size = 100
    
    for chunk in ingestor.ingest():
        batch.append(chunk)
        
        if len(batch) >= batch_size:
            try:
                store.upsert(batch)
                chunks_added += len(batch)
            except Exception as e:
                logger.error(f"Failed to upsert batch: {e}")
                errors += len(batch)
            batch = []
    
    # Dernier batch
    if batch:
        try:
            store.upsert(batch)
            chunks_added += len(batch)
        except Exception as e:
            logger.error(f"Failed to upsert final batch: {e}")
            errors += len(batch)
    
    duration = (time.time() - start) * 1000
    
    return IngestStats(
        source="hacktricks",
        chunks_added=chunks_added,
        errors=errors,
        duration_ms=duration
    )

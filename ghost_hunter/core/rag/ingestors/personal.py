"""
Personal Reports Ingestor
=========================
Ingestion des rapports de bug bounty personnels.

Features:
- Parse YAML frontmatter
- Validation des champs obligatoires
- Poids 1.5x automatique (priorité expérience personnelle)
- Chunking par sections (Summary, PoC, Learnings)
"""

import re
import logging
from pathlib import Path
from typing import Generator, Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime

import yaml

from ghost_hunter.core.rag.contracts import Chunk
from ghost_hunter.core.rag.ingestors.base import BaseIngestor
from ghost_hunter.core.rag.ingestors.registry import IngestorRegistry


logger = logging.getLogger(__name__)


# ============================================================================
# Validation
# ============================================================================

class ReportValidationError(ValueError):
    """Erreur de validation d'un rapport."""
    pass


@dataclass
class ReportFrontmatter:
    """Frontmatter YAML d'un rapport personnel."""
    
    # Champs obligatoires
    title: str
    vuln_type: str
    target: str
    date: str
    
    # Champs optionnels
    severity: str = "medium"
    bounty: Optional[str] = None
    platform: Optional[str] = None  # hackerone, bugcrowd, yeswehack...
    status: str = "resolved"  # resolved, triaged, duplicate, na
    tags: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    
    # Metadata calculées
    file_path: Optional[str] = None
    
    REQUIRED_FIELDS = ["title", "vuln_type", "target", "date"]
    
    VALID_VULN_TYPES = {
        "xss", "sqli", "ssrf", "ssti", "idor", "rce", "lfi", "xxe",
        "csrf", "auth_bypass", "broken_access", "info_disclosure",
        "open_redirect", "file_upload", "deserialization", "business_logic",
        "rate_limiting", "other"
    }
    
    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    
    VALID_STATUSES = {"resolved", "triaged", "duplicate", "na", "pending"}
    
    @classmethod
    def from_dict(cls, data: dict, file_path: Optional[str] = None) -> "ReportFrontmatter":
        """Crée un frontmatter depuis un dict YAML."""
        # Vérifier champs obligatoires
        missing = [f for f in cls.REQUIRED_FIELDS if f not in data or not data[f]]
        if missing:
            raise ReportValidationError(f"Missing required fields: {missing}")
        
        # Valider vuln_type
        vuln_type = data["vuln_type"].lower()
        if vuln_type not in cls.VALID_VULN_TYPES:
            raise ReportValidationError(
                f"Invalid vuln_type '{vuln_type}'. Valid: {cls.VALID_VULN_TYPES}"
            )
        
        # Valider severity
        severity = data.get("severity", "medium").lower()
        if severity not in cls.VALID_SEVERITIES:
            raise ReportValidationError(
                f"Invalid severity '{severity}'. Valid: {cls.VALID_SEVERITIES}"
            )
        
        # Valider status
        status = data.get("status", "resolved").lower()
        if status not in cls.VALID_STATUSES:
            raise ReportValidationError(
                f"Invalid status '{status}'. Valid: {cls.VALID_STATUSES}"
            )
        
        return cls(
            title=data["title"],
            vuln_type=vuln_type,
            target=data["target"],
            date=str(data["date"]),
            severity=severity,
            bounty=data.get("bounty"),
            platform=data.get("platform"),
            status=status,
            tags=data.get("tags", []),
            cwe=data.get("cwe"),
            cvss=data.get("cvss"),
            file_path=file_path,
        )


# ============================================================================
# Parser
# ============================================================================

FRONTMATTER_PATTERN = re.compile(
    r'^---\s*\n(.*?)\n---\s*\n',
    re.DOTALL
)

SECTION_PATTERN = re.compile(
    r'^##\s+(.+)$',
    re.MULTILINE
)


def parse_frontmatter(content: str) -> tuple[Optional[dict], str]:
    """
    Extrait le frontmatter YAML du contenu markdown.
    
    Returns:
        Tuple (frontmatter_dict, remaining_content)
    """
    match = FRONTMATTER_PATTERN.match(content)
    if not match:
        return None, content
    
    try:
        frontmatter = yaml.safe_load(match.group(1))
        remaining = content[match.end():]
        return frontmatter, remaining
    except yaml.YAMLError as e:
        raise ReportValidationError(f"Invalid YAML frontmatter: {e}")


def extract_sections(content: str) -> Dict[str, str]:
    """
    Extrait les sections (## Heading) du markdown.
    
    Returns:
        Dict {section_name: section_content}
    """
    sections = {}
    current_section = "intro"
    current_content = []
    
    for line in content.split("\n"):
        match = SECTION_PATTERN.match(line)
        if match:
            # Sauvegarder la section précédente
            if current_content:
                sections[current_section] = "\n".join(current_content).strip()
            
            current_section = match.group(1).lower().strip()
            current_content = []
        else:
            current_content.append(line)
    
    # Dernière section
    if current_content:
        sections[current_section] = "\n".join(current_content).strip()
    
    return sections


def parse_report(file_path: Path) -> tuple[ReportFrontmatter, Dict[str, str]]:
    """
    Parse un rapport personnel complet.
    
    Args:
        file_path: Chemin vers le fichier .md
        
    Returns:
        Tuple (frontmatter, sections)
        
    Raises:
        ReportValidationError: Si le rapport est invalide
    """
    if not file_path.exists():
        raise ReportValidationError(f"File not found: {file_path}")
    
    if not file_path.suffix == ".md":
        raise ReportValidationError(f"Not a markdown file: {file_path}")
    
    content = file_path.read_text(encoding="utf-8")
    
    # Extraire frontmatter
    fm_dict, remaining = parse_frontmatter(content)
    if fm_dict is None:
        raise ReportValidationError("Missing YAML frontmatter (---)")
    
    frontmatter = ReportFrontmatter.from_dict(fm_dict, str(file_path))
    
    # Extraire sections
    sections = extract_sections(remaining)
    
    return frontmatter, sections


def validate_report(file_path: Path) -> List[str]:
    """
    Valide un rapport sans l'ingérer.
    
    Returns:
        Liste des erreurs (vide si OK)
    """
    errors = []
    
    try:
        frontmatter, sections = parse_report(file_path)
        
        # Warnings (pas bloquants)
        if "summary" not in sections:
            errors.append("Warning: Missing '## Summary' section")
        if "poc" not in sections and "proof of concept" not in sections:
            errors.append("Warning: Missing '## PoC' or '## Proof of Concept' section")
            
    except ReportValidationError as e:
        errors.append(f"Error: {e}")
    except Exception as e:
        errors.append(f"Unexpected error: {e}")
    
    return errors


# ============================================================================
# Ingestor
# ============================================================================

# Poids boost pour les rapports personnels (expérience > théorie)
PERSONAL_REPORT_WEIGHT = 1.5


@IngestorRegistry.register("personal")
class PersonalReportsIngestor(BaseIngestor):
    """
    Ingestor pour les rapports de bug bounty personnels.
    
    Les rapports personnels ont un poids 1.5x car l'expérience
    propre est plus pertinente que la documentation générique.
    """
    
    source_type = "local"
    
    def __init__(
        self,
        reports_dir: Optional[Path] = None,
        weight: float = PERSONAL_REPORT_WEIGHT,
    ):
        """
        Args:
            reports_dir: Dossier contenant les rapports (défaut: knowledge/personal_reports/)
            weight: Poids multiplicateur (défaut: 1.5)
        """
        if reports_dir is None:
            reports_dir = Path(__file__).parent.parent.parent.parent.parent / "knowledge" / "personal_reports"
        
        self.reports_dir = Path(reports_dir)
        self.weight = weight
        self._stats = {
            "files_found": 0,
            "files_valid": 0,
            "files_invalid": 0,
            "chunks_created": 0,
        }
    
    def sync(self) -> None:
        """Pas de sync nécessaire pour les fichiers locaux."""
        pass
    
    def ingest(self) -> Generator[Chunk, None, None]:
        """
        Génère des chunks depuis les rapports personnels.
        
        Yields:
            Chunk pour chaque section de rapport
        """
        if not self.reports_dir.exists():
            logger.warning(f"Reports directory not found: {self.reports_dir}")
            return
        
        # Trouver tous les fichiers .md (sauf TEMPLATE)
        md_files = [
            f for f in self.reports_dir.rglob("*.md")
            if not f.name.upper().startswith("TEMPLATE")
            and not f.name.upper().startswith("README")
        ]
        
        self._stats["files_found"] = len(md_files)
        
        for file_path in md_files:
            try:
                chunks = self._process_report(file_path)
                for chunk in chunks:
                    self._stats["chunks_created"] += 1
                    yield chunk
                self._stats["files_valid"] += 1
                
            except ReportValidationError as e:
                logger.warning(f"Invalid report {file_path}: {e}")
                self._stats["files_invalid"] += 1
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")
                self._stats["files_invalid"] += 1
    
    def _process_report(self, file_path: Path) -> List[Chunk]:
        """Traite un rapport et retourne ses chunks."""
        frontmatter, sections = parse_report(file_path)
        
        # Calculer le chemin relatif (ou absolu si hors du reports_dir)
        try:
            source_path = str(file_path.relative_to(self.reports_dir))
        except ValueError:
            source_path = str(file_path)
        
        chunks = []
        
        # Chunk principal (summary ou tout le contenu)
        main_text = self._build_main_text(frontmatter, sections)
        main_chunk = Chunk.create(
            text=main_text,
            source="personal",
            chunk_type="report",
            vuln_type=frontmatter.vuln_type,
            chunk_id=f"personal:{file_path.stem}:main",
            # Extra metadata
            title=frontmatter.title,
            target=frontmatter.target,
            severity=frontmatter.severity,
            platform=frontmatter.platform,
            bounty=frontmatter.bounty,
            date=frontmatter.date,
            tags=frontmatter.tags,
            weight=self.weight,
            source_path=source_path,
        )
        chunks.append(main_chunk)
        
        # Chunk PoC séparé (si existe et assez long)
        poc_section = sections.get("poc") or sections.get("proof of concept")
        if poc_section and len(poc_section) > 100:
            poc_chunk = Chunk.create(
                text=f"# PoC: {frontmatter.title}\n\nTarget: {frontmatter.target}\nVuln: {frontmatter.vuln_type}\n\n{poc_section}",
                source="personal",
                chunk_type="poc",
                vuln_type=frontmatter.vuln_type,
                chunk_id=f"personal:{file_path.stem}:poc",
                title=f"PoC: {frontmatter.title}",
                target=frontmatter.target,
                weight=self.weight,
                source_path=source_path,
            )
            chunks.append(poc_chunk)
        
        # Chunk Learnings séparé (si existe)
        learnings = sections.get("learnings") or sections.get("lessons learned")
        if learnings and len(learnings) > 50:
            learn_chunk = Chunk.create(
                text=f"# Learnings: {frontmatter.vuln_type}\n\nFrom: {frontmatter.target}\n\n{learnings}",
                source="personal",
                chunk_type="learnings",
                vuln_type=frontmatter.vuln_type,
                chunk_id=f"personal:{file_path.stem}:learnings",
                title=f"Learnings: {frontmatter.title}",
                weight=self.weight * 1.2,  # Extra boost for learnings
                source_path=source_path,
            )
            chunks.append(learn_chunk)
        
        return chunks
    
    def _build_main_text(
        self,
        frontmatter: ReportFrontmatter,
        sections: Dict[str, str]
    ) -> str:
        """Construit le texte principal du chunk."""
        parts = [
            f"# {frontmatter.title}",
            f"\nTarget: {frontmatter.target}",
            f"Vulnerability: {frontmatter.vuln_type}",
            f"Severity: {frontmatter.severity}",
        ]
        
        if frontmatter.bounty:
            parts.append(f"Bounty: {frontmatter.bounty}")
        if frontmatter.platform:
            parts.append(f"Platform: {frontmatter.platform}")
        if frontmatter.cwe:
            parts.append(f"CWE: {frontmatter.cwe}")
        
        parts.append("")  # Ligne vide
        
        # Ajouter summary
        summary = sections.get("summary") or sections.get("intro", "")
        if summary:
            parts.append(summary)
        
        return "\n".join(parts)
    
    def get_stats(self) -> dict:
        """Retourne les statistiques."""
        return self._stats.copy()
    
    def ingest_single(self, file_path: Path) -> List[Chunk]:
        """
        Ingère un seul rapport (pour file watcher).
        
        Args:
            file_path: Chemin vers le rapport
            
        Returns:
            Liste des chunks créés
        """
        return self._process_report(file_path)


# ============================================================================
# Helper Functions
# ============================================================================

def ingest_report(file_path: Path, weight: float = PERSONAL_REPORT_WEIGHT) -> List[Chunk]:
    """
    Helper pour ingérer un rapport personnel.
    
    Args:
        file_path: Chemin vers le rapport .md
        weight: Poids multiplicateur
        
    Returns:
        Liste des chunks créés
    """
    ingestor = PersonalReportsIngestor(weight=weight)
    return ingestor.ingest_single(file_path)


def list_reports(reports_dir: Optional[Path] = None) -> List[Path]:
    """
    Liste tous les rapports dans le dossier.
    
    Returns:
        Liste des chemins de rapports
    """
    if reports_dir is None:
        reports_dir = Path(__file__).parent.parent.parent.parent.parent / "knowledge" / "personal_reports"
    
    if not reports_dir.exists():
        return []
    
    return [
        f for f in reports_dir.rglob("*.md")
        if not f.name.upper().startswith("TEMPLATE")
        and not f.name.upper().startswith("README")
    ]

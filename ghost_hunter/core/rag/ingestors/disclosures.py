"""
Ghost-Hunter HackerOne Disclosures Ingestor
===========================================
Ingestor pour les reports HackerOne publics via le repo reddelexc/hackerone-reports.

Sources:
- GitHub: https://github.com/reddelexc/hackerone-reports (data.csv)
- HackerOne API: https://hackerone.com/reports/{id}.json (enrichment)

Usage:
    from ghost_hunter.core.rag.ingestors.disclosures import HackerOneDisclosureIngestor
    
    ingestor = HackerOneDisclosureIngestor(config)
    ingestor.sync()  # Download CSV
    for chunk in ingestor.ingest():
        store.upsert([chunk])
"""

import csv
import hashlib
import logging
import time
import re
from pathlib import Path
from typing import List, Generator, Dict, Any, Optional, Set
from datetime import datetime
from dataclasses import dataclass, field

try:
    import requests
except ImportError:
    requests = None

from ghost_hunter.core.rag.ingestors.base import BaseIngestor, IngestorConfig, SyncError
from ghost_hunter.core.rag.ingestors.registry import IngestorRegistry
from ghost_hunter.core.rag.contracts import Chunk, IngestStats

logger = logging.getLogger(__name__)


# Configuration
GITHUB_CSV_URL = "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv"
H1_REPORT_API = "https://hackerone.com/reports/{report_id}.json"

# Default destination
DEFAULT_DEST = Path(__file__).parent.parent.parent.parent.parent / "knowledge" / "sources" / "disclosures"


# Mapping des vuln_type HackerOne vers nos types normalisés
H1_VULN_TYPE_MAPPING = {
    # XSS
    "xss": "xss",
    "cross-site scripting": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "dom xss": "xss",
    "dom-based xss": "xss",
    "domxss": "xss",
    
    # SQL Injection
    "sql injection": "sqli",
    "sqli": "sqli",
    "sql": "sqli",
    "blind sql injection": "sqli",
    "nosql injection": "sqli",
    
    # SSRF
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "server side request forgery": "ssrf",
    
    # XXE
    "xxe": "xxe",
    "xml injection": "xxe",
    "xml external entity": "xxe",
    
    # SSTI
    "ssti": "ssti",
    "server-side template injection": "ssti",
    "template injection": "ssti",
    
    # IDOR / Access Control
    "idor": "idor",
    "insecure direct object reference": "idor",
    "broken access control": "idor",
    "bola": "idor",
    "authorization bypass": "idor",
    "privilege escalation": "idor",
    
    # LFI/RFI/Path Traversal
    "lfi": "lfi",
    "rfi": "lfi",
    "local file inclusion": "lfi",
    "file inclusion": "lfi",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    "file reading": "lfi",
    
    # RCE / Command Injection
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "rce",
    "os command injection": "rce",
    "code injection": "rce",
    "code execution": "rce",
    
    # CSRF
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    
    # Auth Bypass
    "authentication bypass": "auth_bypass",
    "auth bypass": "auth_bypass",
    "2fa bypass": "auth_bypass",
    "mfa bypass": "auth_bypass",
    "oauth": "auth_bypass",
    "jwt": "auth_bypass",
    "session fixation": "auth_bypass",
    "session hijacking": "auth_bypass",
    
    # Open Redirect
    "open redirect": "open_redirect",
    "url redirect": "open_redirect",
    
    # File Upload
    "file upload": "file_upload",
    "unrestricted file upload": "file_upload",
    "arbitrary file upload": "file_upload",
    
    # Deserialization
    "deserialization": "deserialization",
    "insecure deserialization": "deserialization",
    
    # Race Condition
    "race condition": "race_condition",
    "toctou": "race_condition",
    
    # Information Disclosure
    "information disclosure": "info_disclosure",
    "information leakage": "info_disclosure",
    "sensitive data exposure": "info_disclosure",
    "pii": "info_disclosure",
    
    # Business Logic
    "business logic": "business_logic",
    "logic flaw": "business_logic",
    
    # Cache
    "cache poisoning": "cache_poisoning",
    "web cache poisoning": "cache_poisoning",
    
    # CORS
    "cors": "cors",
    "cors misconfiguration": "cors",
    
    # Clickjacking
    "clickjacking": "clickjacking",
    "ui redressing": "clickjacking",
    
    # GraphQL
    "graphql": "graphql",
    
    # API
    "api": "api",
    "rest api": "api",
    
    # Account Takeover
    "account takeover": "auth_bypass",
    "ato": "auth_bypass",
    
    # Subdomain Takeover
    "subdomain takeover": "subdomain_takeover",
    
    # DoS
    "dos": "dos",
    "denial of service": "dos",
    "ddos": "dos",
}

# Keywords dans title pour déduire le vuln_type si pas explicite
TITLE_KEYWORDS_MAPPING = {
    "xss": "xss",
    "cross site scripting": "xss",
    "cross-site scripting": "xss",
    "sql injection": "sqli",
    "sqli": "sqli",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "ssti": "ssti",
    "template injection": "ssti",
    "idor": "idor",
    "insecure direct object": "idor",
    "lfi": "lfi",
    "rfi": "lfi",
    "local file": "lfi",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "rce",
    "csrf": "csrf",
    "open redirect": "open_redirect",
    "file upload": "file_upload",
    "information disclosure": "info_disclosure",
    "account takeover": "auth_bypass",
    "authentication bypass": "auth_bypass",
    "2fa bypass": "auth_bypass",
    "race condition": "race_condition",
    "cache poisoning": "cache_poisoning",
    "cors": "cors",
    "graphql": "graphql",
    "subdomain takeover": "subdomain_takeover",
}


@dataclass
class DisclosureReport:
    """Un rapport HackerOne parsé."""
    report_id: str
    title: str
    program: str
    link: str
    upvotes: int
    bounty: float
    vuln_type: str  # Type brut de H1
    normalized_vuln_type: str = "unknown"  # Type normalisé
    
    # Enriched data (optionnel)
    summary: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    impact: Optional[str] = None
    severity: Optional[str] = None
    
    def __post_init__(self):
        """Normalise le vuln_type."""
        if self.vuln_type:
            self.normalized_vuln_type = normalize_vuln_type(self.vuln_type, self.title)
        else:
            self.normalized_vuln_type = infer_vuln_type_from_title(self.title)


def normalize_vuln_type(raw_type: str, title: str = "") -> str:
    """
    Normalise un vuln_type HackerOne vers notre format.
    
    Args:
        raw_type: Type de vulnérabilité brut de HackerOne
        title: Titre du report (pour inférence)
        
    Returns:
        Type normalisé (ex: 'xss', 'sqli', etc.)
    """
    if not raw_type:
        return infer_vuln_type_from_title(title)
    
    raw_lower = raw_type.lower().strip()
    
    # Mapping direct
    if raw_lower in H1_VULN_TYPE_MAPPING:
        return H1_VULN_TYPE_MAPPING[raw_lower]
    
    # Recherche partielle
    for key, value in H1_VULN_TYPE_MAPPING.items():
        if key in raw_lower or raw_lower in key:
            return value
    
    # Fallback sur le title
    return infer_vuln_type_from_title(title)


def infer_vuln_type_from_title(title: str) -> str:
    """
    Infère le type de vulnérabilité depuis le titre.
    
    Args:
        title: Titre du report
        
    Returns:
        Type inféré ou 'unknown'
    """
    if not title:
        return "unknown"
    
    title_lower = title.lower()
    
    for keyword, vuln_type in TITLE_KEYWORDS_MAPPING.items():
        if keyword in title_lower:
            return vuln_type
    
    return "unknown"


def extract_report_id(link: str) -> str:
    """
    Extrait l'ID du report depuis le lien.
    
    Args:
        link: Lien HackerOne (ex: 'hackerone.com/reports/123456')
        
    Returns:
        ID du report (ex: '123456')
    """
    match = re.search(r'/reports/(\d+)', link)
    if match:
        return match.group(1)
    return ""


@IngestorRegistry.register("disclosures")
class HackerOneDisclosureIngestor(BaseIngestor):
    """
    Ingestor pour les reports HackerOne publics.
    
    Fonctionnalités:
    - Download du CSV depuis reddelexc/hackerone-reports
    - Parsing et normalisation des vuln_types
    - Enrichissement optionnel via HackerOne API
    - Génération de chunks optimisés pour le RAG
    """
    
    source_type = "api"
    
    def __init__(self, config: IngestorConfig):
        """
        Args:
            config: Configuration avec params:
                - data_dir: Répertoire de stockage (default: knowledge/sources/disclosures)
                - min_upvotes: Filtre sur les upvotes minimum (default: 0)
                - max_reports: Limite sur le nombre de reports (default: None)
                - enrich: Enrichir via API HackerOne (default: False)
                - vuln_types: Liste de types à inclure (default: tous)
        """
        super().__init__(config)
        
        params = config.params
        self.data_dir = Path(params.get("data_dir", DEFAULT_DEST))
        self.min_upvotes = params.get("min_upvotes", 0)
        self.max_reports = params.get("max_reports", None)
        self.enrich = params.get("enrich", False)
        self.vuln_types_filter: Optional[Set[str]] = None
        if "vuln_types" in params:
            self.vuln_types_filter = set(params["vuln_types"])
        
        self.csv_path = self.data_dir / "data.csv"
        self._reports: List[DisclosureReport] = []
        self._stats: Dict[str, Any] = {}
    
    def sync(self) -> None:
        """
        Télécharge/met à jour le CSV des disclosures.
        
        Le CSV contient: title, program, link, upvotes, bounty, vuln_type
        """
        if requests is None:
            raise SyncError("requests library not installed")
        
        logger.info(f"Syncing HackerOne disclosures to {self.data_dir}")
        
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            
            # Download CSV
            response = requests.get(GITHUB_CSV_URL, timeout=60)
            response.raise_for_status()
            
            # Write CSV
            self.csv_path.write_text(response.text, encoding="utf-8")
            
            # Update timestamp
            self._last_sync = datetime.now()
            
            logger.info(f"Downloaded {len(response.content)} bytes to {self.csv_path}")
            
        except Exception as e:
            if "RequestException" in type(e).__name__ or isinstance(e, IOError):
                raise SyncError(f"Failed to sync disclosures: {e}")
            raise SyncError(f"Failed to download disclosures CSV: {e}")
    
    def _load_reports(self) -> List[DisclosureReport]:
        """
        Charge et parse le CSV des reports.
        
        Returns:
            Liste de DisclosureReport
        """
        if not self.csv_path.exists():
            logger.warning(f"CSV not found at {self.csv_path}, run sync() first")
            return []
        
        reports = []
        
        try:
            with open(self.csv_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    try:
                        # Parse bounty (format: "$1,000" ou "1000")
                        bounty_str = row.get('bounty', '0')
                        bounty = parse_bounty(bounty_str)
                        
                        # Parse upvotes
                        upvotes = int(row.get('upvotes', 0))
                        
                        # Filtre min_upvotes
                        if upvotes < self.min_upvotes:
                            continue
                        
                        # Create report
                        report = DisclosureReport(
                            report_id=extract_report_id(row.get('link', '')),
                            title=row.get('title', ''),
                            program=row.get('program', ''),
                            link=row.get('link', ''),
                            upvotes=upvotes,
                            bounty=bounty,
                            vuln_type=row.get('vuln_type', ''),
                        )
                        
                        # Filtre vuln_types
                        if self.vuln_types_filter:
                            if report.normalized_vuln_type not in self.vuln_types_filter:
                                continue
                        
                        reports.append(report)
                        
                    except (ValueError, KeyError) as e:
                        logger.debug(f"Skipping malformed row: {e}")
                        continue
                    
                    # Limite max_reports
                    if self.max_reports and len(reports) >= self.max_reports:
                        break
            
            logger.info(f"Loaded {len(reports)} reports from CSV")
            
        except Exception as e:
            logger.error(f"Failed to load CSV: {e}")
            return []
        
        return reports
    
    def _enrich_report(self, report: DisclosureReport) -> DisclosureReport:
        """
        Enrichit un report via l'API HackerOne.
        
        Args:
            report: Report à enrichir
            
        Returns:
            Report enrichi
        """
        if not self.enrich or requests is None:
            return report
        
        try:
            url = H1_REPORT_API.format(report_id=report.report_id)
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract summary/vulnerability_information
                report.summary = data.get('vulnerability_information', '')
                
                # Extract severity
                if 'severity_rating' in data:
                    report.severity = data['severity_rating']
                
                logger.debug(f"Enriched report {report.report_id}")
            
            # Rate limiting
            time.sleep(0.5)
            
        except Exception as e:
            logger.debug(f"Failed to enrich report {report.report_id}: {e}")
        
        return report
    
    def ingest(self) -> Generator[Chunk, None, None]:
        """
        Génère les chunks à indexer.
        
        Yields:
            Chunk: Chunks avec metadata enrichies
        """
        reports = self._load_reports()
        
        for report in reports:
            # Enrichissement optionnel
            if self.enrich:
                report = self._enrich_report(report)
            
            # Générer le chunk
            chunk = self._create_chunk(report)
            if chunk and self.validate_chunk(chunk):
                yield chunk
    
    def _create_chunk(self, report: DisclosureReport) -> Optional[Chunk]:
        """
        Crée un chunk depuis un report.
        
        Args:
            report: Report parsé
            
        Returns:
            Chunk ou None si invalide
        """
        if not report.title:
            return None
        
        # Construire le texte du chunk
        text_parts = [
            f"# {report.title}",
            f"Program: {report.program}",
            f"Vulnerability Type: {report.normalized_vuln_type}",
        ]
        
        if report.bounty > 0:
            text_parts.append(f"Bounty: ${report.bounty:,.0f}")
        
        if report.upvotes > 0:
            text_parts.append(f"Upvotes: {report.upvotes}")
        
        if report.severity:
            text_parts.append(f"Severity: {report.severity}")
        
        if report.summary:
            text_parts.append(f"\n## Summary\n{report.summary}")
        
        text = "\n".join(text_parts)
        
        # ID unique
        chunk_id = f"h1_disclosure_{report.report_id}"
        
        # Metadata
        metadata = {
            "source": "h1_disclosure",
            "type": "vulnerability_report",
            "vuln_type": report.normalized_vuln_type,
            "indexed_at": datetime.now().isoformat(),
            "report_id": report.report_id,
            "program": report.program,
            "bounty": report.bounty,
            "upvotes": report.upvotes,
            "link": f"https://{report.link}",
        }
        
        if report.severity:
            metadata["severity"] = report.severity
        
        return Chunk(id=chunk_id, text=text, metadata=metadata)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Retourne les statistiques de la source.
        
        Returns:
            Dict avec stats
        """
        stats = {
            "chunks_count": 0,
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "size_bytes": 0,
            "vuln_type_distribution": {},
            "top_programs": [],
        }
        
        if self.csv_path.exists():
            stats["size_bytes"] = self.csv_path.stat().st_size
        
        if not self._reports:
            self._reports = self._load_reports()
        
        stats["chunks_count"] = len(self._reports)
        
        # Distribution par vuln_type
        vuln_dist: Dict[str, int] = {}
        program_dist: Dict[str, int] = {}
        
        for report in self._reports:
            vt = report.normalized_vuln_type
            vuln_dist[vt] = vuln_dist.get(vt, 0) + 1
            
            prog = report.program
            program_dist[prog] = program_dist.get(prog, 0) + 1
        
        stats["vuln_type_distribution"] = vuln_dist
        stats["top_programs"] = sorted(
            program_dist.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return stats


def parse_bounty(bounty_str: str) -> float:
    """
    Parse une chaîne bounty en float.
    
    Args:
        bounty_str: Ex: '$1,000', '1000', '0'
        
    Returns:
        Valeur numérique
    """
    if not bounty_str:
        return 0.0
    
    # Enlever $, quotes, virgules
    cleaned = bounty_str.replace('"', '').replace('$', '').replace(',', '').strip()
    
    try:
        return float(cleaned)
    except ValueError:
        return 0.0

"""
NVD (National Vulnerability Database) Ingestor.

Synchronise les CVE récents depuis l'API NVD.
IMPORTANT: À exécuter via cron, JAMAIS pendant le pipeline actif.

Rate Limit: 5 requêtes / 30 secondes (API publique sans clé).
Filtre: Seulement CVE web (CWE whitelist).
"""

import time
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Generator, Optional, List, Dict, Any, Set
from dataclasses import dataclass
import json

import httpx
import yaml

from ghost_hunter.core.rag.contracts import Chunk
from ghost_hunter.core.rag.ingestors.base import BaseIngestor
from ghost_hunter.core.rag.ingestors.registry import IngestorRegistry


logger = logging.getLogger(__name__)


# ============================================================================
# CWE Web Filter
# ============================================================================

def load_cwe_whitelist(config_path: Optional[Path] = None) -> Set[str]:
    """
    Charge la liste des CWE web autorisés depuis le fichier YAML.
    
    Returns:
        Set de CWE IDs (ex: {"CWE-79", "CWE-89", ...})
    """
    if config_path is None:
        config_path = Path(__file__).parent.parent.parent.parent.parent / "knowledge" / "config" / "cwe_web_filter.yaml"
    
    if not config_path.exists():
        logger.warning(f"CWE config not found: {config_path}, using defaults")
        return _get_default_web_cwes()
    
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
    
    web_cwes: Set[str] = set()
    
    # Extraire tous les CWE des catégories web_cwe
    for category, cwes in config.get("web_cwe", {}).items():
        if isinstance(cwes, list):
            for cwe in cwes:
                # Normaliser le format (CWE-79 ou 79 → CWE-79)
                web_cwes.add(_normalize_cwe(cwe))
    
    logger.info(f"Loaded {len(web_cwes)} web CWEs from config")
    return web_cwes


def _normalize_cwe(cwe: Any) -> str:
    """Normalise CWE ID vers format CWE-XXX."""
    cwe_str = str(cwe).upper().strip()
    if cwe_str.startswith("CWE-"):
        return cwe_str
    # Juste un numéro
    return f"CWE-{cwe_str}"


def _get_default_web_cwes() -> Set[str]:
    """CWE web par défaut si le fichier config n'existe pas."""
    return {
        "CWE-79",   # XSS
        "CWE-89",   # SQLi
        "CWE-94",   # Code Injection
        "CWE-78",   # OS Command Injection
        "CWE-611",  # XXE
        "CWE-918",  # SSRF
        "CWE-352",  # CSRF
        "CWE-22",   # Path Traversal
        "CWE-434",  # File Upload
        "CWE-639",  # IDOR
        "CWE-502",  # Deserialization
        "CWE-1336", # SSTI
        "CWE-601",  # Open Redirect
    }


def extract_cwe_from_cve(cve_data: dict) -> List[str]:
    """
    Extrait les CWE IDs d'un objet CVE NVD.
    
    Args:
        cve_data: Objet CVE de l'API NVD
        
    Returns:
        Liste de CWE IDs (ex: ["CWE-79", "CWE-89"])
    """
    cwes = []
    
    # NVD API 2.0 format
    weaknesses = cve_data.get("cve", {}).get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") or value.isdigit():
                cwes.append(_normalize_cwe(value))
    
    return cwes


def extract_cvss_score(cve_data: dict) -> Optional[float]:
    """
    Extrait le score CVSS d'un objet CVE NVD.
    
    Priorité: CVSS v3.1 > CVSS v3.0 > CVSS v2.0
    """
    metrics = cve_data.get("cve", {}).get("metrics", {})
    
    # CVSS v3.1
    if "cvssMetricV31" in metrics:
        for m in metrics["cvssMetricV31"]:
            if "cvssData" in m:
                return m["cvssData"].get("baseScore")
    
    # CVSS v3.0
    if "cvssMetricV30" in metrics:
        for m in metrics["cvssMetricV30"]:
            if "cvssData" in m:
                return m["cvssData"].get("baseScore")
    
    # CVSS v2.0
    if "cvssMetricV2" in metrics:
        for m in metrics["cvssMetricV2"]:
            if "cvssData" in m:
                return m["cvssData"].get("baseScore")
    
    return None


def get_severity_from_cvss(score: Optional[float]) -> str:
    """Convertit score CVSS en niveau de sévérité."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


# ============================================================================
# Rate Limiter
# ============================================================================

@dataclass
class RateLimiter:
    """Rate limiter pour l'API NVD (5 req/30s sans clé API)."""
    
    requests_per_window: int = 5
    window_seconds: int = 30
    _request_times: List[float] = None
    
    def __post_init__(self):
        self._request_times = []
    
    def wait_if_needed(self) -> None:
        """Attend si nécessaire pour respecter le rate limit."""
        now = time.time()
        
        # Nettoyer les requêtes hors fenêtre
        cutoff = now - self.window_seconds
        self._request_times = [t for t in self._request_times if t > cutoff]
        
        # Si on a atteint la limite, attendre
        if len(self._request_times) >= self.requests_per_window:
            sleep_time = self._request_times[0] + self.window_seconds - now
            if sleep_time > 0:
                logger.debug(f"Rate limit: sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)
        
        # Enregistrer cette requête
        self._request_times.append(time.time())
    
    def get_request_count(self) -> int:
        """Retourne le nombre de requêtes dans la fenêtre actuelle."""
        now = time.time()
        cutoff = now - self.window_seconds
        return len([t for t in self._request_times if t > cutoff])


# ============================================================================
# NVD API Client
# ============================================================================

class NVDApiClient:
    """Client pour l'API NVD 2.0."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Args:
            api_key: Clé API NVD optionnelle (augmente le rate limit)
        """
        self.api_key = api_key
        self.rate_limiter = RateLimiter(
            requests_per_window=50 if api_key else 5,
            window_seconds=30
        )
        self._client = httpx.Client(timeout=30.0)
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self._client.close()
    
    def fetch_cves(
        self,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        results_per_page: int = 100,
        start_index: int = 0,
    ) -> dict:
        """
        Récupère des CVE depuis l'API NVD.
        
        Args:
            pub_start_date: Date de publication min
            pub_end_date: Date de publication max
            results_per_page: Nombre de résultats par page (max 2000)
            start_index: Index de départ pour pagination
            
        Returns:
            Réponse JSON de l'API
        """
        self.rate_limiter.wait_if_needed()
        
        params = {
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index,
        }
        
        if pub_start_date:
            params["pubStartDate"] = pub_start_date.strftime("%Y-%m-%dT00:00:00.000")
        if pub_end_date:
            params["pubEndDate"] = pub_end_date.strftime("%Y-%m-%dT23:59:59.999")
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        response = self._client.get(self.BASE_URL, params=params, headers=headers)
        response.raise_for_status()
        
        return response.json()
    
    def fetch_all_cves(
        self,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
    ) -> Generator[dict, None, None]:
        """
        Itère sur tous les CVE avec pagination automatique.
        
        Yields:
            Objet CVE individuel
        """
        start_index = 0
        results_per_page = 500  # Balance between efficiency and memory
        
        while True:
            data = self.fetch_cves(
                pub_start_date=pub_start_date,
                pub_end_date=pub_end_date,
                results_per_page=results_per_page,
                start_index=start_index,
            )
            
            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)
            
            for vuln in vulnerabilities:
                yield vuln
            
            # Pagination
            start_index += len(vulnerabilities)
            if start_index >= total_results or not vulnerabilities:
                break
            
            logger.info(f"NVD: fetched {start_index}/{total_results} CVEs")


# ============================================================================
# NVD Sync Service
# ============================================================================

class NVDSyncService:
    """
    Service de synchronisation NVD → RAG.
    
    À exécuter via cron, JAMAIS pendant le pipeline actif.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        cwe_whitelist: Optional[Set[str]] = None,
        min_cvss: float = 5.0,
        max_age_days: int = 365,
    ):
        """
        Args:
            api_key: Clé API NVD optionnelle
            cwe_whitelist: Set de CWE autorisés (None = charger depuis config)
            min_cvss: Score CVSS minimum pour indexer
            max_age_days: Âge max des CVE en jours
        """
        self.api_key = api_key
        self.min_cvss = min_cvss
        self.max_age_days = max_age_days
        self.cwe_whitelist = cwe_whitelist or load_cwe_whitelist()
        
        self._stats = {
            "fetched": 0,
            "filtered_cwe": 0,
            "filtered_cvss": 0,
            "indexed": 0,
        }
    
    def is_web_cve(self, cve_data: dict) -> bool:
        """
        Vérifie si un CVE est une vulnérabilité web.
        
        Args:
            cve_data: Objet CVE de l'API NVD
            
        Returns:
            True si au moins un CWE est dans la whitelist
        """
        cwes = extract_cwe_from_cve(cve_data)
        return any(cwe in self.cwe_whitelist for cwe in cwes)
    
    def passes_cvss_filter(self, cve_data: dict) -> bool:
        """Vérifie si le CVE a un CVSS suffisant."""
        score = extract_cvss_score(cve_data)
        if score is None:
            return False  # Pas de score = on ignore
        return score >= self.min_cvss
    
    def cve_to_chunk(self, cve_data: dict) -> Optional[Chunk]:
        """
        Convertit un CVE en Chunk RAG.
        
        Args:
            cve_data: Objet CVE de l'API NVD
            
        Returns:
            Chunk ou None si invalide
        """
        cve = cve_data.get("cve", {})
        cve_id = cve.get("id", "")
        
        if not cve_id:
            return None
        
        # Extraire description
        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                desc_text = desc.get("value", "")
                break
        
        if not desc_text:
            return None
        
        # Métadonnées
        cwes = extract_cwe_from_cve(cve_data)
        cvss = extract_cvss_score(cve_data)
        severity = get_severity_from_cvss(cvss)
        
        # Mapper CWE vers vuln_type Ghost-Hunter
        vuln_type = self._cwe_to_vuln_type(cwes)
        
        # Construire le texte du chunk
        text = f"# {cve_id}\n\n{desc_text}"
        if cwes:
            text += f"\n\nCWE: {', '.join(cwes)}"
        if cvss:
            text += f"\nCVSS: {cvss} ({severity})"
        
        # Utiliser Chunk.create() avec le bon format de metadata
        return Chunk.create(
            text=text,
            source="nvd",
            chunk_type="cve",
            vuln_type=vuln_type,
            chunk_id=f"nvd:{cve_id}",
            # Extra metadata
            source_path=f"nvd/{cve_id}",
            tags=cwes + [severity],
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            cve_id=cve_id,
            cvss=cvss,
            severity=severity,
            cwes=cwes,
        )
    
    def _cwe_to_vuln_type(self, cwes: List[str]) -> str:
        """Mappe CWE vers vuln_type Ghost-Hunter."""
        cwe_mapping = {
            "CWE-79": "xss",
            "CWE-89": "sqli",
            "CWE-94": "rce",
            "CWE-78": "rce",
            "CWE-77": "rce",
            "CWE-611": "xxe",
            "CWE-918": "ssrf",
            "CWE-352": "csrf",
            "CWE-22": "lfi",
            "CWE-434": "file_upload",
            "CWE-639": "idor",
            "CWE-502": "deserialization",
            "CWE-1336": "ssti",
            "CWE-917": "ssti",
            "CWE-601": "open_redirect",
            "CWE-287": "auth_bypass",
            "CWE-306": "auth_bypass",
            "CWE-862": "broken_access",
            "CWE-863": "broken_access",
        }
        
        for cwe in cwes:
            if cwe in cwe_mapping:
                return cwe_mapping[cwe]
        
        return "unknown"
    
    def sync_recent(self, days: int = 1) -> List[Chunk]:
        """
        Synchronise les CVE des N derniers jours.
        
        Args:
            days: Nombre de jours à synchroniser
            
        Returns:
            Liste des Chunks créés
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        return self.sync_range(start_date, end_date)
    
    def sync_range(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> List[Chunk]:
        """
        Synchronise les CVE dans une plage de dates.
        
        Args:
            start_date: Date de début
            end_date: Date de fin
            
        Returns:
            Liste des Chunks créés
        """
        chunks = []
        
        logger.info(f"NVD Sync: {start_date.date()} → {end_date.date()}")
        
        with NVDApiClient(api_key=self.api_key) as client:
            for cve_data in client.fetch_all_cves(start_date, end_date):
                self._stats["fetched"] += 1
                
                # Filtre CWE web
                if not self.is_web_cve(cve_data):
                    self._stats["filtered_cwe"] += 1
                    continue
                
                # Filtre CVSS
                if not self.passes_cvss_filter(cve_data):
                    self._stats["filtered_cvss"] += 1
                    continue
                
                # Convertir en Chunk
                chunk = self.cve_to_chunk(cve_data)
                if chunk:
                    chunks.append(chunk)
                    self._stats["indexed"] += 1
        
        logger.info(
            f"NVD Sync complete: {self._stats['indexed']} indexed "
            f"({self._stats['fetched']} fetched, "
            f"{self._stats['filtered_cwe']} filtered by CWE, "
            f"{self._stats['filtered_cvss']} filtered by CVSS)"
        )
        
        return chunks
    
    def get_stats(self) -> dict:
        """Retourne les statistiques de la dernière sync."""
        return self._stats.copy()


# ============================================================================
# NVD Ingestor (pour le registry)
# ============================================================================

@IngestorRegistry.register("nvd")
class NVDIngestor(BaseIngestor):
    """
    Ingestor NVD pour le registry.
    
    Utilise NVDSyncService en interne.
    IMPORTANT: sync() ne fait RIEN (sync via cron uniquement).
    """
    
    source_type = "api"
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        min_cvss: float = 5.0,
        max_age_days: int = 365,
    ):
        self.api_key = api_key
        self.min_cvss = min_cvss
        self.max_age_days = max_age_days
        self._sync_service = None
        self._chunks: List[Chunk] = []
    
    @property
    def sync_service(self) -> NVDSyncService:
        """Lazy init du sync service."""
        if self._sync_service is None:
            self._sync_service = NVDSyncService(
                api_key=self.api_key,
                min_cvss=self.min_cvss,
                max_age_days=self.max_age_days,
            )
        return self._sync_service
    
    def sync(self) -> None:
        """
        NE FAIT RIEN - La sync NVD est gérée par cron.
        
        Utiliser sync_recent() pour forcer une sync manuelle.
        """
        logger.info("NVD sync skipped (use cron or sync_recent() manually)")
    
    def sync_recent(self, days: int = 1) -> None:
        """Force une sync des N derniers jours."""
        self._chunks = self.sync_service.sync_recent(days=days)
    
    def ingest(self) -> Generator[Chunk, None, None]:
        """
        Génère les chunks de la dernière sync.
        
        Appeler sync_recent() avant pour charger les données.
        """
        for chunk in self._chunks:
            yield chunk
    
    def get_stats(self) -> dict:
        """Retourne les statistiques."""
        stats = self.sync_service.get_stats()
        stats["chunks_ready"] = len(self._chunks)
        return stats


# ============================================================================
# Helper Functions
# ============================================================================

def sync_nvd_cves(days: int = 1, api_key: Optional[str] = None) -> List[Chunk]:
    """
    Helper pour synchroniser les CVE NVD.
    
    Args:
        days: Nombre de jours à synchroniser
        api_key: Clé API NVD optionnelle
        
    Returns:
        Liste des Chunks créés
    """
    service = NVDSyncService(api_key=api_key)
    return service.sync_recent(days=days)


def is_pipeline_active(pid_file: Optional[Path] = None) -> bool:
    """
    Vérifie si le pipeline Ghost-Hunter est actif.
    
    Args:
        pid_file: Chemin vers le fichier PID (défaut: data/pids/pipeline.pid)
        
    Returns:
        True si le pipeline est actif
    """
    if pid_file is None:
        pid_file = Path(__file__).parent.parent.parent.parent.parent / "data" / "pids" / "pipeline.pid"
    
    if not pid_file.exists():
        return False
    
    try:
        pid = int(pid_file.read_text().strip())
        # Vérifier si le processus existe
        import os
        os.kill(pid, 0)
        return True
    except (ValueError, ProcessLookupError, PermissionError):
        return False

"""
Ghost-Hunter Nuclei Scanner
============================
Scanner Nuclei intégré au pipeline pour détecter les vulns connues.
Tourne en PARALLÈLE du triage IA pour ne rien rater.
"""

import asyncio
import json
import tempfile
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any, Set
from datetime import datetime
from dataclasses import dataclass, field
import logging
import threading
from queue import Queue
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class NucleiResult:
    """Résultat d'un scan Nuclei."""
    template_id: str
    name: str
    severity: str
    url: str
    matched_at: str
    description: str = ""
    extracted: Dict[str, Any] = field(default_factory=dict)
    curl_command: str = ""
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())


class NucleiScanner:
    """
    Scanner Nuclei pour détection de vulns connues.
    
    Fonctionne en parallèle du pipeline IA pour:
    - Détecter les CVEs connues
    - Trouver les misconfigurations
    - Identifier les fuites d'informations
    - Scanner les technologies
    """
    
    def __init__(
        self,
        templates_dir: Optional[Path] = None,
        rate_limit: int = 100,
        concurrency: int = 25,
        timeout: int = 10,
        custom_templates: Optional[Path] = None,
    ):
        """
        Args:
            templates_dir: Dossier des templates (défaut: knowledge/nuclei-templates)
            rate_limit: Requêtes par seconde max
            concurrency: Nombre de scans parallèles
            timeout: Timeout par requête en secondes
            custom_templates: Templates custom additionnels
        """
        # Trouver le dossier templates
        if templates_dir is None:
            base = Path(__file__).parent.parent.parent.parent
            templates_dir = base / "knowledge" / "nuclei-templates"
        
        self.templates_dir = templates_dir
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.timeout = timeout
        self.custom_templates = custom_templates
        
        # Stats
        self.total_scanned = 0
        self.total_findings = 0
        self.findings: List[NucleiResult] = []
        
        # Queue pour le scanning asynchrone
        self._scan_queue: Queue = Queue()
        self._results_queue: Queue = Queue()
        self._scanned_urls: Set[str] = set()
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        
        # Vérifier Nuclei
        self._nuclei_available = self._check_nuclei()
        
        logger.info(f"NucleiScanner initialized - Templates: {self.templates_dir}")
        logger.info(f"Nuclei available: {self._nuclei_available}")
    
    def _check_nuclei(self) -> bool:
        """Vérifie si Nuclei est installé."""
        try:
            result = subprocess.run(
                ["nuclei", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    @property
    def is_available(self) -> bool:
        """Vérifie si le scanner est disponible."""
        return self._nuclei_available and self.templates_dir.exists()
    
    def start_background_scanner(self):
        """Démarre le scanner en background."""
        if self._running:
            return
        
        self._running = True
        self._worker_thread = threading.Thread(target=self._scanner_worker, daemon=True)
        self._worker_thread.start()
        logger.info("Nuclei background scanner started")
    
    def stop_background_scanner(self):
        """Arrête le scanner background."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        logger.info("Nuclei background scanner stopped")
    
    def _scanner_worker(self):
        """Worker thread pour le scanning."""
        while self._running:
            try:
                # Récupérer une URL de la queue (timeout 1s)
                url = self._scan_queue.get(timeout=1)
                
                # Scanner
                results = self._scan_url_sync(url)
                
                # Ajouter les résultats
                for result in results:
                    self.findings.append(result)
                    self.total_findings += 1
                    self._results_queue.put(result)
                
                self.total_scanned += 1
                self._scan_queue.task_done()
                
            except Exception:
                # Queue vide ou timeout
                continue
    
    def queue_url(self, url: str) -> bool:
        """
        Ajoute une URL à la queue de scan.
        
        Args:
            url: URL à scanner
            
        Returns:
            True si ajoutée, False si déjà scannée
        """
        # Normaliser l'URL (sans params pour dédup)
        base_url = url.split('?')[0]
        url_hash = hashlib.md5(base_url.encode()).hexdigest()
        
        if url_hash in self._scanned_urls:
            return False
        
        self._scanned_urls.add(url_hash)
        self._scan_queue.put(url)
        return True
    
    def _scan_url_sync(self, url: str) -> List[NucleiResult]:
        """Scan synchrone d'une URL."""
        if not self.is_available:
            return []
        
        results = []
        
        try:
            # Créer un fichier temporaire pour l'URL
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(url)
                target_file = f.name
            
            # Construire la commande
            cmd = [
                "nuclei",
                "-l", target_file,
                "-t", str(self.templates_dir),
                "-json",
                "-silent",
                "-no-color",
                "-rate-limit", str(self.rate_limit),
                "-c", str(self.concurrency),
                "-timeout", str(self.timeout),
                "-severity", "critical,high,medium,low,info",
                # Exclure les templates trop verbeux
                "-exclude-tags", "dos,fuzzing",
            ]
            
            # Exécuter
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 min max par scan
            )
            
            # Parser les résultats
            if process.stdout:
                for line in process.stdout.strip().split('\n'):
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        result = NucleiResult(
                            template_id=data.get('template-id', 'unknown'),
                            name=data.get('info', {}).get('name', 'Unknown'),
                            severity=data.get('info', {}).get('severity', 'info'),
                            url=data.get('host', url),
                            matched_at=data.get('matched-at', ''),
                            description=data.get('info', {}).get('description', ''),
                            extracted=data.get('extracted-results', {}),
                            curl_command=data.get('curl-command', ''),
                        )
                        results.append(result)
                        logger.info(f"🎯 Nuclei finding: {result.name} ({result.severity}) - {url}")
                    except json.JSONDecodeError:
                        continue
            
            # Cleanup
            Path(target_file).unlink(missing_ok=True)
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Nuclei scan timeout for {url}")
        except Exception as e:
            logger.error(f"Nuclei scan error for {url}: {e}")
        
        return results
    
    async def scan_url(self, url: str, tags: Optional[List[str]] = None) -> List[NucleiResult]:
        """
        Scan asynchrone d'une URL.
        
        Args:
            url: URL à scanner
            tags: Tags Nuclei optionnels (sqli, xss, etc.)
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scan_url_sync, url)
    
    def scan_url_quick(
        self,
        url: str,
        severity: str = "critical,high",
        tags: Optional[List[str]] = None
    ) -> List[NucleiResult]:
        """
        Scan rapide pour vulns critiques uniquement.
        
        Args:
            url: URL à scanner
            severity: Sévérités à scanner (défaut: critical,high)
            tags: Tags spécifiques
        """
        if not self.is_available:
            return []
        
        results = []
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(url)
                target_file = f.name
            
            cmd = [
                "nuclei",
                "-l", target_file,
                "-t", str(self.templates_dir),
                "-json",
                "-silent",
                "-no-color",
                "-rate-limit", "50",
                "-c", "10",
                "-timeout", "5",
                "-severity", severity,
            ]
            
            if tags:
                cmd.extend(["-tags", ",".join(tags)])
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if process.stdout:
                for line in process.stdout.strip().split('\n'):
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        result = NucleiResult(
                            template_id=data.get('template-id', 'unknown'),
                            name=data.get('info', {}).get('name', 'Unknown'),
                            severity=data.get('info', {}).get('severity', 'info'),
                            url=data.get('host', url),
                            matched_at=data.get('matched-at', ''),
                            description=data.get('info', {}).get('description', ''),
                        )
                        results.append(result)
                    except json.JSONDecodeError:
                        continue
            
            Path(target_file).unlink(missing_ok=True)
            
        except Exception as e:
            logger.error(f"Quick scan error: {e}")
        
        return results
    
    def get_findings(self, severity: Optional[str] = None) -> List[NucleiResult]:
        """Récupère les findings (optionnellement filtrés par sévérité)."""
        if severity:
            return [f for f in self.findings if f.severity.lower() == severity.lower()]
        return self.findings
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du scanner."""
        severity_counts = {}
        for finding in self.findings:
            sev = finding.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "available": self.is_available,
            "templates_dir": str(self.templates_dir),
            "total_scanned": self.total_scanned,
            "total_findings": self.total_findings,
            "findings_by_severity": severity_counts,
            "queue_size": self._scan_queue.qsize(),
            "running": self._running,
        }


# Singleton
_scanner_instance: Optional[NucleiScanner] = None


def get_nuclei_scanner() -> NucleiScanner:
    """Récupère l'instance singleton du scanner."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = NucleiScanner()
    return _scanner_instance

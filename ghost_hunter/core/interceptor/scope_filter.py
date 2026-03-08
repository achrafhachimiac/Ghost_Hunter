"""
Ghost-Hunter Scope Filter
=========================
Filtre les requêtes selon le scope défini.
"""

import re
from typing import List, Optional
from fnmatch import fnmatch
import logging

from ghost_hunter.core.contracts import InterceptedRequest, FilteredRequest

logger = logging.getLogger(__name__)


class ScopeFilter:
    """Filtre les requêtes selon le scope du bug bounty."""
    
    # Extensions statiques à ignorer par défaut
    STATIC_EXTENSIONS = {
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.mp4',
        '.mp3', '.pdf', '.zip', '.tar', '.gz'
    }
    
    def __init__(
        self,
        in_scope: List[str],
        out_of_scope: Optional[List[str]] = None,
        ignore_static: bool = True,
        ignore_extensions: Optional[List[str]] = None
    ):
        """
        Args:
            in_scope: Patterns des domaines/paths in-scope (wildcards autorisés)
            out_of_scope: Patterns des domaines/paths out-of-scope
            ignore_static: Ignorer les fichiers statiques
            ignore_extensions: Extensions à ignorer
        """
        self.in_scope = in_scope or []
        self.out_of_scope = out_of_scope or []
        self.ignore_static = ignore_static
        self.ignore_extensions = set(ignore_extensions or [])
        
        # Compiler les patterns pour performance
        self._in_scope_patterns = [self._compile_pattern(p) for p in self.in_scope]
        self._out_scope_patterns = [self._compile_pattern(p) for p in self.out_of_scope]
        
        logger.info(f"ScopeFilter: {len(self.in_scope)} in-scope, {len(self.out_of_scope)} out-of-scope")
    
    def _compile_pattern(self, pattern: str) -> re.Pattern:
        """Compile un pattern wildcard en regex."""
        # Convertir les wildcards en regex
        regex = pattern.replace('.', r'\.').replace('*', '.*')
        return re.compile(f'^{regex}$', re.IGNORECASE)
    
    def _is_static(self, path: str) -> bool:
        """Vérifie si le path est un fichier statique."""
        if not self.ignore_static:
            return False
        
        path_lower = path.lower().split('?')[0]  # Enlever les query params
        
        # Vérifier l'extension
        for ext in self.STATIC_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        
        # Vérifier les extensions custom
        for ext in self.ignore_extensions:
            if path_lower.endswith(ext):
                return True
        
        return False
    
    def _matches_patterns(self, value: str, patterns: List[re.Pattern]) -> bool:
        """Vérifie si une valeur match un des patterns."""
        for pattern in patterns:
            if pattern.match(value):
                return True
        return False
    
    def _strip_port(self, host: str) -> str:
        """Remove port from host if present (e.g., example.com:443 -> example.com)."""
        if ':' in host:
            return host.rsplit(':', 1)[0]
        return host
    
    def _is_api_endpoint(self, host: str, path: str) -> bool:
        """Détecte si c'est un endpoint API."""
        path_lower = path.lower()
        host_lower = host.lower()
        
        # Patterns API communs
        if host_lower.startswith('api.') or host_lower.startswith('api-'):
            return True
        if '/api/' in path_lower or path_lower.startswith('/api'):
            return True
        if '/graphql' in path_lower or '/gql' in path_lower:
            return True
        if '/v1/' in path_lower or '/v2/' in path_lower or '/v3/' in path_lower:
            return True
        if path_lower.endswith('.json') and '/api' in path_lower:
            return True
        
        return False
    
    def _get_matching_pattern(self, value: str, patterns: List[re.Pattern], original_patterns: List[str]) -> Optional[str]:
        """Retourne le pattern original qui match."""
        for i, pattern in enumerate(patterns):
            if pattern.match(value):
                return original_patterns[i]
        return None
    
    def filter(self, request: InterceptedRequest) -> FilteredRequest:
        """
        Filtre une requête selon le scope.
        
        Args:
            request: Requête interceptée
            
        Returns:
            FilteredRequest avec le statut in_scope
        """
        # Strip port from host for matching (e.g., example.com:443 -> example.com)
        host = self._strip_port(request.host)
        path = request.path
        full_url = f"{host}{path}"
        
        # Détecter is_api
        is_api = self._is_api_endpoint(host, path)
        
        # Vérifier si statique
        is_static = self._is_static(path)
        if is_static:
            return FilteredRequest(
                request=request,
                in_scope=False,
                scope_match="",
                domain=host,
                is_api=is_api,
                is_static=True,
                filter_reason="static_file"
            )
        
        # Vérifier out-of-scope d'abord (prioritaire)
        out_match = self._get_matching_pattern(host, self._out_scope_patterns, self.out_of_scope)
        if out_match:
            return FilteredRequest(
                request=request,
                in_scope=False,
                scope_match=f"OUT:{out_match}",
                domain=host,
                is_api=is_api,
                is_static=False,
                filter_reason="out_of_scope"
            )
        
        out_match = self._get_matching_pattern(full_url, self._out_scope_patterns, self.out_of_scope)
        if out_match:
            return FilteredRequest(
                request=request,
                in_scope=False,
                scope_match=f"OUT:{out_match}",
                domain=host,
                is_api=is_api,
                is_static=False,
                filter_reason="out_of_scope"
            )
        
        # Vérifier in-scope
        in_match = self._get_matching_pattern(host, self._in_scope_patterns, self.in_scope)
        if in_match:
            return FilteredRequest(
                request=request,
                in_scope=True,
                scope_match=in_match,
                domain=host,
                is_api=is_api,
                is_static=False,
                filter_reason=None
            )
        
        in_match = self._get_matching_pattern(full_url, self._in_scope_patterns, self.in_scope)
        if in_match:
            return FilteredRequest(
                request=request,
                in_scope=True,
                scope_match=in_match,
                domain=host,
                is_api=is_api,
                is_static=False,
                filter_reason=None
            )
        
        # Par défaut, pas in-scope si pas explicitement inclus
        return FilteredRequest(
            request=request,
            in_scope=False,
            scope_match="NO_MATCH",
            domain=host,
            is_api=is_api,
            is_static=False,
            filter_reason="not_in_scope"
        )
    
    def is_in_scope(self, host: str, path: str = "/") -> bool:
        """Raccourci pour vérifier si un host/path est in-scope."""
        # Strip port from host for matching
        host = self._strip_port(host)
        # Créer une requête fictive
        from ghost_hunter.core.contracts import InterceptedRequest
        fake_request = InterceptedRequest(
            id="check",
            method="GET",
            url=f"https://{host}{path}",
            host=host,
            path=path,
            headers={},
            query_params={},
            body=None,
            timestamp=0
        )
        result = self.filter(fake_request)
        return result.in_scope

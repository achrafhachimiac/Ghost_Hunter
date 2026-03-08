"""
Query Parameter Injector - Injects payloads into URL query parameters.

Simple and focused: handles only query string injection.
"""

import logging
from typing import Dict, Tuple, Optional
from urllib.parse import urlencode

logger = logging.getLogger(__name__)


class QueryInjector:
    """
    Injects payloads into URL query parameters.
    
    Usage:
        injector = QueryInjector()
        new_url, success = injector.inject(url, query_params, injection_point, payload)
    """
    
    @staticmethod
    def inject(
        url: str,
        query_params: Optional[Dict[str, str]],
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        Inject payload into query parameter.
        
        Args:
            url: Original URL (may contain query string)
            query_params: Dict of query parameters from original request
            injection_point: Parameter name to inject into
            payload: Payload to inject
            
        Returns:
            Tuple of (new_url, success)
            - success is True if injection was made
        """
        if not query_params or injection_point not in query_params:
            return url, False
        
        # Copy params and inject
        params = dict(query_params)
        params[injection_point] = payload
        
        # Reconstruct URL
        base_url = url.split('?')[0]
        new_url = f"{base_url}?{urlencode(params)}"
        
        logger.info(f"🔧 [INJECT] ✅ Injected query param '{injection_point}'")
        return new_url, True
    
    @staticmethod
    def can_inject(query_params: Optional[Dict[str, str]], injection_point: str) -> bool:
        """Check if injection is possible for this injection point."""
        return bool(query_params and injection_point in query_params)

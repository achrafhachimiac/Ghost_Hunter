"""
Header Injector - Injects payloads into HTTP headers and cookies.

Handles:
- Standard header injection
- Cookie value injection within Cookie header
"""

import re
import logging
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)


class HeaderInjector:
    """
    Injects payloads into HTTP headers.
    
    Usage:
        injector = HeaderInjector()
        new_headers, success = injector.inject(headers, injection_point, payload)
    """
    
    @staticmethod
    def inject(
        headers: Dict[str, str],
        injection_point: str,
        payload: str,
    ) -> Tuple[Dict[str, str], bool]:
        """
        Inject payload into header value.
        
        Args:
            headers: Dict of headers (will be modified)
            injection_point: Header name to inject into (case-insensitive)
            payload: Payload to inject
            
        Returns:
            Tuple of (headers, success)
        """
        # Find header case-insensitively
        for header_name in headers:
            if header_name.lower() == injection_point.lower():
                headers[header_name] = payload
                logger.info(f"🔧 [INJECT] ✅ Injected header '{header_name}'")
                return headers, True
        
        return headers, False
    
    @staticmethod
    def has_header(headers: Dict[str, str], name: str) -> bool:
        """Check if header exists (case-insensitive)."""
        return any(h.lower() == name.lower() for h in headers)
    
    @staticmethod
    def get_header(headers: Dict[str, str], name: str) -> Optional[str]:
        """Get header value (case-insensitive)."""
        for h, v in headers.items():
            if h.lower() == name.lower():
                return v
        return None
    
    @staticmethod
    def set_header(headers: Dict[str, str], name: str, value: str) -> Dict[str, str]:
        """Set header, removing any existing version (case-insensitive)."""
        headers = {k: v for k, v in headers.items() if k.lower() != name.lower()}
        headers[name] = value
        return headers


class CookieInjector:
    """
    Injects payloads into cookie values within the Cookie header.
    
    Usage:
        injector = CookieInjector()
        new_headers, success = injector.inject(headers, cookies_dict, injection_point, payload)
    """
    
    @classmethod
    def inject(
        cls,
        headers: Dict[str, str],
        cookies_dict: Optional[Dict[str, str]],
        injection_point: str,
        payload: str,
    ) -> Tuple[Dict[str, str], bool]:
        """
        Inject payload into specific cookie value.
        
        Args:
            headers: Request headers
            cookies_dict: Parsed cookies dict from original request
            injection_point: Cookie name to inject into
            payload: Payload to inject
            
        Returns:
            Tuple of (headers, success)
        """
        if not cookies_dict or injection_point not in cookies_dict:
            return headers, False
        
        # Find Cookie header
        cookie_header_key = None
        for h in headers:
            if h.lower() == 'cookie':
                cookie_header_key = h
                break
        
        if cookie_header_key:
            # Modify existing Cookie header
            cookie_str = headers[cookie_header_key]
            new_cookie_str, success = cls._replace_cookie_value(
                cookie_str, injection_point, payload
            )
            if success:
                headers[cookie_header_key] = new_cookie_str
                return headers, True
            else:
                logger.warning(f"⚠️ [INJECT] Cookie '{injection_point}' not found in Cookie header")
                return headers, False
        else:
            # No Cookie header - build one with injected value
            cookies_dict = dict(cookies_dict)
            cookies_dict[injection_point] = payload
            headers['Cookie'] = '; '.join(f'{k}={v}' for k, v in cookies_dict.items())
            logger.info(f"🔧 [INJECT] ✅ Built Cookie header with injected '{injection_point}'")
            return headers, True
    
    @staticmethod
    def _replace_cookie_value(
        cookie_str: str,
        cookie_name: str,
        new_value: str,
    ) -> Tuple[str, bool]:
        """
        Replace a specific cookie value in cookie string.
        
        Format: "name1=value1; name2=value2; ..."
        """
        pattern = rf'({re.escape(cookie_name)}=)([^;]*)'
        if not re.search(pattern, cookie_str):
            return cookie_str, False
        
        # Escape backslashes in payload to prevent regex backreference issues
        safe_payload = new_value.replace('\\', '\\\\')
        new_cookie_str = re.sub(pattern, rf'\g<1>{safe_payload}', cookie_str)
        logger.info(f"🔧 [INJECT] ✅ Replaced cookie '{cookie_name}' value")
        return new_cookie_str, True
    
    @staticmethod
    def build_cookie_header(cookies_dict: Dict[str, str]) -> str:
        """Build Cookie header string from dict."""
        return '; '.join(f'{k}={v}' for k, v in cookies_dict.items())

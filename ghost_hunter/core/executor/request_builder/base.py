"""
Request Builder Base - Orchestrates request building with payload injection.

Coordinates all injectors and handles:
- Cookie processing
- User-Agent strategy
- Header cleanup
"""

import logging
from typing import Tuple, Optional, Dict, Any

from .query_injector import QueryInjector
from .body_injector import BodyInjector
from .header_injector import HeaderInjector, CookieInjector
from .path_injector import PathInjector

logger = logging.getLogger(__name__)


class RequestBuilder:
    """
    Builds HTTP requests with injected payloads.
    
    Coordinates multiple injectors and handles:
    - Cookie processing (dict priority over header)
    - User-Agent strategy (preserve for auth, rotate otherwise)
    - Header cleanup (Content-Length removal, deduplication)
    
    Usage:
        builder = RequestBuilder(ua_rotator, fallback_ua, rotate_ua)
        url, headers, body, success = builder.build(original_req, payload, injection_point)
    """
    
    def __init__(
        self,
        ua_rotator: Any = None,
        fallback_user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        rotate_ua_for_attacks: bool = False,
    ):
        """
        Initialize RequestBuilder.
        
        Args:
            ua_rotator: UserAgentRotator instance for UA rotation
            fallback_user_agent: Default UA when none present
            rotate_ua_for_attacks: Whether to rotate UA for non-auth requests
        """
        self._ua_rotator = ua_rotator
        self._fallback_user_agent = fallback_user_agent
        self.rotate_ua_for_attacks = rotate_ua_for_attacks
    
    def build(
        self,
        original_req: Any,
        payload: str,
        injection_point: str,
    ) -> Tuple[str, Dict[str, str], Optional[str], bool]:
        """
        Build request with payload injected.
        
        Args:
            original_req: Original intercepted request
            payload: Payload to inject
            injection_point: Where to inject (param name, header, path template, etc.)
            
        Returns:
            Tuple of (url, headers, body, injection_success)
        """
        url = original_req.url
        headers = dict(original_req.headers)
        body = original_req.body
        
        # Debug logging
        print(f"🔧 [BUILD_REQUEST] === BUILDING REQUEST ===")
        print(f"🔧 [BUILD_REQUEST] injection_point: '{injection_point}'")
        print(f"🔧 [BUILD_REQUEST] payload: '{payload}'")
        print(f"🔧 [BUILD_REQUEST] original URL: {url}")
        print(f"🔧 [BUILD_REQUEST] original path: {original_req.path}")
        
        # Process cookies
        headers = self._ensure_cookies(headers, original_req)
        
        # Process User-Agent
        headers = self._ensure_user_agent(headers, url)
        
        # Try injection in order of specificity
        injection_success = False
        
        # 1. Query params
        if not injection_success:
            query_params = getattr(original_req, 'query_params', None)
            if QueryInjector.can_inject(query_params, injection_point):
                url, injection_success = QueryInjector.inject(
                    url, query_params, injection_point, payload
                )
        
        # 2. JSON body
        if not injection_success and body:
            body_json = getattr(original_req, 'body_json', None)
            if body_json:
                body, injection_success = BodyInjector.inject_json(
                    body, injection_point, payload
                )
        
        # 3. Form body (if not JSON)
        if not injection_success and body:
            body_json = getattr(original_req, 'body_json', None)
            if not body_json:
                body, injection_success = BodyInjector.inject_form(
                    body, injection_point, payload
                )
        
        # 4. Headers
        if not injection_success:
            if injection_point.lower() in [h.lower() for h in headers]:
                headers, injection_success = HeaderInjector.inject(
                    headers, injection_point, payload
                )
        
        # 5. Cookies
        if not injection_success:
            cookies_dict = getattr(original_req, 'cookies', None)
            if cookies_dict and injection_point in cookies_dict:
                headers, injection_success = CookieInjector.inject(
                    headers, cookies_dict, injection_point, payload
                )
        
        # 6. Path
        if not injection_success:
            url, injection_success = PathInjector.inject(
                url, original_req, injection_point, payload
            )
        
        # Log if no injection made
        if not injection_success:
            logger.warning(f"⚠️ [INJECT] No injection made for '{injection_point}' - field not found in request")
        
        # Cleanup headers
        headers = self._cleanup_headers(headers)
        
        logger.info(f"🔧 [HTTP_RUNNER] Final headers after cleanup: {list(headers.keys())}")
        logger.info(f"🔧 [HTTP_RUNNER] Injection success: {injection_success}")
        
        return url, headers, body, injection_success
    
    def _ensure_cookies(
        self,
        headers: Dict[str, str],
        original_req: Any,
    ) -> Dict[str, str]:
        """
        Ensure cookies are properly set in headers.
        
        Priority:
        1. Build from cookies dict (most reliable)
        2. Use existing header if dict empty
        """
        cookies_dict = getattr(original_req, 'cookies', {}) or {}
        existing_cookie_header = HeaderInjector.get_header(headers, 'cookie') or ''
        
        logger.info(f"🍪 [HTTP_RUNNER] === COOKIE PROCESSING ===")
        logger.info(f"🍪 [HTTP_RUNNER] cookies_dict ({len(cookies_dict)} entries)")
        logger.info(f"🍪 [HTTP_RUNNER] existing_cookie_header: {len(existing_cookie_header)} chars")
        
        if cookies_dict:
            # Build from dict - most reliable source
            cookie_str = CookieInjector.build_cookie_header(cookies_dict)
            headers = HeaderInjector.set_header(headers, 'Cookie', cookie_str)
            logger.info(f"🍪 [HTTP_RUNNER] ✓ Built Cookie header from dict: {len(cookies_dict)} cookies")
        elif existing_cookie_header:
            # Normalize and use existing header
            if ', ' in existing_cookie_header and '; ' not in existing_cookie_header:
                normalized = existing_cookie_header.replace(', ', '; ')
                headers = HeaderInjector.set_header(headers, 'Cookie', normalized)
                logger.info(f"🍪 [HTTP_RUNNER] ✓ Normalized cookie separator (, → ;)")
            else:
                headers = HeaderInjector.set_header(headers, 'Cookie', existing_cookie_header)
                logger.info(f"🍪 [HTTP_RUNNER] ✓ Using existing cookie header")
        else:
            logger.warning(f"🍪 [HTTP_RUNNER] ⚠️ NO COOKIES AVAILABLE")
        
        return headers
    
    def _ensure_user_agent(
        self,
        headers: Dict[str, str],
        url: str,
    ) -> Dict[str, str]:
        """
        Ensure User-Agent is properly set.
        
        Strategy:
        - Auth requests → preserve original UA (session integrity)
        - Non-auth requests → rotate UA if enabled
        """
        has_auth = (
            HeaderInjector.has_header(headers, 'cookie') or
            HeaderInjector.has_header(headers, 'authorization')
        )
        
        if has_auth:
            # Preserve session - don't rotate
            if not HeaderInjector.has_header(headers, 'user-agent'):
                headers['User-Agent'] = self._fallback_user_agent
        else:
            # Can rotate for non-auth requests
            if self.rotate_ua_for_attacks and self._ua_rotator:
                headers = {k: v for k, v in headers.items() if k.lower() != 'user-agent'}
                host = url.split('/')[2] if '//' in url else ''
                headers['User-Agent'] = self._ua_rotator.get_profile(host).user_agent
            elif not HeaderInjector.has_header(headers, 'user-agent'):
                headers['User-Agent'] = self._fallback_user_agent
        
        return headers
    
    def _cleanup_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Clean up headers before sending.
        
        - Remove Content-Length (httpx recalculates)
        - Deduplicate headers (case-insensitive)
        """
        # Remove Content-Length
        headers = {k: v for k, v in headers.items() if k.lower() != 'content-length'}
        
        # Deduplicate (keep last occurrence)
        seen = {}
        for k, v in headers.items():
            seen[k.lower()] = (k, v)
        headers = {k: v for k, v in seen.values()}
        
        return headers

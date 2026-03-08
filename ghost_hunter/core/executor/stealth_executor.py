"""
Stealth Executor - Puppeteer-based HTTP execution for anti-bot bypass.

Uses stealth browser to bypass:
- Friendly Captcha
- Cloudflare detection
- JavaScript-heavy pages
- Bot detection mechanisms

Extracted from http_runner.py Phase 8 refactoring.
"""

import re
import logging
from typing import Optional, TYPE_CHECKING

from ..contracts import (
    Finding,
    FindingSeverity,
    FindingStatus,
    PayloadVariant,
)
from .tool_wrapper import ExecutionContext
from .constants import ERROR_PATTERNS, _safe_get_payload_value

if TYPE_CHECKING:
    from ..stealth.browser import StealthResponse

logger = logging.getLogger(__name__)


class StealthExecutor:
    """
    Executes HTTP requests using Puppeteer stealth browser.
    
    Handles:
    - Anti-bot bypass (Cloudflare, Akamai, etc.)
    - Captcha solving (Friendly Captcha)
    - Cookie merging from headers and dict
    - Full response analysis
    """
    
    def __init__(
        self,
        payload_encoder,
        request_builder,
    ):
        """
        Initialize stealth executor.
        
        Args:
            payload_encoder: PayloadEncoder instance for encoding payloads
            request_builder: RequestBuilder instance for building requests
        """
        self._payload_encoder = payload_encoder
        self._request_builder = request_builder
    
    async def test_payload(
        self,
        original_req,
        vuln_class: str,
        payload: PayloadVariant,
        injection_point: str,
        context: ExecutionContext,
    ) -> tuple[Optional[Finding], dict]:
        """
        Test payload using stealth browser to bypass anti-bot protections.
        
        Uses Puppeteer with stealth plugin to:
        - Bypass Friendly Captcha
        - Evade Cloudflare detection
        - Handle JavaScript-heavy pages
        
        Args:
            original_req: Original intercepted request
            vuln_class: Vulnerability class (XSS, SQLI, IDOR, etc.)
            payload: PayloadVariant to test
            injection_point: Where to inject the payload
            context: Execution context
            
        Returns:
            tuple: (Finding or None, detail dict)
        """
        # Import here to avoid circular imports
        from ..stealth.browser import get_stealth_browser
        
        detail = {
            "payload": _safe_get_payload_value(payload),
            "injection_point": injection_point,
            "encoding": payload.encoding if payload and hasattr(payload, 'encoding') else 'none',
            "request": None,
            "response": None,
            "response_time_ms": 0,
            "finding": None,
            "error": None,
            "stealth_mode": True,
            "captcha_solved": False,
        }
        
        try:
            # Encode the payload if necessary
            encoded_payload = self._payload_encoder.encode(payload)
            
            # Build the modified request
            url, headers, body, injection_success = self._request_builder.build(
                original_req,
                encoded_payload,
                injection_point,
            )
            
            # Skip if injection failed
            if not injection_success:
                logger.warning(f"⏭️ [STEALTH] SKIPPING - injection point '{injection_point}' not found")
                detail["error"] = f"Injection point '{injection_point}' not found in request"
                detail["skipped"] = True
                return None, detail
            
            logger.info(f"🥷 [STEALTH] Testing {original_req.method} {url[:60]}...")
            
            # Store request details with masked sensitive values
            masked_headers = self._mask_sensitive_headers(headers)
            
            detail["request"] = {
                "method": original_req.method,
                "url": url,
                "headers": masked_headers,
                "headers_count": len(headers),
                "has_cookie": any(k.lower() == 'cookie' for k in headers),
                "has_auth": any(k.lower() == 'authorization' for k in headers),
                "body_preview": (body[:500] + "...") if body and len(body) > 500 else body,
            }
            
            # Get stealth browser
            browser = get_stealth_browser()
            
            # Extract and merge cookies
            cookies = self._extract_cookies(headers, original_req)
            
            # Content type
            content_type = headers.get('Content-Type') or headers.get('content-type') or 'application/json'
            
            # Execute with stealth browser
            async with browser:
                response = await browser.execute_request(
                    method=original_req.method,
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    body=body,
                    content_type=content_type,
                )
            
            detail["response_time_ms"] = response.execution_time_ms
            detail["captcha_solved"] = response.captcha_solved
            
            if response.captcha_solved:
                logger.info(f"🔓 [STEALTH] Captcha bypassed successfully!")
            
            if not response.success:
                detail["error"] = response.error
                logger.warning(f"🥷 [STEALTH] Request failed: {response.error}")
                return None, detail
            
            # Store response details - FULL body for analysis
            detail["response"] = {
                "status_code": response.status_code,
                "headers": response.headers,
                "body_preview": response.body[:2000] if len(response.body) > 2000 else response.body,
                "body_full": response.body,
                "body_length": len(response.body),
            }
            
            # Analyze the response
            finding = self.analyze_response(
                response,
                vuln_class,
                payload,
                injection_point,
                url,
            )
            
            if finding:
                detail["finding"] = {
                    "vuln_type": finding.vuln_type,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence,
                    "analysis": finding.ai_analysis,
                }
            
            return finding, detail
            
        except Exception as e:
            detail["error"] = str(e)
            logger.error(f"🥷 [STEALTH] Test failed: {e}")
            return None, detail
    
    def analyze_response(
        self,
        response: 'StealthResponse',
        vuln_class: str,
        payload: PayloadVariant,
        injection_point: str,
        url: str,
    ) -> Optional[Finding]:
        """
        Analyze stealth browser response for vulnerabilities.
        
        Args:
            response: StealthResponse from browser
            vuln_class: Vulnerability class being tested
            payload: The payload that was used
            injection_point: Where payload was injected
            url: The full URL tested
            
        Returns:
            Finding if vulnerability detected, None otherwise
        """
        vuln_class_upper = vuln_class.upper()
        body = response.body or ""
        status = response.status_code
        payload_value = _safe_get_payload_value(payload)
        
        # Check for error patterns indicating vulnerability
        patterns = ERROR_PATTERNS.get(vuln_class.lower(), [])
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return Finding(
                    endpoint=url,
                    method="POST",  # Stealth typically used for POST
                    vuln_type=vuln_class,
                    vuln_subtype="error-based",
                    severity=FindingSeverity.HIGH,
                    status=FindingStatus.NEW,
                    confidence=75,
                    payload_successful=payload_value,
                    ai_analysis=f"Stealth browser detected {vuln_class} pattern in response",
                    tool_used="stealth_browser",
                )
        
        # Check for payload reflection (XSS)
        if vuln_class_upper == "XSS" and payload_value and payload_value in body:
            return Finding(
                endpoint=url,
                method="POST",
                vuln_type="XSS",
                vuln_subtype="reflected",
                severity=FindingSeverity.MEDIUM,
                status=FindingStatus.NEW,
                confidence=70,
                payload_successful=payload_value,
                ai_analysis="Payload reflected in response body (stealth mode)",
                tool_used="stealth_browser",
            )
        
        # IDOR detection: different response for different IDs
        if vuln_class_upper == "IDOR":
            if status == 200 and len(body) > 100:
                return Finding(
                    endpoint=url,
                    method="POST",
                    vuln_type="IDOR",
                    vuln_subtype="potential",
                    severity=FindingSeverity.MEDIUM,
                    status=FindingStatus.NEW,
                    confidence=50,
                    payload_successful=payload_value,
                    ai_analysis="Different response for modified ID - potential IDOR (stealth mode)",
                    tool_used="stealth_browser",
                )
        
        return None
    
    def _mask_sensitive_headers(self, headers: dict) -> dict:
        """
        Mask sensitive header values for logging.
        
        Shows that headers exist but hides actual values.
        """
        masked = {}
        for k, v in headers.items():
            if k.lower() == 'cookie':
                cookie_count = v.count(';') + 1 if v else 0
                masked[k] = f"[{cookie_count} cookies - PRÉSENT MAIS MASQUÉ]"
            elif k.lower() == 'authorization':
                masked[k] = "[PRÉSENT MAIS MASQUÉ]"
            else:
                masked[k] = v
        return masked
    
    def _extract_cookies(self, headers: dict, original_req) -> dict:
        """
        Extract and merge cookies from headers and original request.
        
        Combines cookies from:
        1. Cookie header string
        2. original_req.cookies dict
        
        Returns:
            dict: Merged cookies
        """
        cookies = {}
        
        # Extract from Cookie header
        cookie_header = headers.get('Cookie') or headers.get('cookie')
        if cookie_header:
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    cookies[key.strip()] = value.strip()
        
        # Merge with original cookies (they take priority)
        if hasattr(original_req, 'cookies') and original_req.cookies:
            cookies.update(original_req.cookies)
        
        return cookies

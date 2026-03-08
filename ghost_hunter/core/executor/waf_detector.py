"""
WAF Detector - Extracted from http_runner.py for maintainability.

Detects WAF (Web Application Firewall) block responses based on:
- HTTP status codes
- Response headers
- Response body content
"""

import logging
from typing import Tuple, Optional, Dict, Any

logger = logging.getLogger(__name__)


class WAFDetector:
    """
    Detects WAF block responses from various providers.
    
    Supported WAF providers:
    - Cloudflare (Managed Challenge, WAF Block)
    - AWS WAF
    - Akamai WAF
    - Imperva/Incapsula
    - F5 ASM
    - Generic WAF signatures
    """
    
    @classmethod
    def is_blocked(cls, response) -> Tuple[bool, str]:
        """
        Detect if a response is a WAF block page.
        
        Args:
            response: httpx.Response object (or any object with status_code, 
                     headers, and text attributes)
            
        Returns:
            tuple: (is_blocked: bool, waf_provider: str)
        """
        try:
            content = (response.text or "").lower()
            headers = {k.lower(): v for k, v in response.headers.items()}
            status_code = response.status_code
        except Exception as e:
            logger.debug(f"WAF detection error: {e}")
            return False, ""
        
        # Cloudflare detection
        blocked, provider = cls._detect_cloudflare(status_code, headers, content)
        if blocked:
            return blocked, provider
        
        # AWS WAF detection
        blocked, provider = cls._detect_aws_waf(status_code, headers, content)
        if blocked:
            return blocked, provider
        
        # Akamai detection
        blocked, provider = cls._detect_akamai(status_code, headers, content)
        if blocked:
            return blocked, provider
        
        # Imperva/Incapsula detection
        blocked, provider = cls._detect_imperva(status_code, headers, content)
        if blocked:
            return blocked, provider
        
        # F5 ASM detection
        blocked, provider = cls._detect_f5(content)
        if blocked:
            return blocked, provider
        
        # Generic WAF detection
        blocked, provider = cls._detect_generic_waf(status_code, headers)
        if blocked:
            return blocked, provider
        
        return False, ""
    
    @staticmethod
    def _detect_cloudflare(status_code: int, headers: Dict, content: str) -> Tuple[bool, str]:
        """Detect Cloudflare WAF/Challenge pages."""
        if status_code != 403:
            return False, ""
        
        has_cf_headers = "cf-ray" in headers or "cf-request-id" in headers
        if not has_cf_headers:
            return False, ""
        
        if "challenge-platform" in content or "just a moment" in content:
            return True, "Cloudflare Managed Challenge"
        
        if "attention required" in content:
            return True, "Cloudflare WAF Block"
        
        # Generic Cloudflare block
        if "cloudflare" in content:
            return True, "Cloudflare WAF"
        
        return False, ""
    
    @staticmethod
    def _detect_aws_waf(status_code: int, headers: Dict, content: str) -> Tuple[bool, str]:
        """Detect AWS WAF block pages."""
        if status_code != 403:
            return False, ""
        
        if "x-amzn-requestid" in headers:
            return True, "AWS WAF"
        
        if "<code>accessdenied</code>" in content:
            return True, "AWS WAF"
        
        return False, ""
    
    @staticmethod
    def _detect_akamai(status_code: int, headers: Dict, content: str) -> Tuple[bool, str]:
        """Detect Akamai WAF block pages."""
        if status_code != 403:
            return False, ""
        
        # Check headers for Akamai signatures
        headers_str = str(headers).lower()
        if "akamai" in headers_str:
            return True, "Akamai WAF"
        
        # Check content for Akamai signatures
        if "ak_bmsc" in content:
            return True, "Akamai Bot Manager"
        
        if "access denied" in content and any(k for k in headers if "akamai" in k.lower()):
            return True, "Akamai WAF"
        
        return False, ""
    
    @staticmethod
    def _detect_imperva(status_code: int, headers: Dict, content: str) -> Tuple[bool, str]:
        """Detect Imperva/Incapsula WAF block pages."""
        if status_code != 403:
            return False, ""
        
        if "incapsula" in content:
            return True, "Imperva Incapsula"
        
        if "x-iinfo" in headers:
            return True, "Imperva Incapsula"
        
        if "visitorid" in headers and "incap" in str(headers).lower():
            return True, "Imperva Incapsula"
        
        return False, ""
    
    @staticmethod
    def _detect_f5(content: str) -> Tuple[bool, str]:
        """Detect F5 ASM WAF block pages."""
        if "the requested url was rejected" in content:
            return True, "F5 ASM"
        
        if "support id" in content and "please consult with your administrator" in content:
            return True, "F5 ASM"
        
        return False, ""
    
    @staticmethod
    def _detect_generic_waf(status_code: int, headers: Dict) -> Tuple[bool, str]:
        """Detect generic WAF signatures."""
        if status_code != 403:
            return False, ""
        
        waf_headers = ["x-waf-status", "x-protected-by", "x-firewall", "x-sucuri-id"]
        if any(h in headers for h in waf_headers):
            return True, "Unknown WAF"
        
        return False, ""
    
    @classmethod
    def get_waf_provider(cls, response) -> Optional[str]:
        """
        Get the WAF provider name if blocked, None otherwise.
        
        Convenience method that returns just the provider name.
        """
        is_blocked, provider = cls.is_blocked(response)
        return provider if is_blocked else None

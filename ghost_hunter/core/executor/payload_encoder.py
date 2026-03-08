"""
Payload Encoder - Extracted from http_runner.py for maintainability.

Handles encoding of payloads for different injection scenarios:
- URL encoding (single and double)
- HTML entity encoding
- Unicode escape encoding
- Passthrough (no encoding)
"""

from urllib.parse import quote
from typing import Union, Optional
import logging

logger = logging.getLogger(__name__)


class PayloadEncoder:
    """
    Encodes payloads for different injection scenarios.
    
    Supported encodings:
    - none: No encoding (passthrough)
    - url: URL percent encoding
    - double_url: Double URL encoding
    - html: HTML entity encoding
    - unicode: Unicode escape sequences (\\uXXXX)
    """
    
    SUPPORTED_ENCODINGS = frozenset(['none', 'url', 'double_url', 'html', 'unicode'])
    
    @classmethod
    def encode(cls, payload, encoding: Optional[str] = None) -> str:
        """
        Encode a payload according to the specified encoding type.
        
        Args:
            payload: The payload to encode. Can be:
                - None (returns empty string)
                - str (uses specified encoding)
                - dict with 'payload' and 'encoding' keys
                - PayloadVariant object with .payload and .encoding attributes
                - Any other type (converted to string)
            encoding: Override encoding type. If None, extracted from payload.
            
        Returns:
            str: The encoded payload string
        """
        # Extract value and encoding from various payload types
        value, detected_encoding = cls._extract_payload_info(payload)
        
        # Use provided encoding or detected one
        final_encoding = encoding or detected_encoding or 'none'
        
        # Normalize empty encoding to 'none'
        if not final_encoding:
            final_encoding = 'none'
        
        # DEBUG: Log encoding operation
        logger.debug(f"🔐 [ENCODER] Input: {repr(value)[:100]}, encoding: {final_encoding}")
        
        # Apply encoding
        result = cls._apply_encoding(value, final_encoding)
        
        # DEBUG: Log result
        logger.debug(f"🔐 [ENCODER] Output: {repr(result)[:100]}")
        
        return result
    
    @classmethod
    def _extract_payload_info(cls, payload) -> tuple[str, str]:
        """
        Extract payload value and encoding from various payload types.
        
        Returns:
            tuple: (value: str, encoding: str)
        """
        if payload is None:
            return '', 'none'
        
        if isinstance(payload, dict):
            value = str(payload.get('payload', '')) if payload.get('payload') is not None else ''
            encoding = payload.get('encoding', 'none') or 'none'
            return value, encoding
        
        if isinstance(payload, str):
            return payload, 'none'
        
        if hasattr(payload, 'payload'):
            # PayloadVariant or similar object
            value = str(payload.payload) if payload.payload is not None else ''
            encoding = getattr(payload, 'encoding', 'none') or 'none'
            return value, encoding
        
        # Fallback: convert to string
        return str(payload), 'none'
    
    @classmethod
    def _apply_encoding(cls, value: str, encoding: str) -> str:
        """
        Apply the specified encoding to a value.
        
        Args:
            value: The string to encode
            encoding: The encoding type
            
        Returns:
            str: The encoded string
        """
        if not value:
            return value
        
        encoding = encoding.lower() if encoding else 'none'
        
        if encoding == 'url':
            return quote(value, safe='')
        elif encoding == 'double_url':
            return quote(quote(value, safe=''), safe='')
        elif encoding == 'html':
            return cls._html_encode(value)
        elif encoding == 'unicode':
            result = cls._unicode_encode(value)
            logger.info(f"🔐 [UNICODE_ENCODE] Input: {repr(value)[:50]}, Output: {repr(result)[:50]}")
            return result
        
        # 'none' or unknown encoding - passthrough
        return value
    
    @staticmethod
    def _html_encode(value: str) -> str:
        """HTML entity encode special characters."""
        return (value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))
    
    @staticmethod
    def _unicode_encode(value: str) -> str:
        r"""
        Convert to Unicode escape sequences for WAF bypass.
        
        Note: Unicode encoding is primarily useful for:
        - URL parameters (where \u escapes might bypass filters)
        - Header values in some cases
        
        It should NOT be used for JSON bodies as it can cause parsing issues.
        The encoding produces valid JSON unicode escapes (\uXXXX format).
        
        For JSON body injection, use 'none' or 'url' encoding instead.
        """
        # Only encode non-ASCII and special characters to minimize issues
        result = []
        for c in value:
            code = ord(c)
            # Encode control chars, quotes, backslashes, and non-ASCII
            if code < 32 or code > 126 or c in '"\\':
                result.append(f'\\u{code:04x}')
            else:
                result.append(c)
        return ''.join(result)
    
    @classmethod
    def decode(cls, value: str, encoding: str) -> str:
        """
        Decode a value (reverse of encode).
        
        Useful for testing and validation.
        
        Args:
            value: The encoded string
            encoding: The encoding that was used
            
        Returns:
            str: The decoded string
        """
        if not value:
            return value
        
        encoding = encoding.lower() if encoding else 'none'
        
        if encoding == 'url':
            from urllib.parse import unquote
            return unquote(value)
        elif encoding == 'double_url':
            from urllib.parse import unquote
            return unquote(unquote(value))
        elif encoding == 'html':
            import html
            return html.unescape(value)
        elif encoding == 'unicode':
            # Decode \\uXXXX sequences
            return value.encode().decode('unicode_escape')
        
        return value

"""
Body Injector - Injects payloads into request bodies (JSON and form-urlencoded).

Handles complex cases:
- JSON with nested paths ("foo.bar.baz")
- JSON with various value types (string, number, null, bool, array, object)
- Form-urlencoded with bracket notation
- URL-encoded parameter names
"""

import re
import logging
from typing import Tuple, Optional, Dict, Any
from urllib.parse import quote

logger = logging.getLogger(__name__)


class BodyInjector:
    """
    Injects payloads into request bodies.
    
    Supports JSON and form-urlencoded bodies with intelligent pattern matching.
    Uses text replacement to preserve original formatting.
    """
    
    @classmethod
    def inject(
        cls,
        body: Optional[str],
        body_json: Optional[Dict[str, Any]],
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        Inject payload into body (JSON or form-urlencoded).
        
        Args:
            body: Raw body string
            body_json: Parsed JSON body (if applicable)
            injection_point: Key/path to inject into
            payload: Payload to inject
            
        Returns:
            Tuple of (new_body, success)
        """
        if not body:
            return body or "", False
        
        # Try JSON injection first if we have parsed JSON
        if body_json:
            new_body, success = cls.inject_json(body, injection_point, payload)
            if success:
                return new_body, True
        
        # Try form-urlencoded injection
        new_body, success = cls.inject_form(body, injection_point, payload)
        return new_body, success
    
    @classmethod
    def inject_json(
        cls,
        body: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        Inject payload into JSON body using text replacement.
        
        Preserves original formatting by using regex substitution.
        Handles nested paths like "foo.bar.baz".
        """
        logger.info(f"🔧 [BODY_INJECT] injection_point={injection_point}, payload={repr(payload)[:80]}")
        logger.info(f"🔧 [BODY_INJECT] body_before={repr(body)[:100]}")
        
        # Handle nested paths
        if '.' in injection_point:
            result = cls._inject_json_nested(body, injection_point, payload)
            logger.info(f"🔧 [BODY_INJECT] body_after={repr(result[0])[:100]}, success={result[1]}")
            return result
        
        return cls._inject_json_simple(body, injection_point, payload)
    
    @classmethod
    def _inject_json_nested(
        cls,
        body: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        Inject into nested JSON path like "advertise.url".
        
        Strategy: Find the final key and replace its value.
        """
        path_parts = injection_point.split('.')
        final_key = path_parts[-1]
        
        # Try to find and replace the final key
        # Pattern for string values: "key": "value"
        pattern_string = rf'("{re.escape(final_key)}")\s*:\s*"[^"]*"'
        replacement_string = rf'\1:"{payload}"'
        
        # Pattern for numeric values: "key": 123
        pattern_number = rf'("{re.escape(final_key)}")\s*:\s*(-?\d+(?:\.\d+)?)'
        replacement_number = rf'\1:{payload}'
        
        # Pattern for null/bool: "key": null
        pattern_null = rf'("{re.escape(final_key)}")\s*:\s*(null|true|false)'
        replacement_null = rf'\1:"{payload}"'
        
        if re.search(pattern_string, body):
            new_body = re.sub(pattern_string, replacement_string, body, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced nested string '{injection_point}' (key: {final_key})")
            return new_body, True
        
        if re.search(pattern_number, body):
            new_body = re.sub(pattern_number, replacement_number, body, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced nested number '{injection_point}' (key: {final_key})")
            return new_body, True
        
        if re.search(pattern_null, body):
            new_body = re.sub(pattern_null, replacement_null, body, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced nested null/bool '{injection_point}' (key: {final_key})")
            return new_body, True
        
        logger.warning(f"⚠️ [INJECT] ❌ Could not find nested key '{final_key}' from path '{injection_point}'")
        return body, False
    
    @classmethod
    def _inject_json_simple(
        cls,
        body: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        Inject into simple JSON key (not nested).
        
        Handles: strings, numbers, null, booleans, arrays, objects.
        """
        # Pattern for string values
        pattern_string = rf'("{re.escape(injection_point)}")\s*:\s*"[^"]*"'
        replacement_string = rf'\1:"{payload}"'
        
        # Pattern for numeric values
        pattern_number = rf'("{re.escape(injection_point)}")\s*:\s*(-?\d+(?:\.\d+)?)'
        replacement_number = rf'\1:{payload}'
        
        # Pattern for null/bool
        pattern_null = rf'("{re.escape(injection_point)}")\s*:\s*(null|true|false)'
        replacement_null = rf'\1:"{payload}"'
        
        # Pattern for array values
        pattern_array = rf'("{re.escape(injection_point)}")\s*:\s*\[[^\]]*\]'
        replacement_array = rf'\1:["{payload}"]'
        
        # Pattern for object values
        pattern_object = rf'("{re.escape(injection_point)}")\s*:\s*\{{[^}}]*\}}'
        replacement_object = rf'\1:"{payload}"'
        
        # Try each pattern in order
        if re.search(pattern_string, body):
            new_body = re.sub(pattern_string, replacement_string, body, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced string value for '{injection_point}'")
            return new_body, True
        
        if re.search(pattern_number, body):
            new_body = re.sub(pattern_number, replacement_number, body, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced numeric value for '{injection_point}'")
            return new_body, True
        
        if re.search(pattern_null, body):
            new_body = re.sub(pattern_null, replacement_null, body, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced null/bool value for '{injection_point}'")
            return new_body, True
        
        if re.search(pattern_array, body):
            new_body = re.sub(pattern_array, replacement_array, body, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced array value for '{injection_point}'")
            return new_body, True
        
        if re.search(pattern_object, body):
            new_body = re.sub(pattern_object, replacement_object, body, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced object value for '{injection_point}'")
            return new_body, True
        
        logger.warning(f"⚠️ [INJECT] ❌ Could not find '{injection_point}' in JSON body")
        return body, False
    
    @classmethod
    def inject_form(
        cls,
        body: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        Inject payload into form-urlencoded body.
        
        Tries multiple strategies:
        1. Exact match
        2. URL-encoded version
        3. Bracket-encoded version
        4. Flexible array notation
        """
        body_str = str(body)
        
        # URL-encode the injection point
        injection_point_encoded = quote(injection_point, safe='')
        
        # Bracket pattern encoding
        injection_point_bracket = (
            injection_point
            .replace('[]', '%5B%5D')
            .replace('[', '%5B')
            .replace(']', '%5D')
        )
        
        # Strategy 1: Exact match
        if f"{injection_point}=" in body_str:
            pattern = rf'({re.escape(injection_point)}=)([^&]*)'
            if re.search(pattern, body_str):
                new_body = re.sub(pattern, r'\g<1>' + quote(payload, safe=""), body_str, count=1)
                logger.info(f"🔧 [INJECT] ✅ Replaced form param '{injection_point}' (exact match)")
                return new_body, True
        
        # Strategy 2: URL-encoded version
        if f"{injection_point_encoded}=" in body_str:
            pattern = rf'({re.escape(injection_point_encoded)}=)([^&]*)'
            if re.search(pattern, body_str):
                new_body = re.sub(pattern, r'\g<1>' + quote(payload, safe=""), body_str, count=1)
                logger.info(f"🔧 [INJECT] ✅ Replaced form param '{injection_point}' (URL-encoded)")
                return new_body, True
        
        # Strategy 3: Bracket-encoded version
        if f"{injection_point_bracket}=" in body_str:
            pattern = rf'({re.escape(injection_point_bracket)}=)([^&]*)'
            if re.search(pattern, body_str):
                new_body = re.sub(pattern, r'\g<1>' + quote(payload, safe=""), body_str, count=1)
                logger.info(f"🔧 [INJECT] ✅ Replaced form param '{injection_point}' (bracket-encoded)")
                return new_body, True
        
        # Strategy 4: Flexible regex for array notation
        if '[]' in injection_point or '[' in injection_point:
            new_body, success = cls._inject_form_array(body_str, injection_point, payload)
            if success:
                return new_body, True
        
        logger.warning(f"⚠️ [INJECT] Form param '{injection_point}' not found in body")
        logger.debug(f"⚠️ [INJECT] Body preview: {body_str[:200]}...")
        return body, False
    
    @classmethod
    def _inject_form_array(
        cls,
        body: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        Handle array notation in form bodies.
        
        "foo[].bar" should match "foo[0][bar]", "foo[][bar]", "foo%5B0%5D%5Bbar%5D", etc.
        """
        array_match = re.match(r'([^\[\]]+)\[\]\.?(.+)?', injection_point)
        if not array_match:
            return body, False
        
        base = array_match.group(1)
        suffix = array_match.group(2) or ""
        
        # Build flexible pattern
        base_esc = re.escape(base)
        suffix_esc = re.escape(suffix) if suffix else ""
        
        # Pattern matches: base[any index or empty][suffix]
        # Including URL-encoded versions
        pattern = rf'({base_esc}(?:\[|\%5[Bb])(?:\d*)?(?:\]|\%5[Dd])(?:\[|\%5[Bb]){suffix_esc}(?:\]|\%5[Dd])=)([^&]*)'
        
        if re.search(pattern, body):
            new_body = re.sub(pattern, r'\g<1>' + quote(payload, safe=""), body, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced form array param '{injection_point}' (flexible pattern)")
            return new_body, True
        
        return body, False

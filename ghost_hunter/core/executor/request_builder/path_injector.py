"""
Path Injector - Injects payloads into URL paths.

Handles 6 different cases:
- CASE 0: Template mapping using path_template
- CASE 1: Resource template like "profiles/{id}"
- CASE 2: Simple placeholder like "{id}", "{token}"
- CASE 3: Named ID like "id", "user_id"
- CASE 4: Named token like "token", "session"
- CASE 5: Literal string in URL
- CASE 6: Fallback path segment extraction
"""

import re
import logging
from typing import Tuple, Optional, Any

logger = logging.getLogger(__name__)


class PathInjector:
    """
    Injects payloads into URL paths with intelligent pattern matching.
    
    Supports multiple injection strategies based on injection_point format.
    """
    
    @classmethod
    def inject(
        cls,
        url: str,
        original_req: Any,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        Inject payload into URL path.
        
        Tries multiple strategies in order:
        1. Template mapping (if path_template available)
        2. Resource template pattern ("profiles/{id}")
        3. Simple placeholder ("{id}", "{token}")
        4. Named ID patterns
        5. Named token patterns
        6. Literal string replacement
        7. Fallback path segment
        
        Args:
            url: Original URL
            original_req: Original request object (for path_template)
            injection_point: Path segment or template to inject into
            payload: Payload to inject
            
        Returns:
            Tuple of (new_url, success)
        """
        # Extract path and query from URL
        url_parts = url.split('?')
        path_part = url_parts[0]
        query_part = url_parts[1] if len(url_parts) > 1 else None
        
        # Get path_template if available
        path_template = cls._get_path_template(original_req)
        
        logger.debug(f"🔧 [INJECT] Path template: {path_template}, injection_point: {injection_point}")
        
        # Try each case in order
        new_path, success = cls._try_all_cases(
            path_part, path_template, injection_point, payload, original_req
        )
        
        if not success:
            logger.warning(f"⚠️ [INJECT] ❌ Could not inject in path for '{injection_point}'")
            logger.warning(f"⚠️ [INJECT] URL was: {url}")
            return url, False
        
        # Reconstruct URL
        if query_part:
            new_url = f"{new_path}?{query_part}"
        else:
            new_url = new_path
        
        return new_url, True
    
    @staticmethod
    def _get_path_template(original_req: Any) -> Optional[str]:
        """Extract path_template from request object."""
        if hasattr(original_req, 'get_endpoint_template') and callable(original_req.get_endpoint_template):
            return original_req.get_endpoint_template()
        elif hasattr(original_req, 'path_template'):
            return original_req.path_template
        return None
    
    @classmethod
    def _try_all_cases(
        cls,
        path_part: str,
        path_template: Optional[str],
        injection_point: str,
        payload: str,
        original_req: Any,
    ) -> Tuple[str, bool]:
        """Try all injection cases in priority order."""
        
        # CASE 0: Smart mapping using path_template
        if path_template and '{' in path_template:
            new_path, success = cls._inject_using_template(
                path_template, path_part, injection_point, payload
            )
            if success:
                logger.info(f"🔧 [INJECT] ✅ Template mapping: '{injection_point}' replaced using path_template")
                return new_path, True
        
        # CASE 1: Resource template like "profiles/{id}"
        new_path, success = cls._inject_resource_template(path_part, injection_point, payload)
        if success:
            return new_path, True
        
        # CASE 2: Simple placeholder like "{id}", "{token}"
        new_path, success = cls._inject_placeholder(path_part, injection_point, payload)
        if success:
            return new_path, True
        
        # CASE 3: Named ID like "id", "user_id"
        new_path, success = cls._inject_named_id(path_part, injection_point, payload)
        if success:
            return new_path, True
        
        # CASE 4: Named token like "token", "session"
        new_path, success = cls._inject_named_token(path_part, injection_point, payload)
        if success:
            return new_path, True
        
        # CASE 5: Literal string in URL
        new_path, success = cls._inject_literal(path_part, injection_point, payload)
        if success:
            return new_path, True
        
        # CASE 6: Fallback path segment extraction
        new_path, success = cls._inject_fallback(path_part, injection_point, payload)
        if success:
            return new_path, True
        
        return path_part, False
    
    @classmethod
    def _inject_using_template(
        cls,
        path_template: str,
        path_part: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        CASE 0: Use path_template to map placeholders to actual values.
        
        Example:
            template = "/users/{id}/sessions/{token}/info"
            url = "/users/123/sessions/abc456/info"
            injection_point = "{token}" → should replace "abc456"
        """
        # Check if injection_point matches a template placeholder
        if not injection_point.startswith('{') or not injection_point.endswith('}'):
            # Try adding braces
            placeholder = '{' + injection_point + '}'
            if placeholder not in path_template:
                return path_part, False
            injection_point = placeholder
        
        if injection_point not in path_template:
            return path_part, False
        
        # Build regex pattern from template to extract values
        # Convert template to regex: /users/{id}/sessions → /users/([^/]+)/sessions
        pattern_parts = []
        value_names = []
        
        remaining = path_template
        while '{' in remaining:
            idx = remaining.index('{')
            end_idx = remaining.index('}')
            
            # Add literal part
            if idx > 0:
                pattern_parts.append(re.escape(remaining[:idx]))
            
            # Add capture group for placeholder
            placeholder_name = remaining[idx:end_idx+1]
            value_names.append(placeholder_name)
            pattern_parts.append('([^/]+)')
            
            remaining = remaining[end_idx+1:]
        
        if remaining:
            pattern_parts.append(re.escape(remaining))
        
        pattern = '^' + ''.join(pattern_parts) + '$'
        
        # Extract protocol and host from path_part if present
        if '://' in path_part:
            proto_host, path_only = path_part.split('://', 1)
            if '/' in path_only:
                host, path_only = path_only.split('/', 1)
                path_only = '/' + path_only
                prefix = f"{proto_host}://{host}"
            else:
                return path_part, False
        else:
            path_only = path_part
            prefix = ''
        
        # Match and extract values
        match = re.match(pattern, path_only)
        if not match:
            return path_part, False
        
        # Find which group corresponds to our injection point
        try:
            idx = value_names.index(injection_point)
            groups = list(match.groups())
            groups[idx] = payload
            
            # Reconstruct path from template
            new_path = path_template
            for name, value in zip(value_names, groups):
                new_path = new_path.replace(name, value, 1)
            
            return prefix + new_path, True
        except (ValueError, IndexError):
            return path_part, False
    
    @classmethod
    def _inject_resource_template(
        cls,
        path_part: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        CASE 1: Template-style injection point like "profiles/{id}".
        
        Pattern: "resource/{placeholder}" - can be anywhere in the path.
        """
        template_match = re.search(r'([a-zA-Z_]+)/\{([^}]+)\}', injection_point)
        if not template_match:
            return path_part, False
        
        resource_prefix = template_match.group(1)
        
        print(f"🔧 [INJECT] CASE 1: resource='{resource_prefix}'")
        print(f"🔧 [INJECT] Path to search: {path_part}")
        
        # Try numeric first
        pattern = rf'(/{re.escape(resource_prefix)}/)(\d+)'
        if re.search(pattern, path_part):
            old_path = path_part
            new_path = re.sub(pattern, rf'\g<1>{payload}', path_part, count=1)
            print(f"🔧 [INJECT] ✅ Replaced: '{old_path}' → '{new_path}'")
            logger.info(f"🔧 [INJECT] ✅ Replaced numeric template '{injection_point}'")
            return new_path, True
        
        # Try alphanumeric token (for UUIDs, hashes)
        pattern_token = rf'(/{re.escape(resource_prefix)}/)([a-zA-Z0-9_\-]{{4,}})'
        if re.search(pattern_token, path_part):
            new_path = re.sub(pattern_token, rf'\g<1>{payload}', path_part, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced token template '{injection_point}'")
            return new_path, True
        
        return path_part, False
    
    @classmethod
    def _inject_placeholder(
        cls,
        path_part: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        CASE 2: Simple placeholder like "{id}" or "{token}".
        
        Uses position heuristics based on placeholder name.
        """
        if not injection_point.startswith('{') or not injection_point.endswith('}'):
            return path_part, False
        
        placeholder_name = injection_point[1:-1].lower()
        
        # ID-like placeholders: replace first numeric
        if placeholder_name in ['id', 'user_id', 'account_id', 'profile_id', 'item_id']:
            pattern = r'/(\d+)(/|$|\?)'
            if re.search(pattern, path_part):
                new_path = re.sub(pattern, f'/{payload}\\g<2>', path_part, count=1)
                logger.info(f"🔧 [INJECT] ✅ Replaced '{injection_point}' → first numeric ID")
                return new_path, True
        
        # UUID placeholders
        elif placeholder_name in ['uuid', 'guid', 'task_id', 'doc_id', 'ref']:
            pattern_uuid = r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(/|$|\?)'
            if re.search(pattern_uuid, path_part, re.IGNORECASE):
                new_path = re.sub(pattern_uuid, f'/{payload}\\g<2>', path_part, count=1, flags=re.IGNORECASE)
                logger.info(f"🔧 [INJECT] ✅ Replaced '{injection_point}' → first UUID")
                return new_path, True
        
        # Token placeholders: replace first NON-numeric token
        elif placeholder_name in ['token', 'session', 'hash', 'key', 'code', 'secret']:
            # First try: alphanumeric with letters
            pattern = r'/([a-zA-Z][a-zA-Z0-9_\-]{3,}|[a-zA-Z0-9_\-]*[a-zA-Z][a-zA-Z0-9_\-]*)(/|$|\?)'
            if re.search(pattern, path_part):
                new_path = re.sub(pattern, f'/{payload}\\g<2>', path_part, count=1)
                logger.info(f"🔧 [INJECT] ✅ Replaced '{injection_point}' → first alphanumeric token")
                return new_path, True
            
            # Fallback: second dynamic segment
            segments = [s for s in path_part.split('/') if s]
            if len(segments) >= 2:
                count = 0
                new_segments = []
                for seg in path_part.split('/'):
                    if seg and re.match(r'^[a-zA-Z0-9_\-]{2,}$', seg) and not seg.isalpha():
                        count += 1
                        if count == 2:
                            new_segments.append(payload)
                            logger.info(f"🔧 [INJECT] ✅ Replaced '{injection_point}' → second dynamic segment")
                            # Continue building the path
                            new_segments.extend(path_part.split('/')[len(new_segments)+1:])
                            return '/'.join(new_segments), True
                    new_segments.append(seg)
        
        else:
            # Generic: replace first dynamic segment
            pattern = r'/(\d+|[a-zA-Z0-9_\-]{8,})(/|$|\?)'
            if re.search(pattern, path_part):
                new_path = re.sub(pattern, f'/{payload}\\g<2>', path_part, count=1)
                logger.info(f"🔧 [INJECT] ✅ Replaced placeholder '{injection_point}' → first dynamic segment")
                return new_path, True
        
        return path_part, False
    
    @classmethod
    def _inject_named_id(
        cls,
        path_part: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        CASE 3: Named ID like "id", "user_id", "profile_id" (without braces).
        """
        ip_lower = injection_point.lower()
        if not (ip_lower.endswith('id') or ip_lower in ['id', 'uuid', 'key']):
            return path_part, False
        
        # Try numeric ID
        pattern = r'/(\d+)(/|$|\?)'
        if re.search(pattern, path_part):
            new_path = re.sub(pattern, f'/{payload}\\g<2>', path_part, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced named ID '{injection_point}' → first numeric ID")
            return new_path, True
        
        # Try UUID
        pattern_uuid = r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(/|$|\?)'
        if re.search(pattern_uuid, path_part, re.IGNORECASE):
            new_path = re.sub(pattern_uuid, f'/{payload}\\g<2>', path_part, count=1, flags=re.IGNORECASE)
            logger.info(f"🔧 [INJECT] ✅ Replaced UUID '{injection_point}'")
            return new_path, True
        
        return path_part, False
    
    @classmethod
    def _inject_named_token(
        cls,
        path_part: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        CASE 4: Named token like "token", "session", "hash" (without braces).
        """
        ip_lower = injection_point.lower()
        if ip_lower not in ['token', 'session', 'hash', 'key', 'code', 'secret', 'signature']:
            return path_part, False
        
        # Replace first alphanumeric token with letters
        pattern = r'/([a-zA-Z][a-zA-Z0-9_\-]{3,}|[a-zA-Z0-9_\-]*[a-zA-Z][a-zA-Z0-9_\-]*)(/|$|\?)'
        if re.search(pattern, path_part):
            new_path = re.sub(pattern, f'/{payload}\\g<2>', path_part, count=1)
            logger.info(f"🔧 [INJECT] ✅ Replaced named token '{injection_point}'")
            return new_path, True
        
        return path_part, False
    
    @classmethod
    def _inject_literal(
        cls,
        path_part: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        CASE 5: Literal string replacement in URL.
        """
        # Try with braces
        if '{' + injection_point + '}' in path_part:
            new_path = path_part.replace('{' + injection_point + '}', payload)
            logger.info(f"🔧 [INJECT] ✅ Replaced literal placeholder '{{{injection_point}}}'")
            return new_path, True
        
        # Try exact string
        if injection_point in path_part:
            new_path = path_part.replace(injection_point, payload, 1)
            logger.info(f"🔧 [INJECT] ✅ Replaced literal string '{injection_point}'")
            return new_path, True
        
        return path_part, False
    
    @classmethod
    def _inject_fallback(
        cls,
        path_part: str,
        injection_point: str,
        payload: str,
    ) -> Tuple[str, bool]:
        """
        CASE 6: Fallback - extract resource name from injection_point and match.
        
        E.g., injection_point = "profiles/{id}/edit" → extract "profiles" and replace value after it.
        """
        if '/' not in injection_point:
            return path_part, False
        
        # Extract segments that might be resource names
        segments = [s for s in injection_point.split('/') if s and not s.startswith('{')]
        
        for segment in segments:
            if len(segment) <= 2:
                continue
            
            # Try numeric after segment
            pattern = rf'(/{re.escape(segment)}/)(\d+)'
            if re.search(pattern, path_part):
                new_path = re.sub(pattern, rf'\g<1>{payload}', path_part, count=1)
                logger.info(f"🔧 [INJECT] ✅ Fallback: Replaced numeric after '{segment}'")
                return new_path, True
            
            # Try alphanumeric token after segment
            pattern_token = rf'(/{re.escape(segment)}/)([a-zA-Z0-9_\-]{{4,}})'
            if re.search(pattern_token, path_part):
                new_path = re.sub(pattern_token, rf'\g<1>{payload}', path_part, count=1)
                logger.info(f"🔧 [INJECT] ✅ Fallback: Replaced token after '{segment}'")
                return new_path, True
        
        return path_part, False

"""
WAF Evasion Handler - Payload transformation to bypass WAF.

Handles:
- Automatic evasion via PayloadMutator
- WAF-specific transform selection
- Evasion statistics tracking

Extracted from http_runner.py Phase 11 refactoring.
"""

import logging
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..evasion.checker import WAFChecker
    from ..evasion.mutator import PayloadMutator
    from ..contracts import SecurityProfile

from ..evasion.transforms import apply_transform

logger = logging.getLogger(__name__)


class WAFEvasionHandler:
    """
    Handles WAF evasion for payloads.
    
    Uses WAFChecker to detect if payload would be blocked,
    then applies transforms to evade detection.
    """
    
    def __init__(
        self,
        waf_checker: Optional['WAFChecker'] = None,
        payload_mutator: Optional['PayloadMutator'] = None,
        security_profile: Optional['SecurityProfile'] = None,
    ):
        """
        Initialize WAF evasion handler.
        
        Args:
            waf_checker: WAFChecker instance for block detection
            payload_mutator: PayloadMutator for auto-evasion
            security_profile: SecurityProfile with detected WAF info
        """
        self._waf_checker = waf_checker
        self._payload_mutator = payload_mutator
        self.security_profile = security_profile
        self._evasion_stats = {"original_blocked": 0, "evaded": 0, "failed": 0}
    
    @property
    def stats(self) -> dict:
        """Get evasion statistics."""
        return self._evasion_stats.copy()
    
    def apply_evasion(self, payload: str, vuln_type: str) -> tuple[str, str, bool]:
        """
        Apply WAF evasion transforms if payload would be blocked.
        
        Args:
            payload: Original payload string
            vuln_type: Vulnerability type (sqli, xss, cmdi, etc.)
            
        Returns:
            tuple: (transformed_payload, transform_used, was_transformed)
        """
        if not self._waf_checker or not payload:
            return payload, "none", False
        
        # Normalize vuln_type
        vuln_type_lower = self._normalize_vuln_type(vuln_type)
        
        # Check if original payload would be blocked
        is_blocked, blocked_by, _ = self._waf_checker.is_blocked_any(payload, vuln_type_lower)
        
        if not is_blocked:
            return payload, "none", False
        
        logger.warning(f"🛡️ [WAF_EVASION] Original payload BLOCKED by: {blocked_by}")
        self._evasion_stats["original_blocked"] += 1
        
        # Try auto-evasion first
        if self._payload_mutator:
            result = self._try_auto_evade(payload, vuln_type_lower)
            if result:
                return result
        
        # Fallback to manual transforms
        result = self._try_manual_transforms(payload, vuln_type_lower)
        if result:
            return result
        
        # No evasion found
        logger.error(f"❌ [WAF_EVASION] All evasion attempts failed for: {payload[:30]}...")
        self._evasion_stats["failed"] += 1
        return payload, "none (blocked)", False
    
    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type to standard format."""
        vuln_type_lower = vuln_type.lower() if vuln_type else "sqli"
        if vuln_type_lower in ["sql_injection", "sqli", "sql"]:
            return "sqli"
        elif vuln_type_lower in ["cross_site_scripting", "xss"]:
            return "xss"
        elif vuln_type_lower in ["command_injection", "cmdi", "rce", "os_command"]:
            return "cmdi"
        return vuln_type_lower
    
    def _try_auto_evade(self, payload: str, vuln_type: str) -> Optional[tuple[str, str, bool]]:
        """Try automatic evasion via PayloadMutator."""
        evasion_result = self._payload_mutator.auto_evade(
            payload, 
            vuln_type, 
            max_depth=3
        )
        
        if evasion_result.best_mutation and evasion_result.best_mutation.evades:
            mutated = evasion_result.best_mutation.mutated
            transform = evasion_result.best_mutation.transform
            logger.info(f"🎯 [WAF_EVASION] Found evasion using: {transform}")
            self._evasion_stats["evaded"] += 1
            return mutated, transform, True
        
        logger.warning(f"🛡️ [WAF_EVASION] Auto-evade failed, trying WAF-specific transforms")
        return None
    
    def _try_manual_transforms(self, payload: str, vuln_type: str) -> Optional[tuple[str, str, bool]]:
        """Try manual transforms based on detected WAF."""
        transforms = self.get_waf_specific_transforms(vuln_type)
        
        for transform_name in transforms:
            try:
                mutated = apply_transform(payload, transform_name, vuln_type)
                if mutated and mutated != payload:
                    is_still_blocked, _, _ = self._waf_checker.is_blocked_any(mutated, vuln_type)
                    if not is_still_blocked:
                        logger.info(f"🎯 [WAF_EVASION] Transform '{transform_name}' evades WAF!")
                        self._evasion_stats["evaded"] += 1
                        return mutated, transform_name, True
            except Exception as e:
                logger.debug(f"Transform {transform_name} failed: {e}")
                continue
        
        return None
    
    def get_waf_specific_transforms(self, vuln_type: str) -> List[str]:
        """
        Get transforms optimized for the detected WAF.
        
        Returns ordered list of transforms to try based on security profile.
        """
        detected_waf = self._get_detected_waf()
        
        # Cloudflare-specific evasions
        if detected_waf and "cloudflare" in detected_waf:
            return [
                "unicode", "double_url_encode", "inline_comment",
                "case_swap", "whitespace_substitute", "hex_encode",
            ]
        
        # AWS WAF
        if detected_waf and "aws" in detected_waf:
            return [
                "case_swap", "inline_comment", "whitespace_substitute",
                "url_encode", "concat_split",
            ]
        
        # Akamai
        if detected_waf and "akamai" in detected_waf:
            return [
                "double_url_encode", "null_bytes", "whitespace_substitute",
                "hex_encode", "char_function",
            ]
        
        # Generic transforms based on vuln type
        return self._get_generic_transforms(vuln_type)
    
    def _get_detected_waf(self) -> Optional[str]:
        """Get the detected WAF from security profile."""
        if not self.security_profile:
            return None
        waf_list = getattr(self.security_profile, 'waf', []) or []
        return waf_list[0].lower() if waf_list else None
    
    def _get_generic_transforms(self, vuln_type: str) -> List[str]:
        """Get generic transforms for a vulnerability type."""
        if vuln_type == "sqli":
            return [
                "case_swap", "inline_comment", "whitespace_substitute",
                "url_encode", "double_url_encode", "hex_encode",
                "char_function", "concat_split"
            ]
        elif vuln_type == "xss":
            return [
                "tag_case_mix", "svg_payload", "img_payload",
                "null_bytes", "url_encode", "double_url_encode"
            ]
        elif vuln_type == "cmdi":
            return [
                "variable_sub", "ifs_sub", "quote_insert",
                "wildcard", "url_encode", "base64_wrap"
            ]
        return ["url_encode", "double_url_encode", "case_swap"]

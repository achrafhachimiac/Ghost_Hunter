"""
WAF Checker
===========
Simule le comportement d'un WAF F5 pour tester si un payload serait bloqué.
"""

import re
import yaml
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from functools import lru_cache


# Simplified keyword-based patterns for quick detection
KEYWORD_PATTERNS = {
    "sqli": [
        r"(?i)\bUNION\b.*\bSELECT\b",
        r"(?i)\bSELECT\b.*\bFROM\b",
        r"(?i)\bINSERT\b.*\bINTO\b",
        r"(?i)\bUPDATE\b.*\bSET\b",
        r"(?i)\bDELETE\b.*\bFROM\b",
        r"(?i)\bDROP\b.*\b(?:TABLE|DATABASE)\b",
        r"(?i)\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"(?i)\bAND\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"(?i)['\"]\s*(?:OR|AND)\s*['\"]",
        r"(?i)\bEXEC\b.*\b(?:XP_|SP_)",
        r"(?i)--\s*$",
        r"(?i);\s*--",
        r"(?i)/\*.*\*/",
        r"(?i)\bWAITFOR\b.*\bDELAY\b",
        r"(?i)\bBENCHMARK\b\s*\(",
        r"(?i)\bSLEEP\b\s*\(",
        r"(?i)'\s*;\s*\w+",
    ],
    "xss": [
        r"(?i)<\s*script\b",
        r"(?i)</\s*script\s*>",
        r"(?i)\bon\w+\s*=",
        r"(?i)javascript\s*:",
        r"(?i)vbscript\s*:",
        r"(?i)<\s*img\b[^>]*\bonerror\b",
        r"(?i)<\s*svg\b[^>]*\bonload\b",
        r"(?i)<\s*iframe\b",
        r"(?i)<\s*object\b",
        r"(?i)<\s*embed\b",
        r"(?i)<\s*link\b[^>]*\bhref\b",
        r"(?i)expression\s*\(",
        r"(?i)eval\s*\(",
        r"(?i)document\s*\.\s*(?:cookie|location|write)",
        r"(?i)window\s*\.\s*(?:location|open)",
        r"(?i)alert\s*\(",
        r"(?i)prompt\s*\(",
        r"(?i)confirm\s*\(",
    ],
    "cmdi": [
        r"(?i)[;&|`]\s*(?:cat|ls|id|whoami|pwd|uname|ifconfig|netstat)",
        r"(?i)[;&|`]\s*(?:wget|curl|nc|ncat|bash|sh|zsh|python|perl|ruby|php)",
        r"(?i)\$\([^)]+\)",
        r"(?i)`[^`]+`",
        r"(?i)/(?:bin|usr|etc|var|tmp)/",
        r"(?i)/etc/passwd",
        r"(?i)/etc/shadow",
        r"(?i)\|\s*(?:cat|head|tail|grep|awk|sed)",
        r"(?i);\s*(?:cat|ls|rm|mv|cp|chmod|chown)",
        r"(?i)&&\s*(?:cat|ls|rm|wget|curl)",
        r"(?i)\bnc\b.*-[elp]",
        r"(?i)\bbash\s+-[ci]",
        r"(?i)\bsh\s+-c",
    ],
    "ssti": [
        r"\{\{.*\}\}",
        r"\{%.*%\}",
        r"\$\{.*\}",
        r"(?i)<%.*%>",
        r"(?i)\[\[.*\]\]",
        r"(?i)#\{.*\}",
        r"(?i)\{\*.*\*\}",
    ],
    "ssrf": [
        r"(?i)(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)",
        r"(?i)(?:https?://)?(?:169\.254\.\d+\.\d+)",
        r"(?i)(?:https?://)?(?:10\.\d+\.\d+\.\d+)",
        r"(?i)(?:https?://)?(?:172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)",
        r"(?i)(?:https?://)?(?:192\.168\.\d+\.\d+)",
        r"(?i)file://",
        r"(?i)gopher://",
        r"(?i)dict://",
        r"(?i)@localhost",
        r"(?i)@127\.0\.0\.1",
    ],
    "traversal": [
        r"(?:\.\.[\\/]){2,}",
        r"(?i)\.\.[\\/](?:etc|var|usr|bin|windows|boot)",
        r"(?i)[\\/]etc[\\/]passwd",
        r"(?i)[\\/]etc[\\/]shadow",
        r"(?i)[\\/]windows[\\/]system32",
        r"(?i)%2e%2e[\\/]",
        r"(?i)%252e%252e[\\/]",
        r"(?i)\.\.%00",
    ],
    "xxe": [
        r"(?i)<!ENTITY\s+",
        r"(?i)<!DOCTYPE\s+[^>]*\[",
        r"(?i)SYSTEM\s+['\"](?:file|http|ftp)://",
        r"(?i)PUBLIC\s+['\"]",
    ],
    "ldap": [
        r"(?i)\)\s*\(\|",
        r"(?i)\)\s*\(\&",
        r"(?i)\*\)\s*\(",
        r"(?i)[\\/][\\/]",
    ],
    "nosql": [
        r'(?i)\$(?:ne|eq|gt|lt|gte|lte|in|nin|or|and|not|exists|regex|where)\b',
        r"(?i)\{\s*['\"]?\$",
        r'(?i)\[\s*\$',
    ],
}


class WAFChecker:
    """
    Simule le comportement du WAF F5.
    
    Charge les patterns depuis le YAML et compile les regex pour
    une vérification rapide des payloads.
    """
    
    def __init__(self, patterns_file: Optional[str] = None):
        """
        Initialize WAF Checker.
        
        Args:
            patterns_file: Path to YAML patterns file. If None, uses default.
        """
        if patterns_file is None:
            # Default path relative to this file
            patterns_file = Path(__file__).parent / "data" / "waf_patterns.yaml"
        
        self.patterns_file = Path(patterns_file)
        self.patterns: Dict[str, List[Dict]] = {}
        self._compiled: Dict[str, List[Tuple[str, re.Pattern]]] = {}
        
        self._load_patterns()
        self._compile_patterns()
    
    def _load_patterns(self) -> None:
        """Load patterns from YAML file."""
        if not self.patterns_file.exists():
            raise FileNotFoundError(f"Patterns file not found: {self.patterns_file}")
        
        with open(self.patterns_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        # Extract vuln type categories
        skip_keys = {'version', 'source', 'generated', 'total_patterns'}
        
        for key, value in data.items():
            if key not in skip_keys and isinstance(value, list):
                self.patterns[key] = value
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for performance."""
        for vuln_type, patterns in self.patterns.items():
            compiled_list = []
            
            for p in patterns:
                pattern_str = p.get('pattern', '')
                flags_str = p.get('flags', '').lower()
                pattern_id = p.get('id', 'unknown')
                
                if not pattern_str:
                    continue
                
                # Convert flags
                flags = 0
                if 'i' in flags_str:
                    flags |= re.IGNORECASE
                if 's' in flags_str:
                    flags |= re.DOTALL
                if 'm' in flags_str:
                    flags |= re.MULTILINE
                
                try:
                    compiled = re.compile(pattern_str, flags)
                    compiled_list.append((pattern_id, compiled))
                except re.error:
                    # Skip invalid patterns
                    continue
            
            self._compiled[vuln_type] = compiled_list
    
    def is_blocked(
        self,
        payload: str,
        vuln_type: str,
        location: str = "parameter",
        include_other: bool = False
    ) -> Tuple[bool, List[str]]:
        """
        Check if a payload would be blocked by the WAF.
        
        Args:
            payload: The payload to check
            vuln_type: Vulnerability type (sqli, xss, cmdi, ssti, etc.)
            location: Where the payload is (parameter, header, uri, body)
            include_other: Include "other" category patterns (can cause false positives)
            
        Returns:
            Tuple of (is_blocked, list_of_matching_pattern_ids)
        """
        matching_patterns = []
        
        # Get compiled patterns for this vuln type
        patterns = self._compiled.get(vuln_type, [])
        
        for pattern_id, compiled_regex in patterns:
            try:
                if compiled_regex.search(payload):
                    matching_patterns.append(pattern_id)
            except Exception:
                continue
        
        # Optionally check "other" category (disabled by default - too many false positives)
        if include_other:
            other_patterns = self._compiled.get("other", [])
            for pattern_id, compiled_regex in other_patterns:
                try:
                    if compiled_regex.search(payload):
                        matching_patterns.append(pattern_id)
                except Exception:
                    continue
        
        return len(matching_patterns) > 0, matching_patterns
    
    def check_all(
        self,
        payload: str,
        location: str = "parameter"
    ) -> Dict[str, Tuple[bool, List[str]]]:
        """
        Check payload against all vulnerability types.
        
        Args:
            payload: The payload to check
            location: Where the payload is
            
        Returns:
            Dict mapping vuln_type to (is_blocked, pattern_ids)
        """
        results = {}
        
        for vuln_type in self.patterns.keys():
            if vuln_type == "other":
                continue
            results[vuln_type] = self.is_blocked(payload, vuln_type, location)
        
        return results
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about loaded patterns."""
        return {
            vuln_type: len(patterns) 
            for vuln_type, patterns in self._compiled.items()
        }
    
    def is_blocked_keywords(
        self,
        payload: str,
        vuln_type: str
    ) -> Tuple[bool, List[str]]:
        """
        Check if payload matches simplified keyword patterns.
        
        This is a faster, more general check based on common WAF keywords.
        Use this for quick pre-filtering before using the full F5 patterns.
        
        Args:
            payload: The payload to check
            vuln_type: Vulnerability type
            
        Returns:
            Tuple of (is_blocked, list_of_matching_pattern_names)
        """
        patterns = KEYWORD_PATTERNS.get(vuln_type, [])
        matching = []
        
        for i, pattern in enumerate(patterns):
            try:
                if re.search(pattern, payload):
                    matching.append(f"kw_{vuln_type}_{i}")
            except re.error:
                continue
        
        return len(matching) > 0, matching
    
    def is_blocked_any(
        self,
        payload: str,
        vuln_type: str,
        location: str = "parameter"
    ) -> Tuple[bool, List[str], str]:
        """
        Check payload using both keyword and F5 patterns.
        
        Args:
            payload: The payload to check
            vuln_type: Vulnerability type
            location: Where the payload is
            
        Returns:
            Tuple of (is_blocked, pattern_ids, detection_source)
            detection_source is "keywords", "f5", or "none"
        """
        # Try keyword patterns first (faster)
        kw_blocked, kw_patterns = self.is_blocked_keywords(payload, vuln_type)
        if kw_blocked:
            return True, kw_patterns, "keywords"
        
        # Try F5 patterns
        f5_blocked, f5_patterns = self.is_blocked(payload, vuln_type, location)
        if f5_blocked:
            return True, f5_patterns, "f5"
        
        return False, [], "none"

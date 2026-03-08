"""
Tests for WAF Evasion Transforms
================================
Phase 4: TDD - Semantic-preserving payload transformations.
"""

import pytest


class TestSQLiTransforms:
    """Tests pour les transformations SQLi."""
    
    def test_sqli_case_swap(self):
        """Test alternance de casse: UNION → uNiOn."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("UNION SELECT", "case_swap", "sqli")
        
        assert result != "UNION SELECT"
        assert result.upper() == "UNION SELECT"
    
    def test_sqli_inline_comment(self):
        """Test commentaires inline: UNION → UN/**/ION."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("UNION SELECT", "inline_comment", "sqli")
        
        assert "/**/" in result or "/*" in result
    
    def test_sqli_whitespace_substitute(self):
        """Test substitution espaces: UNION SELECT → UNION/**/SELECT."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("UNION SELECT", "whitespace_substitute", "sqli")
        
        assert " " not in result or "/**/" in result or "%09" in result or "%0a" in result
    
    def test_sqli_url_encode(self):
        """Test URL encoding."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("' OR 1=1--", "url_encode", "sqli")
        
        assert "%" in result
    
    def test_sqli_double_url_encode(self):
        """Test double URL encoding."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("'", "double_url_encode", "sqli")
        
        assert "%25" in result  # % encoded as %25
    
    def test_sqli_hex_encode(self):
        """Test hex encoding de strings."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("admin", "hex_encode", "sqli")
        
        assert "0x" in result.lower() or "\\x" in result
    
    def test_sqli_char_function(self):
        """Test utilisation CHAR()."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("admin", "char_function", "sqli")
        
        assert "CHAR(" in result.upper() or "CHR(" in result.upper()
    
    def test_sqli_concat_split(self):
        """Test split avec CONCAT."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("admin", "concat_split", "sqli")
        
        assert "CONCAT(" in result.upper() or "||" in result or "+" in result


class TestXSSTransforms:
    """Tests pour les transformations XSS."""
    
    def test_xss_tag_case_mix(self):
        """Test mix de casse: <script> → <ScRiPt>."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("<script>", "tag_case_mix", "xss")
        
        assert result.lower() == "<script>"
        assert result != "<script>"
    
    def test_xss_null_bytes(self):
        """Test insertion null bytes."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("<script>", "null_bytes", "xss")
        
        assert "%00" in result or "\x00" in result or "\\x00" in result
    
    def test_xss_event_handler_swap(self):
        """Test swap event handlers."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("onerror=alert(1)", "event_case_swap", "xss")
        
        # Should be case-swapped
        assert result.lower() == "onerror=alert(1)"
    
    def test_xss_svg_payload(self):
        """Test conversion vers SVG."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("alert(1)", "svg_payload", "xss")
        
        assert "<svg" in result.lower()


class TestCMDiTransforms:
    """Tests pour les transformations Command Injection."""
    
    def test_cmdi_variable_substitution(self):
        """Test substitution variables: cat → c${x}at."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("cat", "variable_sub", "cmdi")
        
        assert "${" in result or "$" in result
    
    def test_cmdi_ifs_substitution(self):
        """Test IFS: cat /etc → cat$IFS/etc."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("cat /etc/passwd", "ifs_sub", "cmdi")
        
        assert "$IFS" in result or "${IFS}" in result
    
    def test_cmdi_quote_insertion(self):
        """Test insertion quotes: cat → c'a't."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("cat", "quote_insert", "cmdi")
        
        assert "'" in result or '"' in result
    
    def test_cmdi_wildcard_expansion(self):
        """Test wildcards: /bin/cat → /???/c?t."""
        from ghost_hunter.core.evasion.transforms import apply_transform
        
        result = apply_transform("/bin/cat", "wildcard", "cmdi")
        
        assert "?" in result or "*" in result


class TestTransformPreservation:
    """Tests que les transformations préservent la sémantique."""
    
    def test_transform_preserves_semantic(self):
        """Test que le payload reste fonctionnel."""
        from ghost_hunter.core.evasion.transforms import get_transform_info
        
        info = get_transform_info("case_swap", "sqli")
        
        assert info is not None
        assert info.get("preserves_semantic", False) is True
    
    def test_transform_chain_multiple(self):
        """Test chaînage de transformations."""
        from ghost_hunter.core.evasion.transforms import apply_transforms_chain
        
        result = apply_transforms_chain(
            "UNION SELECT",
            ["case_swap", "whitespace_substitute"],
            "sqli"
        )
        
        # Should have both transforms applied
        assert result != "UNION SELECT"

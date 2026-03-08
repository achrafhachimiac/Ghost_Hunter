"""
Tests for WAF Checker
=====================
Phase 3: TDD - WAF simulation with is_blocked()
"""

import pytest
from pathlib import Path


# Module-level shared checker for performance
_checker = None

@pytest.fixture(scope="module")
def checker():
    """Shared WAF Checker instance for all tests in module."""
    global _checker
    if _checker is None:
        from ghost_hunter.core.evasion.checker import WAFChecker
        _checker = WAFChecker()
    return _checker


class TestWAFCheckerLoad:
    """Tests pour le chargement des patterns."""
    
    def test_load_patterns_from_yaml(self, checker):
        """Test chargement des patterns depuis YAML."""
        assert checker.patterns is not None
        assert len(checker.patterns) > 0
        
        # Should have main categories
        assert "sqli" in checker.patterns or "cmdi" in checker.patterns
    
    def test_compile_regex_patterns(self, checker):
        """Test que les regex sont compilées."""
        # Should have compiled patterns
        assert hasattr(checker, '_compiled')
        assert len(checker._compiled) > 0


class TestWAFCheckerSQLi:
    """Tests pour la détection SQLi."""
    
    def test_sqli_union_select_blocked(self, checker):
        """Test que UNION SELECT est bloqué."""
        blocked, patterns, source = checker.is_blocked_any(
            "' UNION SELECT * FROM users--",
            "sqli"
        )
        
        assert blocked is True
        assert len(patterns) > 0
    
    def test_sqli_basic_select_blocked(self, checker):
        """Test que SELECT FROM est bloqué."""
        blocked, patterns, source = checker.is_blocked_any(
            "'; SELECT password FROM users--",
            "sqli"
        )
        
        assert blocked is True


class TestWAFCheckerXSS:
    """Tests pour la détection XSS."""
    
    def test_xss_script_tag_blocked(self, checker):
        """Test que <script> est bloqué."""
        blocked, patterns, source = checker.is_blocked_any(
            "<script>alert(1)</script>",
            "xss"
        )
        
        assert blocked is True
    
    def test_xss_event_handler_blocked(self, checker):
        """Test que onerror est bloqué."""
        blocked, patterns, source = checker.is_blocked_any(
            '<img src=x onerror="alert(1)">',
            "xss"
        )
        
        assert blocked is True


class TestWAFCheckerCMDi:
    """Tests pour la détection Command Injection."""
    
    def test_cmdi_bash_blocked(self, checker):
        """Test que /bin/bash est bloqué."""
        blocked, patterns, source = checker.is_blocked_any(
            "/bin/bash -c 'cat /etc/passwd'",
            "cmdi"
        )
        
        assert blocked is True
    
    def test_cmdi_semicolon_blocked(self, checker):
        """Test que ; command est bloqué."""
        blocked, patterns, source = checker.is_blocked_any(
            "; cat /etc/passwd",
            "cmdi"
        )
        
        assert blocked is True


class TestWAFCheckerSSTI:
    """Tests pour la détection SSTI."""
    
    def test_ssti_jinja_blocked(self, checker):
        """Test que {{...}} est bloqué."""
        blocked, patterns, source = checker.is_blocked_any(
            "{{7*7}}",
            "ssti"
        )
        
        assert blocked is True


class TestWAFCheckerBenign:
    """Tests pour les payloads bénins."""
    
    def test_benign_payload_not_blocked(self, checker):
        """Test qu'un payload normal n'est pas bloqué."""
        blocked, patterns, source = checker.is_blocked_any(
            "hello world",
            "sqli"
        )
        
        assert blocked is False
        assert len(patterns) == 0


class TestWAFCheckerOptions:
    """Tests pour les options du checker."""
    
    def test_location_parameter_vs_header(self, checker):
        """Test que la location est prise en compte."""
        # Test with parameter location
        blocked_param, _, _ = checker.is_blocked_any(
            "UNION SELECT",
            "sqli",
            location="parameter"
        )
        
        # Should be blocked in parameters
        assert blocked_param is True
    
    def test_case_insensitivity(self, checker):
        """Test que la détection est case-insensitive."""
        # Lowercase
        blocked1, _, _ = checker.is_blocked_any("union select * from users", "sqli")
        # Uppercase  
        blocked2, _, _ = checker.is_blocked_any("UNION SELECT * FROM users", "sqli")
        # Mixed
        blocked3, _, _ = checker.is_blocked_any("UnIoN SeLeCt * FrOm users", "sqli")
        
        # All should be detected
        assert blocked1 is True
        assert blocked2 is True
        assert blocked3 is True
    
    def test_check_all_vuln_types(self, checker):
        """Test check_all() contre tous les types."""
        result = checker.check_all("' UNION SELECT * FROM users; cat /etc/passwd")
        
        assert isinstance(result, dict)
        assert "sqli" in result
        assert "cmdi" in result
    
    def test_returns_matching_pattern_ids(self, checker):
        """Test que les IDs des patterns matchés sont retournés."""
        blocked, patterns, source = checker.is_blocked_any(
            "' UNION SELECT * FROM users--",
            "sqli"
        )
        
        assert blocked is True
        assert len(patterns) > 0
        # Pattern IDs should have a prefix
        for p in patterns:
            assert p.startswith("f5_") or p.startswith("kw_"), f"Pattern ID {p} has unexpected prefix"

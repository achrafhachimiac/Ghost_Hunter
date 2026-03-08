"""
Tests pour prompts/formatters.py

TDD: Validation des fonctions de formatage.
"""

import pytest
from ghost_hunter.core.brain.strategist_v2.contracts import (
    AttemptResult,
    SecurityProfile,
)
from ghost_hunter.core.brain.strategist_v2.prompts.formatters import (
    format_headers,
    format_body,
    format_test,
    format_list,
    format_encoding_stats,
    format_security_profile,
    format_round_summary,
    _mask_sensitive_value,
    _truncate,
)


class TestFormatHeaders:
    """Tests pour format_headers."""
    
    def test_empty_headers(self):
        """Retourne message si pas de headers."""
        result = format_headers({})
        assert result == "_No headers_"
    
    def test_simple_headers(self):
        """Formate des headers simples."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        result = format_headers(headers)
        assert "| Header | Value |" in result
        assert "Content-Type" in result
        assert "application/json" in result
    
    def test_priority_headers_first(self):
        """Les headers prioritaires sont en premier."""
        headers = {
            "X-Custom": "custom",
            "Authorization": "Bearer token123",
            "Accept": "application/json"
        }
        result = format_headers(headers)
        lines = result.split("\n")
        
        # Authorization doit apparaître avant X-Custom
        auth_line = next(i for i, l in enumerate(lines) if "Authorization" in l)
        custom_line = next(i for i, l in enumerate(lines) if "X-Custom" in l)
        assert auth_line < custom_line
    
    def test_max_headers_limit(self):
        """Limite le nombre de headers affichés."""
        headers = {f"Header-{i}": f"value-{i}" for i in range(20)}
        result = format_headers(headers, max_headers=5)
        assert "...and 15 more" in result


class TestMaskSensitiveValue:
    """Tests pour _mask_sensitive_value."""
    
    def test_masks_authorization(self):
        """Masque partiellement Authorization."""
        value = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        result = _mask_sensitive_value("Authorization", value)
        assert "Bearer eyJ" in result
        assert "..." in result
    
    def test_no_mask_short_value(self):
        """Ne masque pas les valeurs courtes."""
        value = "Bearer short"
        result = _mask_sensitive_value("Authorization", value)
        assert result == value
    
    def test_truncates_long_value(self):
        """Tronque les valeurs très longues."""
        value = "x" * 100
        result = _mask_sensitive_value("X-Custom", value)
        assert len(result) == 50
        assert result.endswith("...")


class TestFormatBody:
    """Tests pour format_body."""
    
    def test_empty_body(self):
        """Retourne message si pas de body."""
        assert format_body(None) == "_No body_"
        assert format_body("") == "_No body_"
    
    def test_simple_body(self):
        """Formate un body simple."""
        body = '{"id": 123}'
        result = format_body(body)
        assert "```" in result
        assert '{"id": 123}' in result
    
    def test_truncates_long_body(self):
        """Tronque les bodies longs."""
        body = "x" * 1000
        result = format_body(body, max_length=100)
        assert "truncated" in result
        assert "1000 total chars" in result


class TestFormatTest:
    """Tests pour format_test."""
    
    def test_blocked_test(self):
        """Formate un test bloqué par WAF."""
        test = AttemptResult(
            payload_original="' OR 1=1--",
            payload_sent="%27%20OR%201%3D1--",
            encoding="url",
            injection_point="id",
            method="GET",
            url="http://test",
            status_code=403,
            response_time_ms=150.5,
            response_length=1234,
            waf_blocked=True,
            waf_provider="cloudflare",
            waf_signature="SQL injection"
        )
        result = format_test(test, 1)
        
        assert "### Test 1" in result
        assert "❌ BLOCKED" in result
        assert "cloudflare" in result
        assert "url" in result
    
    def test_passed_interesting_test(self):
        """Formate un test passé et intéressant."""
        test = AttemptResult(
            payload_original="124",
            payload_sent="124",
            encoding="none",
            injection_point="user_id",
            method="GET",
            url="http://test",
            status_code=200,
            response_time_ms=89,
            response_length=5678,
            waf_blocked=False,
            is_interesting=True,
            diff_indicators=["content_changed", "different_user_data"]
        )
        result = format_test(test, 2)
        
        assert "### Test 2" in result
        assert "✅ PASSED" in result
        assert "🎯 YES" in result
        assert "content_changed" in result
    
    def test_with_response_snippet(self):
        """Inclut le snippet de réponse."""
        test = AttemptResult(
            payload_original="test",
            payload_sent="test",
            encoding="none",
            injection_point="x",
            method="GET",
            url="http://test",
            status_code=200,
            response_time_ms=100,
            response_length=100,
            response_snippet='{"error": "Access denied"}'
        )
        result = format_test(test, 1)
        
        assert "Response snippet" in result
        assert "Access denied" in result


class TestTruncate:
    """Tests pour _truncate."""
    
    def test_no_truncate_short(self):
        """Ne tronque pas les textes courts."""
        assert _truncate("hello", 10) == "hello"
    
    def test_truncate_long(self):
        """Tronque les textes longs."""
        result = _truncate("hello world", 8)
        assert result == "hello..."
        assert len(result) == 8


class TestFormatList:
    """Tests pour format_list."""
    
    def test_empty_list(self):
        """Retourne message si liste vide."""
        assert format_list([]) == "_None_"
    
    def test_simple_list(self):
        """Formate une liste simple."""
        items = ["item1", "item2", "item3"]
        result = format_list(items)
        
        assert "- item1" in result
        assert "- item2" in result
        assert "- item3" in result
    
    def test_custom_bullet(self):
        """Utilise un bullet custom."""
        items = ["a", "b"]
        result = format_list(items, bullet="*")
        assert "* a" in result
    
    def test_max_items(self):
        """Limite le nombre d'items."""
        items = [f"item{i}" for i in range(20)]
        result = format_list(items, max_items=5)
        assert "...and 15 more" in result


class TestFormatEncodingStats:
    """Tests pour format_encoding_stats."""
    
    def test_empty_stats(self):
        """Retourne message si pas de stats."""
        assert format_encoding_stats({}) == "_No encoding stats_"
    
    def test_with_stats(self):
        """Formate les stats correctement."""
        stats = {
            "url": {"blocked": 3, "passed": 7},
            "unicode": {"blocked": 1, "passed": 9}
        }
        result = format_encoding_stats(stats)
        
        assert "| Encoding | Blocked | Passed | Success Rate |" in result
        assert "url" in result
        assert "70%" in result  # 7/10 pour url
        assert "unicode" in result
        assert "90%" in result  # 9/10 pour unicode
    
    def test_zero_total(self):
        """Gère le cas total = 0."""
        stats = {"none": {"blocked": 0, "passed": 0}}
        result = format_encoding_stats(stats)
        assert "N/A" in result


class TestFormatSecurityProfile:
    """Tests pour format_security_profile."""
    
    def test_empty_profile(self):
        """Retourne message si rien détecté."""
        profile = SecurityProfile()
        result = format_security_profile(profile)
        assert result == "_No security measures detected_"
    
    def test_full_profile(self):
        """Formate un profil complet."""
        profile = SecurityProfile(
            waf="cloudflare",
            cdn="cloudflare",
            rate_limit=True,
            anti_bot="datadome"
        )
        result = format_security_profile(profile)
        
        assert "🛡️ **WAF:** cloudflare" in result
        assert "🌐 **CDN:** cloudflare" in result
        assert "⏱️ **Rate Limiting:** Detected" in result
        assert "🤖 **Anti-Bot:** datadome" in result
    
    def test_partial_profile(self):
        """Formate un profil partiel."""
        profile = SecurityProfile(waf="aws_waf")
        result = format_security_profile(profile)
        
        assert "aws_waf" in result
        assert "CDN" not in result


class TestFormatRoundSummary:
    """Tests pour format_round_summary."""
    
    def test_no_tests(self):
        """Gère le cas sans tests."""
        result = format_round_summary(1, 0, 0, 0, 0)
        assert "No tests executed" in result
    
    def test_with_stats(self):
        """Formate un résumé complet."""
        result = format_round_summary(
            round_number=2,
            blocked=3,
            passed=7,
            interesting=2,
            total=10
        )
        
        assert "Round 2 Summary" in result
        assert "Total tests: 10" in result
        assert "Blocked by WAF: 3 (30%)" in result
        assert "Passed WAF: 7" in result
        assert "Interesting results: 2" in result

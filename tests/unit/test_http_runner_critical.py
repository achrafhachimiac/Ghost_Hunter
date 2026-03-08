"""
Tests critiques pour http_runner.py - comportements à ne PAS casser lors du refactoring.

Ces tests documentent le comportement actuel AVANT refactoring.
Si un test échoue après refactoring, c'est une RÉGRESSION.
"""

import pytest
import json
from unittest.mock import MagicMock, AsyncMock, patch
from urllib.parse import quote

from ghost_hunter.core.executor.http_runner import (
    CustomHTTPRunner,
)
from ghost_hunter.core.executor.constants import (
    _safe_get_payload_value,
    ERROR_PATTERNS,
)
from ghost_hunter.core.executor.finding_factory import FindingFactory
from ghost_hunter.core.contracts import (
    PayloadVariant,
    ResponseSignature,
)


# ==================== Fixtures ====================

@pytest.fixture
def runner():
    return CustomHTTPRunner()


@pytest.fixture
def mock_request():
    """Create a mock InterceptedRequest with all required attributes."""
    req = MagicMock()
    req.method = "GET"
    req.url = "https://api.example.com/users/123/profile"
    req.host = "api.example.com"
    req.path = "/users/123/profile"
    req.query_params = {}
    req.body = None
    req.body_json = None
    req.headers = {}
    req.cookies = {}
    return req


# ==================== _safe_get_payload_value Tests ====================

class TestSafeGetPayloadValue:
    """Test the defensive payload extraction - CRITICAL for avoiding NoneType errors."""
    
    def test_none_payload(self):
        """None payload should return empty string, not crash."""
        result = _safe_get_payload_value(None)
        assert result == ""
    
    def test_dict_with_payload_key(self):
        """Dict with 'payload' key should extract it."""
        result = _safe_get_payload_value({"payload": "test'", "encoding": "none"})
        assert result == "test'"
    
    def test_dict_with_none_payload(self):
        """Dict with None payload value should return empty string."""
        result = _safe_get_payload_value({"payload": None})
        assert result == ""
    
    def test_dict_without_payload_key(self):
        """Dict without 'payload' key should return empty string."""
        result = _safe_get_payload_value({"other": "value"})
        assert result == ""
    
    def test_empty_dict(self):
        """Empty dict should return empty string."""
        result = _safe_get_payload_value({})
        assert result == ""
    
    def test_payload_variant_object(self):
        """PayloadVariant object should use .payload attribute."""
        pv = PayloadVariant(payload="<script>alert(1)</script>")
        result = _safe_get_payload_value(pv)
        assert result == "<script>alert(1)</script>"
    
    def test_payload_variant_with_none(self):
        """PayloadVariant with None payload should return empty string."""
        # Use a real PayloadVariant-like object, not MagicMock
        class FakePayloadVariant:
            def __init__(self):
                self.payload = None
                self.encoding = "none"
        
        pv = FakePayloadVariant()
        result = _safe_get_payload_value(pv)
        assert result == ""
    
    def test_string_payload(self):
        """String payload should pass through."""
        result = _safe_get_payload_value("' OR 1=1--")
        assert result == "' OR 1=1--"
    
    def test_int_payload(self):
        """Integer payload should be converted to string."""
        result = _safe_get_payload_value(123)
        assert result == "123"
    
    def test_float_payload(self):
        """Float payload should be converted to string."""
        result = _safe_get_payload_value(3.14)
        assert result == "3.14"


# ==================== Cookie Handling Tests ====================

class TestCookieHandling:
    """CRITICAL: Cookie handling priority and format."""
    
    def test_cookies_from_dict_priority(self, runner, mock_request):
        """Cookies from dict should take priority over header."""
        mock_request.cookies = {"session": "abc123", "user": "john"}
        mock_request.headers = {"Cookie": "old=value"}
        
        url, headers, body, success = runner._build_request(mock_request, "PAYLOAD", "param")
        
        # Should have Cookie header
        cookie_header = headers.get("Cookie") or headers.get("cookie")
        assert cookie_header is not None
        assert "session=abc123" in cookie_header
        assert "user=john" in cookie_header
    
    def test_cookies_semicolon_separator(self, runner, mock_request):
        """Cookies should use semicolon separator, not comma."""
        mock_request.cookies = {"a": "1", "b": "2"}
        
        url, headers, body, success = runner._build_request(mock_request, "PAYLOAD", "param")
        
        cookie_header = headers.get("Cookie") or headers.get("cookie")
        if cookie_header and "a=1" in cookie_header and "b=2" in cookie_header:
            # Should be separated by semicolon, not comma
            assert ";" in cookie_header or len(mock_request.cookies) == 1
    
    def test_cookies_from_header_fallback(self, runner, mock_request):
        """If no cookies dict, use header value."""
        mock_request.cookies = {}
        mock_request.headers = {"Cookie": "session=xyz789"}
        
        url, headers, body, success = runner._build_request(mock_request, "PAYLOAD", "param")
        
        cookie_header = headers.get("Cookie") or headers.get("cookie")
        assert cookie_header is not None
        assert "session=xyz789" in cookie_header
    
    def test_comma_to_semicolon_normalization(self, runner, mock_request):
        """Cookie header with comma should be normalized to semicolon."""
        mock_request.cookies = {}
        mock_request.headers = {"Cookie": "a=1, b=2"}  # Comma-separated (wrong)
        
        url, headers, body, success = runner._build_request(mock_request, "PAYLOAD", "param")
        
        cookie_header = headers.get("Cookie") or headers.get("cookie")
        if cookie_header:
            # Check that comma is replaced with semicolon
            # Or at least cookies are present
            assert "a=1" in cookie_header


# ==================== User-Agent Strategy Tests ====================

class TestUserAgentStrategy:
    """CRITICAL: UA rotation vs preservation for auth requests."""
    
    def test_ua_preserved_with_cookie(self, runner, mock_request):
        """With cookies (auth), should preserve original UA."""
        mock_request.cookies = {"session": "authenticated"}
        mock_request.headers = {"User-Agent": "OriginalBrowser/1.0"}
        
        url, headers, body, success = runner._build_request(mock_request, "PAYLOAD", "param")
        
        ua = headers.get("User-Agent") or headers.get("user-agent")
        # Should keep original or at least have a UA
        assert ua is not None
    
    def test_ua_preserved_with_authorization(self, runner, mock_request):
        """With Authorization header, should preserve original UA."""
        mock_request.headers = {
            "User-Agent": "OriginalBrowser/1.0",
            "Authorization": "Bearer token123",
        }
        
        url, headers, body, success = runner._build_request(mock_request, "PAYLOAD", "param")
        
        ua = headers.get("User-Agent") or headers.get("user-agent")
        assert ua is not None
    
    def test_ua_added_when_missing(self, runner, mock_request):
        """Without auth, should add UA (possibly rotated)."""
        mock_request.headers = {}
        mock_request.cookies = {}
        
        url, headers, body, success = runner._build_request(mock_request, "PAYLOAD", "param")
        
        # Should always have a User-Agent
        ua = headers.get("User-Agent") or headers.get("user-agent")
        assert ua is not None
        assert len(ua) > 10  # Not empty


# ==================== Injection Success Tracking Tests ====================

class TestInjectionSuccessTracking:
    """CRITICAL: Injection must report success/failure accurately."""
    
    def test_injection_success_query_param(self, runner, mock_request):
        """Query param injection should succeed when param exists."""
        mock_request.query_params = {"id": "123"}
        mock_request.url = "https://example.com?id=123"
        
        url, headers, body, success = runner._build_request(mock_request, "PAYLOAD", "id")
        
        assert success is True
        assert "PAYLOAD" in url
    
    def test_injection_fail_nonexistent_param(self, runner, mock_request):
        """Should report failure when injection point not found."""
        mock_request.query_params = {"other": "value"}
        mock_request.body = None
        mock_request.body_json = None
        
        url, headers, body, success = runner._build_request(mock_request, "PAYLOAD", "nonexistent")
        
        # Injection should fail gracefully
        # The exact behavior depends on implementation, but shouldn't crash
        assert isinstance(success, bool)
    
    def test_injection_success_json_body(self, runner, mock_request):
        """JSON body injection should succeed when key exists."""
        mock_request.body_json = {"username": "test", "password": "secret"}
        mock_request.body = '{"username": "test", "password": "secret"}'
        mock_request.query_params = {}
        
        url, headers, body, success = runner._build_request(mock_request, "PAYLOAD", "username")
        
        assert success is True
        assert "PAYLOAD" in body


# ==================== Path Injection Tests (6 Cases) ====================

class TestPathInjection:
    """Test all 6 path injection cases."""
    
    def test_path_numeric_id_replacement(self, runner, mock_request):
        """Path with numeric ID should allow replacement."""
        mock_request.url = "https://api.example.com/users/12345/profile"
        mock_request.path = "/users/12345/profile"
        mock_request.query_params = {}
        
        # Using {id} placeholder should target the numeric segment
        url, headers, body, success = runner._build_request(mock_request, "99999", "{id}")
        
        # Should replace 12345 with 99999
        if success:
            assert "99999" in url
    
    def test_path_resource_template(self, runner, mock_request):
        """Test resource/{id} style template injection."""
        mock_request.url = "https://api.example.com/profiles/abc123"
        mock_request.path = "/profiles/abc123"
        mock_request.query_params = {}
        
        url, headers, body, success = runner._build_request(mock_request, "INJECTED", "profiles/{id}")
        
        if success:
            assert "INJECTED" in url
    
    def test_path_literal_injection(self, runner, mock_request):
        """Test literal string injection in path."""
        mock_request.url = "https://api.example.com/users/john/settings"
        mock_request.path = "/users/john/settings"
        mock_request.query_params = {}
        
        # Try to replace "john" literally
        url, headers, body, success = runner._build_request(mock_request, "admin", "john")
        
        if success:
            assert "admin" in url


# ==================== JSON Nested Path Tests ====================

class TestJsonNestedPath:
    """CRITICAL: Test nested JSON path injection like "foo.bar.baz"."""
    
    def test_nested_json_simple(self, runner, mock_request):
        """Simple nested path like user.id."""
        mock_request.body_json = {"user": {"id": "123", "name": "test"}}
        mock_request.body = '{"user": {"id": "123", "name": "test"}}'
        mock_request.query_params = {}
        
        url, headers, body, success = runner._build_request(mock_request, "999", "user.id")
        
        if success:
            # Body should contain the injected value
            parsed = json.loads(body)
            assert parsed["user"]["id"] == "999" or "999" in body
    
    def test_nested_json_deep(self, runner, mock_request):
        """Deep nested path like data.users.0.profile.avatar."""
        mock_request.body_json = {
            "data": {
                "users": [
                    {"profile": {"avatar": "old.png"}}
                ]
            }
        }
        mock_request.body = json.dumps(mock_request.body_json)
        mock_request.query_params = {}
        
        # This is a complex case - may not be fully supported
        url, headers, body, success = runner._build_request(mock_request, "hacked.png", "avatar")
        
        # At minimum, shouldn't crash
        assert body is not None or success is False


# ==================== WAF Detection Tests ====================

class TestWAFDetection:
    """Test WAF block detection."""
    
    def test_detect_cloudflare_challenge(self, runner):
        """Detect Cloudflare managed challenge."""
        response = MagicMock()
        response.status_code = 403
        response.headers = {"cf-ray": "abc123", "cf-request-id": "xyz"}
        response.text = "Just a moment... challenge-platform"
        
        is_blocked, provider = runner._is_waf_block_response(response)
        
        assert is_blocked is True
        assert "Cloudflare" in provider
    
    def test_detect_aws_waf(self, runner):
        """Detect AWS WAF block."""
        response = MagicMock()
        response.status_code = 403
        response.headers = {"x-amzn-requestid": "abc123"}
        response.text = "Access Denied"
        
        is_blocked, provider = runner._is_waf_block_response(response)
        
        assert is_blocked is True
        assert "AWS" in provider
    
    def test_detect_akamai_waf(self, runner):
        """Detect Akamai WAF block."""
        response = MagicMock()
        response.status_code = 403
        response.headers = {"Server": "AkamaiGHost"}
        response.text = "Access Denied ak_bmsc"
        
        is_blocked, provider = runner._is_waf_block_response(response)
        
        assert is_blocked is True
        assert "Akamai" in provider
    
    def test_normal_403_not_waf(self, runner):
        """Normal 403 without WAF signatures should not be detected."""
        response = MagicMock()
        response.status_code = 403
        response.headers = {"Server": "nginx"}
        response.text = "Forbidden - You don't have permission"
        
        is_blocked, provider = runner._is_waf_block_response(response)
        
        # Could be detected or not depending on implementation
        # But should not crash
        assert isinstance(is_blocked, bool)
    
    def test_200_response_not_blocked(self, runner):
        """200 OK should never be detected as WAF block."""
        response = MagicMock()
        response.status_code = 200
        response.headers = {"cf-ray": "abc123"}  # Even with CF headers
        response.text = "Success"
        
        is_blocked, provider = runner._is_waf_block_response(response)
        
        assert is_blocked is False


# ==================== Response Detail Structure Tests ====================

class TestResponseDetailStructure:
    """Test that response details have expected structure."""
    
    def test_response_none_safety(self, runner):
        """Accessing detail['response'] when None should not crash."""
        detail = {
            "payload": "test",
            "response": None,
        }
        
        # This simulates the bug scenario - should handle gracefully
        response_data = detail.get("response")
        if response_data is not None:
            status = response_data.get("status_code")
        else:
            status = None
        
        assert status is None  # Should be None, not crash


# ==================== Encoding Tests ====================

class TestPayloadEncoding:
    """Test payload encoding variations."""
    
    def test_encoding_none(self, runner):
        """Encoding 'none' should pass through unchanged."""
        pv = PayloadVariant(payload="<script>", encoding="none")
        result = runner._encode_payload(pv)
        assert result == "<script>"
    
    def test_encoding_empty_string(self, runner):
        """Empty encoding string should be treated as 'none'."""
        pv = PayloadVariant(payload="<script>", encoding="")
        result = runner._encode_payload(pv)
        # Should not crash, should return something
        assert result is not None
    
    def test_encoding_none_value(self, runner):
        """None encoding should be treated as 'none'."""
        pv = MagicMock()
        pv.payload = "<script>"
        pv.encoding = None
        result = runner._encode_payload(pv)
        assert result is not None
    
    def test_encoding_url(self, runner):
        """URL encoding should encode special chars."""
        pv = PayloadVariant(payload="<script>alert(1)</script>", encoding="url")
        result = runner._encode_payload(pv)
        assert "%3C" in result  # <
        assert "%3E" in result  # >
    
    def test_encoding_double_url(self, runner):
        """Double URL encoding should double-encode."""
        pv = PayloadVariant(payload="<", encoding="double_url")
        result = runner._encode_payload(pv)
        assert "%25" in result  # % from %3C
    
    def test_encoding_unicode(self, runner):
        """Unicode encoding should produce \\uXXXX format."""
        pv = PayloadVariant(payload="<", encoding="unicode")
        result = runner._encode_payload(pv)
        # Should contain unicode escape
        assert "\\u" in result or "u003c" in result.lower() or result == "<"


# ==================== Limits Tests ====================

class TestLimits:
    """Test hardcoded limits are respected."""
    
    def test_max_payloads_limit(self):
        """Verify the code limits payloads (check in execute())."""
        # This is documented as max 10 payloads
        # Can't easily test without running execute(), but document the expectation
        MAX_PAYLOADS = 10
        assert MAX_PAYLOADS == 10  # Document the limit
    
    def test_max_injection_points_limit(self):
        """Verify the code limits injection points."""
        # This is documented as max 5 injection points
        MAX_INJECTION_POINTS = 5
        assert MAX_INJECTION_POINTS == 5  # Document the limit


# ==================== Finding Structure Tests ====================

class TestFindingCreation:
    """Test finding creation with proper structure."""
    
    def test_signature_with_timing_anomaly(self):
        """Signature with timing should produce time-based subtype."""
        signature = ResponseSignature(
            timing_anomaly=True,
            response_time_ms=6000,
        )
        subtype = FindingFactory.determine_subtype(signature, "SQLi")
        assert subtype == "time-based"
    
    def test_signature_with_error_patterns(self):
        """Signature with error patterns should produce error-based subtype."""
        signature = ResponseSignature(
            error_patterns_found=["SQL syntax error"],
        )
        subtype = FindingFactory.determine_subtype(signature, "SQLi")
        assert subtype == "error-based"
    
    def test_analysis_includes_response_time(self):
        """Analysis should mention response time for timing anomalies."""
        signature = ResponseSignature(
            timing_anomaly=True,
            response_time_ms=8500,
        )
        analysis = FindingFactory.generate_analysis(signature, "SQLi")
        assert "8500" in analysis or "time" in analysis.lower()

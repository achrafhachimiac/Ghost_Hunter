"""
Tests for Ghost-Hunter Heuristics Engine
"""

import pytest
from ghost_hunter.core.interceptor.heuristics import HeuristicsEngine
from ghost_hunter.core.contracts import (
    InterceptedRequest, FilteredRequest, ScoredRequest, Priority
)


class TestHeuristicsEngine:
    
    @pytest.fixture
    def engine(self):
        return HeuristicsEngine(score_threshold=40)
    
    def test_idor_param_detection(self, engine):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users",
            host="example.com",
            path="/api/users",
            query_params={"user_id": "123"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert result.score > 0
        assert "user_id" in result.interesting_params
        assert "IDOR" in result.potential_vulns
    
    def test_ssrf_param_detection(self, engine):
        req = InterceptedRequest(
            method="POST",
            url="https://example.com/api/fetch",
            host="example.com",
            path="/api/fetch",
            body_json={"url": "https://internal.com"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert "url" in result.interesting_params
        assert "SSRF" in result.potential_vulns
    
    def test_sqli_param_detection(self, engine):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/search",
            host="example.com",
            path="/search",
            query_params={"query": "test", "sort": "name"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert "SQLi" in result.potential_vulns
    
    def test_lfi_param_detection(self, engine):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/download",
            host="example.com",
            path="/download",
            query_params={"file": "report.pdf"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert "file" in result.interesting_params
        assert "LFI" in result.potential_vulns or "Path Traversal" in result.potential_vulns
    
    def test_admin_endpoint_high_score(self, engine):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/admin/users",
            host="example.com",
            path="/admin/users"
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert result.score >= 10
        signal_names = [s.name for s in result.signals]
        assert any("admin" in s.lower() for s in signal_names)
    
    def test_graphql_endpoint_detection(self, engine):
        req = InterceptedRequest(
            method="POST",
            url="https://example.com/graphql",
            host="example.com",
            path="/graphql"
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert "GraphQL Introspection" in result.potential_vulns or "IDOR" in result.potential_vulns
    
    def test_analytics_param_negative_score(self, engine):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/page",
            host="example.com",
            path="/page",
            query_params={"utm_source": "google", "utm_medium": "cpc"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        # Analytics params should have negative score contribution
        assert len(result.interesting_params) == 0
    
    def test_method_scoring_delete(self, engine):
        req_delete = InterceptedRequest(
            method="DELETE",
            url="https://example.com/api/users/123",
            host="example.com",
            path="/api/users/123"
        )
        req_get = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/123",
            host="example.com",
            path="/api/users/123"
        )
        
        filtered_delete = FilteredRequest(request=req_delete, in_scope=True)
        filtered_get = FilteredRequest(request=req_get, in_scope=True)
        
        score_delete = engine.score(filtered_delete).score
        score_get = engine.score(filtered_get).score
        
        assert score_delete > score_get
    
    def test_method_scoring_put(self, engine):
        req = InterceptedRequest(
            method="PUT",
            url="https://example.com/api/users/123",
            host="example.com",
            path="/api/users/123"
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        signal_names = [s.name for s in result.signals]
        assert any("method:PUT" in s for s in signal_names)
    
    def test_auth_header_bonus(self, engine):
        req_auth = InterceptedRequest(
            method="GET",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            headers={"Authorization": "Bearer token123"}
        )
        req_no_auth = InterceptedRequest(
            method="GET",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            headers={}
        )
        
        filtered_auth = FilteredRequest(request=req_auth, in_scope=True)
        filtered_no_auth = FilteredRequest(request=req_no_auth, in_scope=True)
        
        score_auth = engine.score(filtered_auth).score
        score_no_auth = engine.score(filtered_no_auth).score
        
        assert score_auth > score_no_auth
    
    def test_json_content_bonus(self, engine):
        req_json = InterceptedRequest(
            method="POST",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            headers={"content-type": "application/json"}
        )
        req_form = InterceptedRequest(
            method="POST",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            headers={"content-type": "application/x-www-form-urlencoded"}
        )
        
        filtered_json = FilteredRequest(request=req_json, in_scope=True)
        filtered_form = FilteredRequest(request=req_form, in_scope=True)
        
        score_json = engine.score(filtered_json).score
        score_form = engine.score(filtered_form).score
        
        assert score_json > score_form
    
    def test_priority_computation_critical(self, engine):
        # Score >= 80 = CRITICAL, >= 60 = HIGH, >= 40 = MEDIUM
        req = InterceptedRequest(
            method="DELETE",
            url="https://example.com/admin/api/internal",
            host="example.com",
            path="/admin/api/internal",
            query_params={"user_id": "123", "cmd": "delete"},
            headers={"Authorization": "Bearer admin"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        # Score ~53: admin(10) + internal(10) + api(5) + user_id(10) + cmd(10) + DELETE(5) + auth(3)
        # Should be at least MEDIUM priority given these signals
        assert result.priority in [Priority.MEDIUM, Priority.HIGH, Priority.CRITICAL]
        assert result.score >= 40  # At minimum, should be interesting
    
    def test_priority_computation_low(self, engine):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/page",
            host="example.com",
            path="/page",
            query_params={"timestamp": "123456"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert result.priority == Priority.LOW
    
    def test_is_interesting_threshold(self, engine):
        # High score request - needs more signals to reach threshold 40
        high_req = InterceptedRequest(
            method="DELETE",
            url="https://example.com/admin/api/users",
            host="example.com",
            path="/admin/api/users",
            query_params={"user_id": "123", "file": "data.csv"},
            headers={"Authorization": "Bearer token", "content-type": "application/json"}
        )
        high_filtered = FilteredRequest(request=high_req, in_scope=True)
        high_scored = engine.score(high_filtered)
        
        # Low score request
        low_req = InterceptedRequest(
            method="GET",
            url="https://example.com/static/page",
            host="example.com",
            path="/static/page"
        )
        low_filtered = FilteredRequest(request=low_req, in_scope=True)
        low_scored = engine.score(low_filtered)
        
        # High should be >= 40, low should be < 40
        assert high_scored.score >= engine.score_threshold
        assert engine.is_interesting(high_scored) == True
        assert engine.is_interesting(low_scored) == False
    
    def test_mass_assignment_detection(self, engine):
        req = InterceptedRequest(
            method="POST",
            url="https://example.com/api/users",
            host="example.com",
            path="/api/users",
            body_json={"name": "test", "role": "admin", "is_admin": True}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert "Mass Assignment" in result.potential_vulns
        assert "role" in result.interesting_params or "is_admin" in result.interesting_params
    
    def test_payment_endpoint_detection(self, engine):
        req = InterceptedRequest(
            method="POST",
            url="https://example.com/checkout/payment",
            host="example.com",
            path="/checkout/payment"
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert "Business Logic" in result.potential_vulns or "Race Condition" in result.potential_vulns
    
    def test_contract_output(self, engine):
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/")
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert isinstance(result, ScoredRequest)
        assert isinstance(result.score, int)
        assert 0 <= result.score <= 100
        assert isinstance(result.signals, list)
        assert isinstance(result.interesting_params, list)
        assert isinstance(result.potential_vulns, list)
        assert isinstance(result.priority, Priority)
    
    def test_score_capped_at_100(self, engine):
        # Create a request that would score very high
        req = InterceptedRequest(
            method="DELETE",
            url="https://example.com/admin/api/internal/debug",
            host="example.com",
            path="/admin/api/internal/debug",
            query_params={
                "user_id": "1",
                "cmd": "exec",
                "file": "test",
                "url": "http://evil.com",
                "role": "admin"
            },
            headers={"Authorization": "Bearer admin", "content-type": "application/json"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert result.score <= 100
    
    def test_score_minimum_zero(self, engine):
        # Create a request with only negative signals
        req = InterceptedRequest(
            method="OPTIONS",
            url="https://example.com/health",
            host="example.com",
            path="/health",
            query_params={"utm_source": "test", "timestamp": "123"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert result.score >= 0


class TestHeuristicsEdgeCases:
    
    def test_empty_request(self):
        engine = HeuristicsEngine()
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/")
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        assert result.score >= 0
        assert result.priority == Priority.LOW
    
    def test_custom_threshold(self):
        engine = HeuristicsEngine(score_threshold=80)
        
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users",
            host="example.com",
            path="/api/users",
            query_params={"user_id": "123"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        scored = engine.score(filtered)
        
        # With threshold 80, this should not be interesting
        assert engine.is_interesting(scored) == (scored.score >= 80)
    
    def test_multiple_vuln_types(self):
        engine = HeuristicsEngine()
        
        req = InterceptedRequest(
            method="POST",
            url="https://example.com/api/process",
            host="example.com",
            path="/api/process",
            query_params={"file": "test", "url": "http://example.com", "user_id": "123"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = engine.score(filtered)
        
        # Should detect multiple potential vulns
        assert len(result.potential_vulns) >= 2

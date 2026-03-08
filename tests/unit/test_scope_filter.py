"""
Tests for Ghost-Hunter Scope Filter
"""

import pytest
from ghost_hunter.core.interceptor.scope_filter import ScopeFilter
from ghost_hunter.core.contracts import InterceptedRequest, FilteredRequest


class TestScopeFilter:
    
    @pytest.fixture
    def scope_filter(self):
        return ScopeFilter(
            in_scope=["*.example.com", "api.test.com"],
            out_of_scope=["*.google.com", "*.analytics.*"]
        )
    
    def test_in_scope_exact_match(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://api.test.com/users",
            host="api.test.com",
            path="/users"
        )
        result = scope_filter.filter(req)
        
        assert isinstance(result, FilteredRequest)
        assert result.in_scope == True
        assert result.scope_match == "api.test.com"
    
    def test_in_scope_wildcard(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://www.example.com/api",
            host="www.example.com",
            path="/api"
        )
        result = scope_filter.filter(req)
        
        assert result.in_scope == True
        assert result.scope_match == "*.example.com"
    
    def test_in_scope_subdomain_wildcard(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://api.staging.example.com/v1/users",
            host="api.staging.example.com",
            path="/v1/users"
        )
        result = scope_filter.filter(req)
        
        assert result.in_scope == True
    
    def test_out_of_scope_explicit(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://www.google.com/search",
            host="www.google.com",
            path="/search"
        )
        result = scope_filter.filter(req)
        
        assert result.in_scope == False
        assert "OUT:" in result.scope_match
    
    def test_out_of_scope_analytics(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://stats.analytics.google.com/collect",
            host="stats.analytics.google.com",
            path="/collect"
        )
        result = scope_filter.filter(req)
        
        assert result.in_scope == False
    
    def test_out_of_scope_no_match(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://random-site.org/page",
            host="random-site.org",
            path="/page"
        )
        result = scope_filter.filter(req)
        
        assert result.in_scope == False
        assert result.scope_match == "NO_MATCH"
    
    def test_static_asset_excluded(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://www.example.com/static/app.js",
            host="www.example.com",
            path="/static/app.js"
        )
        result = scope_filter.filter(req)
        
        assert result.in_scope == False  # Exclu car statique
        assert result.is_static == True
    
    def test_static_css_excluded(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://cdn.example.com/styles/main.css",
            host="cdn.example.com",
            path="/styles/main.css"
        )
        result = scope_filter.filter(req)
        
        assert result.is_static == True
    
    def test_static_image_excluded(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://www.example.com/images/logo.png",
            host="www.example.com",
            path="/images/logo.png"
        )
        result = scope_filter.filter(req)
        
        assert result.is_static == True
    
    def test_api_detection(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://api.example.com/api/v1/users",
            host="api.example.com",
            path="/api/v1/users"
        )
        result = scope_filter.filter(req)
        
        assert result.is_api == True
    
    def test_graphql_detection(self, scope_filter):
        req = InterceptedRequest(
            method="POST",
            url="https://api.example.com/graphql",
            host="api.example.com",
            path="/graphql"
        )
        result = scope_filter.filter(req)
        
        assert result.is_api == True
    
    def test_out_of_scope_priority(self, scope_filter):
        """Out-of-scope doit avoir priorité même si in-scope matche."""
        filter_priority = ScopeFilter(
            in_scope=["*"],  # Tout
            out_of_scope=["*.google.com"]
        )
        req = InterceptedRequest(
            method="GET",
            url="https://www.google.com",
            host="www.google.com",
            path="/"
        )
        result = filter_priority.filter(req)
        
        assert result.in_scope == False
    
    def test_contract_output_type(self, scope_filter):
        """Vérifie que le contrat est respecté."""
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/")
        result = scope_filter.filter(req)
        
        assert isinstance(result, FilteredRequest)
        assert isinstance(result.in_scope, bool)
        assert isinstance(result.scope_match, str)
        assert isinstance(result.domain, str)
        assert isinstance(result.is_api, bool)
        assert isinstance(result.is_static, bool)
    
    def test_domain_extraction(self, scope_filter):
        req = InterceptedRequest(
            method="GET",
            url="https://api.example.com/test",
            host="api.example.com",
            path="/test"
        )
        result = scope_filter.filter(req)
        
        assert result.domain == "api.example.com"
    
    def test_static_with_query_string(self, scope_filter):
        """Static detection should ignore query strings."""
        req = InterceptedRequest(
            method="GET",
            url="https://www.example.com/app.js?v=123",
            host="www.example.com",
            path="/app.js"
        )
        result = scope_filter.filter(req)
        
        assert result.is_static == True


class TestScopeFilterEdgeCases:
    
    def test_empty_scope(self):
        filter_empty = ScopeFilter(in_scope=[], out_of_scope=[])
        req = InterceptedRequest(method="GET", url="https://any.com", host="any.com", path="/")
        result = filter_empty.filter(req)
        
        assert result.in_scope == False
        assert result.scope_match == "NO_MATCH"
    
    def test_case_insensitive_matching(self):
        filter_case = ScopeFilter(in_scope=["*.EXAMPLE.COM"])
        req = InterceptedRequest(
            method="GET",
            url="https://api.example.com/test",
            host="api.example.com",
            path="/test"
        )
        result = filter_case.filter(req)
        
        assert result.in_scope == True
    
    def test_disable_static_filtering(self):
        filter_no_static = ScopeFilter(
            in_scope=["*.example.com"],
            ignore_static=False
        )
        req = InterceptedRequest(
            method="GET",
            url="https://www.example.com/app.js",
            host="www.example.com",
            path="/app.js"
        )
        result = filter_no_static.filter(req)
        
        assert result.in_scope == True
        assert result.is_static == False

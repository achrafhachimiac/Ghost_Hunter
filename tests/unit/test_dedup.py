"""
Tests for Ghost-Hunter Deduplication Engine
"""

import pytest
from ghost_hunter.core.interceptor.dedup import DedupEngine, DedupResult
from ghost_hunter.core.contracts import InterceptedRequest, FilteredRequest


class TestDedupEngine:
    
    @pytest.fixture
    def dedup_engine(self):
        # Force fallback mode by using invalid Redis config
        engine = DedupEngine(redis_host="invalid", redis_port=9999)
        engine.clear()
        return engine
    
    def test_first_request_not_duplicate(self, dedup_engine):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/123",
            host="example.com",
            path="/api/users/123",
            query_params={}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = dedup_engine.check(filtered)
        
        assert isinstance(result, DedupResult)
        assert result.is_duplicate == False
        assert result.seen_count == 1
        assert result.hash != ""
        assert len(result.hash) == 16
    
    def test_same_endpoint_is_duplicate(self, dedup_engine):
        # Première requête
        req1 = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/123",
            host="example.com",
            path="/api/users/123"
        )
        filtered1 = FilteredRequest(request=req1, in_scope=True)
        dedup_engine.check(filtered1)
        
        # Deuxième requête avec ID différent mais même pattern
        req2 = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/456",  # ID différent
            host="example.com",
            path="/api/users/456"
        )
        filtered2 = FilteredRequest(request=req2, in_scope=True)
        result = dedup_engine.check(filtered2)
        
        assert result.is_duplicate == True
        assert result.seen_count == 2
    
    def test_different_methods_not_duplicate(self, dedup_engine):
        req1 = InterceptedRequest(method="GET", url="https://example.com/api", host="example.com", path="/api")
        req2 = InterceptedRequest(method="POST", url="https://example.com/api", host="example.com", path="/api")
        
        filtered1 = FilteredRequest(request=req1, in_scope=True)
        filtered2 = FilteredRequest(request=req2, in_scope=True)
        
        dedup_engine.check(filtered1)
        result = dedup_engine.check(filtered2)
        
        assert result.is_duplicate == False  # Méthode différente = pas duplicate
    
    def test_different_params_not_duplicate(self, dedup_engine):
        req1 = InterceptedRequest(
            method="GET",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            query_params={"id": "123"}
        )
        req2 = InterceptedRequest(
            method="GET",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            query_params={"name": "test"}  # Param différent
        )
        
        filtered1 = FilteredRequest(request=req1, in_scope=True)
        filtered2 = FilteredRequest(request=req2, in_scope=True)
        
        dedup_engine.check(filtered1)
        result = dedup_engine.check(filtered2)
        
        assert result.is_duplicate == False
    
    def test_same_params_different_values_is_duplicate(self, dedup_engine):
        req1 = InterceptedRequest(
            method="GET",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            query_params={"id": "123"}
        )
        req2 = InterceptedRequest(
            method="GET",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            query_params={"id": "456"}  # Same param, different value
        )
        
        filtered1 = FilteredRequest(request=req1, in_scope=True)
        filtered2 = FilteredRequest(request=req2, in_scope=True)
        
        dedup_engine.check(filtered1)
        result = dedup_engine.check(filtered2)
        
        assert result.is_duplicate == True
    
    def test_auth_level_affects_hash(self, dedup_engine):
        req1 = InterceptedRequest(
            method="GET",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            headers={}
        )
        req2 = InterceptedRequest(
            method="GET",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            headers={"Authorization": "Bearer token"}  # Authentifié
        )
        
        filtered1 = FilteredRequest(request=req1, in_scope=True)
        filtered2 = FilteredRequest(request=req2, in_scope=True)
        
        dedup_engine.check(filtered1)
        result = dedup_engine.check(filtered2)
        
        assert result.is_duplicate == False  # Auth différent = pas duplicate
    
    def test_session_cookie_auth_detection(self, dedup_engine):
        """Session cookies don't affect the hash - only auth headers do.
        
        This is by design: we want to deduplicate requests regardless of session,
        but different auth levels (Authorization header) are tracked separately.
        """
        req1 = InterceptedRequest(
            method="GET",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            cookies={}
        )
        req2 = InterceptedRequest(
            method="GET",
            url="https://example.com/api",
            host="example.com",
            path="/api",
            cookies={"session_id": "abc123"}  # Cookie doesn't change hash
        )
        
        filtered1 = FilteredRequest(request=req1, in_scope=True)
        filtered2 = FilteredRequest(request=req2, in_scope=True)
        
        dedup_engine.check(filtered1)
        result = dedup_engine.check(filtered2)
        
        # Cookies don't affect the hash, so it IS a duplicate
        assert result.is_duplicate == True
    
    def test_uuid_path_is_duplicate(self, dedup_engine):
        req1 = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/550e8400-e29b-41d4-a716-446655440000",
            host="example.com",
            path="/api/users/550e8400-e29b-41d4-a716-446655440000"
        )
        req2 = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/123e4567-e89b-12d3-a456-426614174000",
            host="example.com",
            path="/api/users/123e4567-e89b-12d3-a456-426614174000"
        )
        
        filtered1 = FilteredRequest(request=req1, in_scope=True)
        filtered2 = FilteredRequest(request=req2, in_scope=True)
        
        dedup_engine.check(filtered1)
        result = dedup_engine.check(filtered2)
        
        assert result.is_duplicate == True
    
    def test_contract_output(self, dedup_engine):
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/")
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result = dedup_engine.check(filtered)
        
        assert isinstance(result, DedupResult)
        assert isinstance(result.is_duplicate, bool)
        assert isinstance(result.hash, str)
        assert len(result.hash) == 16
        assert isinstance(result.seen_count, int)
        assert result.first_seen is not None
    
    def test_clear(self, dedup_engine):
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/")
        filtered = FilteredRequest(request=req, in_scope=True)
        
        dedup_engine.check(filtered)
        dedup_engine.clear()
        
        result = dedup_engine.check(filtered)
        assert result.is_duplicate == False
        assert result.seen_count == 1
    
    def test_stats(self, dedup_engine):
        req1 = InterceptedRequest(method="GET", url="https://example.com/a", host="example.com", path="/a")
        req2 = InterceptedRequest(method="GET", url="https://example.com/b", host="example.com", path="/b")
        
        dedup_engine.check(FilteredRequest(request=req1, in_scope=True))
        dedup_engine.check(FilteredRequest(request=req2, in_scope=True))
        
        stats = dedup_engine.stats()
        assert stats["entries"] == 2
        assert stats["backend"] == "memory"
    
    def test_seen_count_increments(self, dedup_engine):
        req = InterceptedRequest(method="GET", url="https://example.com/api", host="example.com", path="/api")
        filtered = FilteredRequest(request=req, in_scope=True)
        
        result1 = dedup_engine.check(filtered)
        assert result1.seen_count == 1
        
        result2 = dedup_engine.check(filtered)
        assert result2.seen_count == 2
        
        result3 = dedup_engine.check(filtered)
        assert result3.seen_count == 3

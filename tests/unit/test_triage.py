"""
Tests for Ghost-Hunter Triage Engine
"""

import pytest
from unittest.mock import MagicMock, patch
from ghost_hunter.core.brain.triage import TriageEngine
from ghost_hunter.core.brain.openrouter_client import OpenRouterClient, AIResponse
from ghost_hunter.core.contracts import (
    InterceptedRequest, FilteredRequest, ScoredRequest, 
    TriageDecision, TestPhase, Priority
)


class TestTriageEngine:
    
    @pytest.fixture
    def mock_client(self):
        client = MagicMock(spec=OpenRouterClient)
        return client
    
    @pytest.fixture
    def sample_scored_request(self):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/123",
            host="example.com",
            path="/api/users/123",
            query_params={"user_id": "123"},
            headers={"Authorization": "Bearer token"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        scored = ScoredRequest(
            request=filtered,
            score=65,
            interesting_params=["user_id"],
            potential_vulns=["IDOR"]
        )
        return scored
    
    def test_engine_instantiation(self, mock_client):
        engine = TriageEngine(client=mock_client)
        assert engine.model == "llama-70b"
        assert engine.confidence_threshold == 60
    
    def test_extract_json_direct(self, mock_client):
        engine = TriageEngine(client=mock_client)
        
        json_str = '{"interesting": true, "confidence": 80}'
        result = engine._extract_json(json_str)
        
        assert result is not None
        assert result["interesting"] == True
        assert result["confidence"] == 80
    
    def test_extract_json_from_markdown(self, mock_client):
        engine = TriageEngine(client=mock_client)
        
        text = """Here's my analysis:
        
```json
{"interesting": true, "confidence": 75, "reason": "IDOR potential"}
```

This request looks interesting."""
        
        result = engine._extract_json(text)
        
        assert result is not None
        assert result["interesting"] == True
        assert result["confidence"] == 75
    
    def test_extract_json_fails_gracefully(self, mock_client):
        engine = TriageEngine(client=mock_client)
        
        result = engine._extract_json("No JSON here at all")
        assert result is None
    
    def test_build_request_data(self, mock_client, sample_scored_request):
        engine = TriageEngine(client=mock_client)
        
        data = engine._build_request_data(sample_scored_request)
        
        assert data["method"] == "GET"
        assert data["path"] == "/api/users/123"
        assert data["score"] == 65
        assert "user_id" in data["interesting_params"]
        assert data["has_auth"] == True
    
    def test_triage_success(self, mock_client, sample_scored_request):
        engine = TriageEngine(client=mock_client)
        
        mock_client.chat.return_value = AIResponse(
            content='{"interesting": true, "confidence": 85, "reason": "IDOR vulnerability likely", "suggested_vulns": ["IDOR"], "test_phase": "medium", "priority": "high"}',
            model="anthropic/claude-3.5-haiku",
            tokens_input=200,
            tokens_output=50,
            latency_ms=150
        )
        
        result = engine.triage(sample_scored_request)
        
        assert isinstance(result, TriageDecision)
        assert result.interesting == True
        assert result.confidence == 85
        assert "IDOR" in result.suggested_vulns
        assert result.test_phase == TestPhase.MEDIUM
        assert result.needs_deep_analysis == True
    
    def test_triage_not_interesting(self, mock_client, sample_scored_request):
        engine = TriageEngine(client=mock_client)
        
        mock_client.chat.return_value = AIResponse(
            content='{"interesting": false, "confidence": 20, "reason": "Standard pagination request", "suggested_vulns": [], "test_phase": "safe", "priority": "low"}',
            model="anthropic/claude-3.5-haiku",
            tokens_input=200,
            tokens_output=50,
            latency_ms=100
        )
        
        result = engine.triage(sample_scored_request)
        
        assert result.interesting == False
        assert result.confidence == 20
        assert result.needs_deep_analysis == False
    
    def test_triage_ai_error(self, mock_client, sample_scored_request):
        engine = TriageEngine(client=mock_client)
        
        # Simulate AI error by making chat raise an exception
        mock_client.chat.side_effect = Exception("API timeout")
        
        result = engine.triage(sample_scored_request)
        
        assert result.interesting == False
        assert "AI error" in result.reason
        assert result.confidence == 0
    
    def test_triage_json_parse_fallback(self, mock_client, sample_scored_request):
        engine = TriageEngine(client=mock_client)
        
        # Response that mentions "interesting" but isn't valid JSON
        mock_client.chat.return_value = AIResponse(
            content="This request looks interesting because it has user IDs",
            model="anthropic/claude-3.5-haiku",
            tokens_input=200,
            tokens_output=30,
            latency_ms=100
        )
        
        result = engine.triage(sample_scored_request)
        
        assert result.interesting == True  # Fallback detection
        assert "Parse failed" in result.reason
    
    def test_triage_test_phase_risky(self, mock_client, sample_scored_request):
        engine = TriageEngine(client=mock_client)
        
        mock_client.chat.return_value = AIResponse(
            content='{"interesting": true, "confidence": 90, "reason": "Race condition potential", "suggested_vulns": ["Race Condition"], "test_phase": "risky", "priority": "critical"}',
            model="anthropic/claude-3.5-haiku",
            tokens_input=200,
            tokens_output=50,
            latency_ms=120
        )
        
        result = engine.triage(sample_scored_request)
        
        assert result.test_phase == TestPhase.RISKY
    
    def test_is_worth_testing(self, mock_client):
        engine = TriageEngine(client=mock_client, confidence_threshold=60)
        
        # Above threshold
        decision_high = TriageDecision(interesting=True, confidence=75)
        assert engine.is_worth_testing(decision_high) == True
        
        # Below threshold
        decision_low = TriageDecision(interesting=True, confidence=50)
        assert engine.is_worth_testing(decision_low) == False
        
        # Not interesting
        decision_not = TriageDecision(interesting=False, confidence=90)
        assert engine.is_worth_testing(decision_not) == False
    
    def test_batch_triage(self, mock_client, sample_scored_request):
        engine = TriageEngine(client=mock_client)
        
        mock_client.chat.return_value = AIResponse(
            content='{"interesting": true, "confidence": 70, "reason": "Test", "suggested_vulns": ["XSS"], "test_phase": "safe", "priority": "medium"}',
            model="anthropic/claude-3.5-haiku",
            tokens_input=200,
            tokens_output=50,
            latency_ms=100
        )
        
        results = engine.batch_triage([sample_scored_request, sample_scored_request])
        
        assert len(results) == 2
        assert all(isinstance(r, TriageDecision) for r in results)


class TestTriageEngineEdgeCases:
    
    def test_empty_params(self):
        client = MagicMock(spec=OpenRouterClient)
        engine = TriageEngine(client=client)
        
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/",
            host="example.com",
            path="/"
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        scored = ScoredRequest(request=filtered, score=10)
        
        client.chat.return_value = AIResponse(
            content='{"interesting": false, "confidence": 10, "reason": "Empty request", "suggested_vulns": [], "test_phase": "safe", "priority": "low"}',
            model="anthropic/claude-3.5-haiku",
            tokens_input=100,
            tokens_output=40,
            latency_ms=80
        )
        
        result = engine.triage(scored)
        
        assert result.interesting == False
    
    def test_custom_confidence_threshold(self):
        client = MagicMock(spec=OpenRouterClient)
        engine = TriageEngine(client=client, confidence_threshold=80)
        
        # Confidence 75 should not pass with threshold 80
        decision = TriageDecision(interesting=True, confidence=75)
        assert engine.is_worth_testing(decision) == False
        
        # Confidence 85 should pass
        decision = TriageDecision(interesting=True, confidence=85)
        assert engine.is_worth_testing(decision) == True


class TestTriageRAGIntegration:
    """Tests for RAG Engine integration in Triage."""
    
    @pytest.fixture
    def mock_client(self):
        client = MagicMock(spec=OpenRouterClient)
        return client
    
    @pytest.fixture
    def sample_scored_request(self):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/123",
            host="example.com",
            path="/api/users/123",
            query_params={"user_id": "123"},
            headers={"Authorization": "Bearer token"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        scored = ScoredRequest(
            request=filtered,
            score=65,
            interesting_params=["user_id"],
            potential_vulns=["IDOR"]
        )
        return scored
    
    def test_engine_has_rag_attributes(self, mock_client):
        """Test that engine has RAG-related attributes."""
        engine = TriageEngine(client=mock_client)
        
        assert hasattr(engine, 'use_rag')
        assert hasattr(engine, '_rag_engine')
        assert hasattr(engine, 'TIER2_RAG_MAX_TOKENS')
        assert hasattr(engine, 'TIER2_RAG_MAX_CHUNKS')
    
    def test_rag_config_values(self, mock_client):
        """Test RAG configuration defaults."""
        engine = TriageEngine(client=mock_client)
        
        assert engine.TIER2_RAG_MAX_TOKENS == 1000
        assert engine.TIER2_RAG_MAX_CHUNKS == 10
    
    @patch('ghost_hunter.core.brain.triage.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.triage.get_rag_engine')
    def test_rag_engine_lazy_loading(self, mock_get_rag, mock_client):
        """Test that RAG engine is lazily loaded."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = True
        mock_get_rag.return_value = mock_rag
        
        engine = TriageEngine(client=mock_client, use_rag=True)
        
        # RAG engine not loaded yet
        assert engine._rag_engine is None
        
        # Access via property triggers lazy load
        rag = engine.rag_engine
        
        mock_get_rag.assert_called_once()
        assert rag is not None
    
    @patch('ghost_hunter.core.brain.triage.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.triage.get_rag_engine')
    def test_rag_context_retrieval(self, mock_get_rag, mock_client, sample_scored_request):
        """Test RAG context retrieval for Tier 2."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = True
        mock_rag.get_context_sync.return_value = "## IDOR Techniques\n- Check user_id manipulation"
        mock_get_rag.return_value = mock_rag
        
        engine = TriageEngine(client=mock_client, use_rag=True)
        engine._rag_engine = mock_rag  # Bypass lazy load
        
        context = engine._get_rag_context(sample_scored_request)
        
        assert context is not None
        assert "IDOR" in context
        mock_rag.get_context_sync.assert_called_once_with(
            sample_scored_request,
            max_tokens=1000,
            max_chunks=10,
            include_payloads=False
        )
    
    @patch('ghost_hunter.core.brain.triage.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.triage.get_rag_engine')
    def test_rag_fallback_on_error(self, mock_get_rag, mock_client, sample_scored_request):
        """Test fallback to KnowledgeLoader when RAG fails."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = True
        mock_rag.get_context_sync.side_effect = Exception("RAG error")
        mock_get_rag.return_value = mock_rag
        
        engine = TriageEngine(client=mock_client, use_rag=True)
        engine._rag_engine = mock_rag
        engine._knowledge = MagicMock()
        engine._knowledge.get_context_for_prompt.return_value = "Fallback context"
        
        context = engine._get_rag_context(sample_scored_request)
        
        # Should fallback to legacy KnowledgeLoader
        assert context == "Fallback context"
    
    def test_use_rag_disabled(self, mock_client, sample_scored_request):
        """Test that RAG can be disabled."""
        engine = TriageEngine(client=mock_client, use_rag=False)
        
        assert engine.use_rag == False
        assert engine.rag_engine is None
    
    @patch('ghost_hunter.core.brain.triage.RAG_AVAILABLE', False)
    def test_rag_not_available(self, mock_client):
        """Test behavior when RAG is not available."""
        engine = TriageEngine(client=mock_client, use_rag=True)
        
        # use_rag should be False if RAG_AVAILABLE is False
        assert engine.use_rag == False
    
    @patch('ghost_hunter.core.brain.triage.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.triage.get_rag_engine')
    def test_triage_uses_rag_context(self, mock_get_rag, mock_client, sample_scored_request):
        """Test that triage method uses RAG context."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = True
        mock_rag.get_context_sync.return_value = "## Relevant IDOR Context"
        mock_get_rag.return_value = mock_rag
        
        mock_client.chat.return_value = AIResponse(
            content='{"interesting": true, "confidence": 85, "reason": "IDOR", "suggested_vulns": ["IDOR"], "test_phase": "medium"}',
            model="anthropic/claude-3.5-haiku",
            tokens_input=300,
            tokens_output=50,
            latency_ms=150
        )
        
        engine = TriageEngine(client=mock_client, use_rag=True)
        engine._rag_engine = mock_rag
        
        result = engine.triage(sample_scored_request)
        
        # RAG should have been called
        mock_rag.get_context_sync.assert_called_once()
        assert result.interesting == True
    
    def test_quick_triage_no_rag(self, mock_client, sample_scored_request):
        """Test that Tier 1 (quick_triage) does NOT use RAG."""
        mock_client.chat.return_value = AIResponse(
            content='{"worth_analyzing": true, "reason": "Has user_id", "priority": 1}',
            model="anthropic/claude-3.5-haiku",
            tokens_input=50,
            tokens_output=30,
            latency_ms=80
        )
        
        engine = TriageEngine(client=mock_client, use_rag=True)
        mock_rag = MagicMock()
        engine._rag_engine = mock_rag
        
        result = engine.quick_triage(sample_scored_request)
        
        # RAG should NOT be called for quick_triage (Tier 1)
        mock_rag.get_context_sync.assert_not_called()
        assert result["worth_analyzing"] == True
    
    @patch('ghost_hunter.core.brain.triage.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.triage.get_rag_engine')
    def test_rag_engine_unavailable_fallback(self, mock_get_rag, mock_client, sample_scored_request):
        """Test fallback when RAG engine is_available returns False."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = False
        mock_get_rag.return_value = mock_rag
        
        engine = TriageEngine(client=mock_client, use_rag=True)
        
        # Access rag_engine property
        result = engine.rag_engine
        
        # Should return None when RAG is not available
        assert result is None


class TestTriageSkipTier1:
    """Tests for skip_tier1 configuration."""
    
    @pytest.fixture
    def mock_client(self):
        client = MagicMock(spec=OpenRouterClient)
        return client
    
    @pytest.fixture
    def sample_scored_request(self):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/123",
            host="example.com",
            path="/api/users/123",
            query_params={"user_id": "123"},
            headers={"Authorization": "Bearer token"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        scored = ScoredRequest(
            request=filtered,
            score=65,
            interesting_params=["user_id"],
            potential_vulns=["IDOR"]
        )
        return scored
    
    def test_engine_has_skip_tier1_attribute(self, mock_client):
        """Test that engine has skip_tier1 attribute."""
        engine = TriageEngine(client=mock_client)
        assert hasattr(engine, 'skip_tier1')
    
    def test_skip_tier1_default_from_config(self, mock_client):
        """Test that skip_tier1 defaults to config value."""
        # Import the global config
        from ghost_hunter.core.brain.triage import SKIP_TIER1_TRIAGE
        
        engine = TriageEngine(client=mock_client)
        assert engine.skip_tier1 == SKIP_TIER1_TRIAGE
    
    def test_skip_tier1_override_true(self, mock_client):
        """Test that skip_tier1 can be overridden to True."""
        engine = TriageEngine(client=mock_client, skip_tier1=True)
        assert engine.skip_tier1 == True
    
    def test_skip_tier1_override_false(self, mock_client):
        """Test that skip_tier1 can be overridden to False."""
        engine = TriageEngine(client=mock_client, skip_tier1=False)
        assert engine.skip_tier1 == False
    
    def test_smart_triage_exists(self, mock_client):
        """Test that smart_triage method exists."""
        engine = TriageEngine(client=mock_client)
        assert hasattr(engine, 'smart_triage')
        assert callable(engine.smart_triage)
    
    def test_smart_triage_skip_tier1_goes_to_tier2(self, mock_client, sample_scored_request):
        """Test smart_triage with skip_tier1=True goes directly to Tier 2."""
        engine = TriageEngine(client=mock_client, skip_tier1=True)
        
        mock_client.chat.return_value = AIResponse(
            content='{"interesting": true, "confidence": 85, "reason": "IDOR", "suggested_vulns": ["IDOR"], "test_phase": "medium"}',
            model="test-model",
            tokens_input=300,
            tokens_output=50,
            latency_ms=150
        )
        
        result = engine.smart_triage(sample_scored_request)
        
        # Should have called full triage (chat was called)
        mock_client.chat.assert_called_once()
        assert result.interesting == True
        assert result.confidence == 85
    
    def test_smart_triage_with_tier1_rejected(self, mock_client, sample_scored_request):
        """Test smart_triage with skip_tier1=False when Tier 1 rejects."""
        engine = TriageEngine(client=mock_client, skip_tier1=False)
        
        # Tier 1 rejects
        mock_client.chat.return_value = AIResponse(
            content='{"worth_analyzing": false, "reason": "boring endpoint", "priority": 3}',
            model="test-model",
            tokens_input=50,
            tokens_output=30,
            latency_ms=80
        )
        
        result = engine.smart_triage(sample_scored_request)
        
        # Should be rejected, only 1 call (Tier 1 only)
        mock_client.chat.assert_called_once()
        assert result.interesting == False
        assert "Tier 1 rejected" in result.reason
    
    def test_smart_triage_with_tier1_passes(self, mock_client, sample_scored_request):
        """Test smart_triage with skip_tier1=False when Tier 1 passes."""
        engine = TriageEngine(client=mock_client, skip_tier1=False)
        
        # First call: Tier 1 passes
        # Second call: Tier 2 full triage
        mock_client.chat.side_effect = [
            AIResponse(
                content='{"worth_analyzing": true, "reason": "interesting", "priority": 1}',
                model="tier1",
                tokens_input=50,
                tokens_output=30,
                latency_ms=80
            ),
            AIResponse(
                content='{"interesting": true, "confidence": 85, "reason": "IDOR", "suggested_vulns": ["IDOR"], "test_phase": "medium"}',
                model="tier2",
                tokens_input=300,
                tokens_output=50,
                latency_ms=150
            )
        ]
        
        result = engine.smart_triage(sample_scored_request)
        
        # Should have called both Tier 1 and Tier 2
        assert mock_client.chat.call_count == 2
        assert result.interesting == True
        assert result.confidence == 85

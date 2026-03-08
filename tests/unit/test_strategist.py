"""
Tests for Ghost-Hunter Strategist Engine
"""

import pytest
from unittest.mock import MagicMock, patch
from ghost_hunter.core.brain.strategist import StrategistEngine
from ghost_hunter.core.brain.openrouter_client import OpenRouterClient, AIResponse
from ghost_hunter.core.contracts import (
    InterceptedRequest, FilteredRequest, ScoredRequest,
    TriageDecision, AttackPlan, PayloadVariant, TestStep, TestPhase
)


class TestStrategistEngine:
    
    @pytest.fixture
    def mock_client(self):
        return MagicMock(spec=OpenRouterClient)
    
    @pytest.fixture
    def sample_triage(self):
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
            score=70,
            interesting_params=["user_id"],
            potential_vulns=["IDOR"]
        )
        triage = TriageDecision(
            request=scored,
            interesting=True,
            confidence=85,
            suggested_vulns=["IDOR"],
            test_phase=TestPhase.MEDIUM
        )
        return triage
    
    def test_engine_instantiation(self, mock_client):
        engine = StrategistEngine(client=mock_client)
        assert engine.model == "llama-70b"
    
    def test_extract_json_from_response(self, mock_client):
        engine = StrategistEngine(client=mock_client)
        
        text = """Here's the attack plan:

```json
{
  "vuln_class": "IDOR",
  "tool": "custom",
  "reasoning": "Test user ID manipulation",
  "injection_points": ["user_id"],
  "payloads": [{"payload": "456", "encoding": "none"}],
  "test_sequence": [{"order": 1, "action": "send_request", "description": "Test other user ID"}],
  "baseline_needed": true,
  "max_requests": 5,
  "delay_between_ms": 1000
}
```
"""
        
        result = engine._extract_json(text)
        
        assert result is not None
        assert result["vuln_class"] == "IDOR"
        assert result["tool"] == "custom"
    
    def test_create_plan_success(self, mock_client, sample_triage):
        engine = StrategistEngine(client=mock_client)
        
        mock_client.chat.return_value = AIResponse(
            content='''{
                "vuln_class": "IDOR",
                "tool": "custom",
                "reasoning": "User ID parameter can be manipulated to access other users data",
                "injection_points": ["user_id"],
                "payloads": [
                    {"payload": "456", "encoding": "none"},
                    {"payload": "1", "encoding": "none"},
                    {"payload": "999999", "encoding": "none"}
                ],
                "test_sequence": [
                    {"order": 1, "action": "send_request", "description": "Try different user ID", "expected_indicators": ["200", "different_data"]}
                ],
                "baseline_needed": true,
                "max_requests": 10,
                "delay_between_ms": 1000,
                "success_indicators": ["Access to other user data", "200 OK with different content"],
                "evasion_techniques": []
            }''',
            model="anthropic/claude-3.5-sonnet",
            tokens_input=500,
            tokens_output=200,
            latency_ms=800
        )
        
        result = engine.create_plan(sample_triage)
        
        assert isinstance(result, AttackPlan)
        assert result.vuln_class == "IDOR"
        assert result.tool == "custom"
        assert len(result.payloads) == 3
        assert result.payloads[0].payload == "456"
        assert result.max_requests == 10
        assert result.baseline_needed == True
    
    def test_create_plan_fallback_on_ai_error(self, mock_client, sample_triage):
        engine = StrategistEngine(client=mock_client)
        
        # Empty content triggers fallback
        mock_client.chat.return_value = AIResponse(
            content="",
            model="anthropic/claude-3.5-sonnet",
            tokens_input=0,
            tokens_output=0,
            latency_ms=100
        )
        
        result = engine.create_plan(sample_triage)
        
        # Should get fallback plan
        assert isinstance(result, AttackPlan)
        assert result.vuln_class == "IDOR"
        assert len(result.payloads) > 0
        assert "Fallback" in result.reasoning
    
    def test_create_plan_fallback_on_parse_error(self, mock_client, sample_triage):
        engine = StrategistEngine(client=mock_client)
        
        mock_client.chat.return_value = AIResponse(
            content="This is not valid JSON at all",
            model="anthropic/claude-3.5-sonnet",
            tokens_input=500,
            tokens_output=50,
            latency_ms=500
        )
        
        result = engine.create_plan(sample_triage)
        
        # Should get fallback plan
        assert isinstance(result, AttackPlan)
        assert len(result.payloads) > 0
    
    def test_default_payloads_exist(self, mock_client):
        engine = StrategistEngine(client=mock_client)
        
        assert "IDOR" in engine.DEFAULT_PAYLOADS
        assert "SQLi" in engine.DEFAULT_PAYLOADS
        assert "XSS" in engine.DEFAULT_PAYLOADS
        assert "SSRF" in engine.DEFAULT_PAYLOADS
        assert "LFI" in engine.DEFAULT_PAYLOADS
        assert "CMDi" in engine.DEFAULT_PAYLOADS
        
        # Each should have multiple payloads
        for vuln_type, payloads in engine.DEFAULT_PAYLOADS.items():
            assert len(payloads) >= 3
    
    def test_get_quick_payloads(self, mock_client):
        engine = StrategistEngine(client=mock_client)
        
        idor_payloads = engine.get_quick_payloads("IDOR")
        assert len(idor_payloads) > 0
        assert all(isinstance(p, PayloadVariant) for p in idor_payloads)
        
        sqli_payloads = engine.get_quick_payloads("SQLi")
        assert any("'" in p.payload for p in sqli_payloads)
        
        xss_payloads = engine.get_quick_payloads("XSS")
        assert any("<script>" in p.payload for p in xss_payloads)
    
    def test_get_quick_payloads_unknown_vuln(self, mock_client):
        engine = StrategistEngine(client=mock_client)
        
        # Unknown vuln type should return IDOR defaults
        payloads = engine.get_quick_payloads("UnknownVuln")
        assert len(payloads) > 0
    
    def test_create_plan_with_sqli_suggested(self, mock_client):
        engine = StrategistEngine(client=mock_client)
        
        # Create triage with SQLi suggestion
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/search",
            host="example.com",
            path="/search",
            query_params={"query": "test"}
        )
        filtered = FilteredRequest(request=req, in_scope=True)
        scored = ScoredRequest(request=filtered, score=60, potential_vulns=["SQLi"])
        triage = TriageDecision(
            request=scored,
            interesting=True,
            confidence=75,
            suggested_vulns=["SQLi"]
        )
        
        mock_client.chat.return_value = AIResponse(
            content='''{
                "vuln_class": "SQLi",
                "tool": "sqlmap",
                "reasoning": "Search parameter likely used in SQL query",
                "injection_points": ["query"],
                "payloads": [
                    {"payload": "'", "encoding": "none"},
                    {"payload": "' OR '1'='1", "encoding": "url"}
                ],
                "test_sequence": [{"order": 1, "action": "send_request", "description": "Test single quote"}],
                "baseline_needed": true,
                "max_requests": 15,
                "delay_between_ms": 2000
            }''',
            model="anthropic/claude-3.5-sonnet",
            tokens_input=600,
            tokens_output=250,
            latency_ms=900
        )
        
        result = engine.create_plan(triage)
        
        assert result.vuln_class == "SQLi"
        assert result.tool == "sqlmap"
        assert "query" in result.injection_points


class TestStrategistEnginePayloads:
    
    def test_payload_variant_creation(self):
        payload = PayloadVariant(
            payload="' OR '1'='1",
            encoding="url",
            evasion="comment_insert"
        )
        
        assert payload.payload == "' OR '1'='1"
        assert payload.encoding == "url"
        assert payload.evasion == "comment_insert"
    
    def test_test_step_creation(self):
        step = TestStep(
            order=1,
            action="send_request",
            description="Send malicious payload",
            expected_indicators=["error", "sql syntax"]
        )
        
        assert step.order == 1
        assert step.action == "send_request"
        assert len(step.expected_indicators) == 2
    
    def test_attack_plan_contract(self):
        plan = AttackPlan(
            vuln_class="IDOR",
            tool="custom",
            payloads=[PayloadVariant(payload="123")],
            injection_points=["user_id"],
            max_requests=10,
            baseline_needed=True
        )
        
        assert plan.id is not None  # UUID generated
        assert plan.vuln_class == "IDOR"
        assert len(plan.payloads) == 1


class TestStrategistRAGIntegration:
    """Tests for RAG Engine integration in Strategist."""
    
    @pytest.fixture
    def mock_client(self):
        return MagicMock(spec=OpenRouterClient)
    
    @pytest.fixture
    def sample_triage(self):
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
            score=70,
            interesting_params=["user_id"],
            potential_vulns=["IDOR"]
        )
        triage = TriageDecision(
            request=scored,
            interesting=True,
            confidence=85,
            suggested_vulns=["IDOR"],
            test_phase=TestPhase.MEDIUM
        )
        return triage
    
    def test_engine_has_rag_attributes(self, mock_client):
        """Test that engine has RAG-related attributes."""
        engine = StrategistEngine(client=mock_client)
        
        assert hasattr(engine, 'use_rag')
        assert hasattr(engine, '_rag_engine')
        assert hasattr(engine, 'RAG_MAX_TOKENS')
        assert hasattr(engine, 'RAG_MAX_CHUNKS')
    
    def test_rag_config_values(self, mock_client):
        """Test RAG configuration defaults for Strategist."""
        engine = StrategistEngine(client=mock_client)
        
        assert engine.RAG_MAX_TOKENS == 1500
        assert engine.RAG_MAX_CHUNKS == 15
    
    @patch('ghost_hunter.core.brain.strategist.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.strategist.get_rag_engine')
    def test_rag_engine_lazy_loading(self, mock_get_rag, mock_client):
        """Test that RAG engine is lazily loaded."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = True
        mock_get_rag.return_value = mock_rag
        
        engine = StrategistEngine(client=mock_client, use_rag=True)
        
        # RAG engine not loaded yet
        assert engine._rag_engine is None
        
        # Access via property triggers lazy load
        rag = engine.rag_engine
        
        mock_get_rag.assert_called_once()
        assert rag is not None
    
    @patch('ghost_hunter.core.brain.strategist.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.strategist.get_rag_engine')
    def test_rag_context_retrieval(self, mock_get_rag, mock_client, sample_triage):
        """Test RAG context retrieval for Strategist."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = True
        mock_rag.get_context_sync.return_value = "## IDOR Techniques\n- Payloads: 1, 2, -1"
        mock_get_rag.return_value = mock_rag
        
        engine = StrategistEngine(client=mock_client, use_rag=True)
        engine._rag_engine = mock_rag  # Bypass lazy load
        
        context, payloads = engine._get_rag_context(sample_triage)
        
        assert context is not None
        assert "IDOR" in context
        mock_rag.get_context_sync.assert_called_once()
        
        # Verify include_payloads=True for Strategist
        call_args = mock_rag.get_context_sync.call_args
        assert call_args.kwargs['max_tokens'] == 1500
        assert call_args.kwargs['max_chunks'] == 15
        assert call_args.kwargs['include_payloads'] == True
    
    @patch('ghost_hunter.core.brain.strategist.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.strategist.get_rag_engine')
    def test_rag_fallback_on_error(self, mock_get_rag, mock_client, sample_triage):
        """Test fallback to KnowledgeLoader when RAG fails."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = True
        mock_rag.get_context_sync.side_effect = Exception("RAG error")
        mock_get_rag.return_value = mock_rag
        
        engine = StrategistEngine(client=mock_client, use_rag=True)
        engine._rag_engine = mock_rag
        engine._knowledge = MagicMock()
        engine._knowledge.get_context_for_prompt.return_value = "Fallback context"
        engine._knowledge.get_payloads_for_prompt.return_value = ["payload1", "payload2"]
        
        context, payloads = engine._get_rag_context(sample_triage)
        
        # Should fallback to legacy KnowledgeLoader
        assert context == "Fallback context"
    
    def test_use_rag_disabled(self, mock_client, sample_triage):
        """Test that RAG can be disabled."""
        engine = StrategistEngine(client=mock_client, use_rag=False)
        
        assert engine.use_rag == False
        assert engine.rag_engine is None
    
    @patch('ghost_hunter.core.brain.strategist.RAG_AVAILABLE', False)
    def test_rag_not_available(self, mock_client):
        """Test behavior when RAG is not available."""
        engine = StrategistEngine(client=mock_client, use_rag=True)
        
        # use_rag should be False if RAG_AVAILABLE is False
        assert engine.use_rag == False
    
    @patch('ghost_hunter.core.brain.strategist.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.strategist.get_rag_engine')
    def test_create_plan_uses_rag_context(self, mock_get_rag, mock_client, sample_triage):
        """Test that create_plan method uses RAG context."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = True
        mock_rag.get_context_sync.return_value = "## RAG IDOR Context with payloads"
        mock_get_rag.return_value = mock_rag
        
        mock_client.chat.return_value = AIResponse(
            content='''{
                "vuln_class": "IDOR",
                "tool": "custom",
                "reasoning": "Test user ID manipulation",
                "injection_points": ["user_id"],
                "payloads": [{"payload": "456", "encoding": "none"}],
                "test_sequence": [{"order": 1, "action": "send_request", "description": "Test"}],
                "baseline_needed": true,
                "max_requests": 5,
                "delay_between_ms": 1000
            }''',
            model="anthropic/claude-3.5-sonnet",
            tokens_input=500,
            tokens_output=200,
            latency_ms=300
        )
        
        engine = StrategistEngine(client=mock_client, use_rag=True)
        engine._rag_engine = mock_rag
        
        result = engine.create_plan(sample_triage)
        
        # RAG should have been called
        mock_rag.get_context_sync.assert_called_once()
        assert result.vuln_class == "IDOR"
    
    @patch('ghost_hunter.core.brain.strategist.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.strategist.get_rag_engine')
    def test_rag_engine_unavailable_fallback(self, mock_get_rag, mock_client, sample_triage):
        """Test fallback when RAG engine is_available returns False."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = False
        mock_get_rag.return_value = mock_rag
        
        engine = StrategistEngine(client=mock_client, use_rag=True)
        
        # Access rag_engine property
        result = engine.rag_engine
        
        # Should return None when RAG is not available
        assert result is None
    
    @patch('ghost_hunter.core.brain.strategist.RAG_AVAILABLE', True)
    @patch('ghost_hunter.core.brain.strategist.get_rag_engine')
    def test_rag_returns_payloads_in_context(self, mock_get_rag, mock_client, sample_triage):
        """Test that RAG returns payloads embedded in context."""
        mock_rag = MagicMock()
        mock_rag.is_available.return_value = True
        # RAG returns context with payloads embedded
        mock_rag.get_context_sync.return_value = """## IDOR Techniques
- Check user_id manipulation

## Payloads
- 1
- -1
- 999999"""
        mock_get_rag.return_value = mock_rag
        
        engine = StrategistEngine(client=mock_client, use_rag=True)
        engine._rag_engine = mock_rag
        
        context, payloads = engine._get_rag_context(sample_triage)
        
        assert context is not None
        assert "Payloads" in context
        # RAG returns empty payloads list (payloads are in context)
        assert payloads == []

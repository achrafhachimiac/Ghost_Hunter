"""
Tests pour engine.py

TDD: Validation de l'orchestrateur StrategistV2Engine.
"""

import pytest
import json
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch
from ghost_hunter.core.brain.strategist_v2.engine import StrategistV2Engine
from ghost_hunter.core.brain.strategist_v2.contracts import (
    OriginalContext,
    SecurityProfile,
    RoundResult,
    RoundNPlan,
    PayloadSpec,
    AttemptResult,
    CumulativeKnowledge,
)
from ghost_hunter.core.brain.strategist_v2.history import AttackHistory


@pytest.fixture
def mock_llm_client():
    """Mock du client LLM."""
    client = MagicMock()
    client.chat.return_value = json.dumps({
        "reasoning": "Testing IDOR with ID manipulation",
        "bypass_techniques": ["unicode_normalization"],
        "payloads": [
            {
                "payload": "124",
                "encoding": "none",
                "injection_point": "user_id",
                "reasoning": "ID increment test"
            },
            {
                "payload": "122",
                "encoding": "none",
                "injection_point": "user_id",
                "reasoning": "ID decrement test"
            }
        ]
    })
    return client


@pytest.fixture
def mock_history():
    """Mock de l'historique."""
    history = MagicMock(spec=AttackHistory)
    history.get_last_round_number.return_value = 0
    history.get_rounds.return_value = []
    history.get_knowledge.return_value = CumulativeKnowledge()
    return history


@pytest.fixture
def original_context():
    """Contexte original de test."""
    return OriginalContext(
        method="GET",
        url="https://api.example.com/users/123/profile",
        headers={"Authorization": "Bearer token"},
        vuln_class="IDOR",
        confidence=85,
        interesting_params=["123"],
        triage_reasoning="Numeric ID in path",
        security_profile=SecurityProfile(waf="cloudflare")
    )


@pytest.fixture
def engine(mock_llm_client, mock_history):
    """Engine avec mocks."""
    return StrategistV2Engine(
        llm_client=mock_llm_client,
        history=mock_history
    )


class TestStrategistV2EngineInit:
    """Tests pour l'initialisation."""
    
    def test_creates_with_defaults(self):
        """Création avec valeurs par défaut."""
        engine = StrategistV2Engine()
        assert engine._history is not None
    
    def test_creates_with_custom_history(self, mock_history):
        """Création avec historique custom."""
        engine = StrategistV2Engine(history=mock_history)
        assert engine._history == mock_history


class TestGenerateNextRound:
    """Tests pour generate_next_round."""
    
    @patch('ghost_hunter.core.brain.strategist_v2.engine.get_combined_context')
    def test_generates_round_1(
        self, mock_rag, engine, original_context, mock_history
    ):
        """Génère le premier round."""
        mock_rag.return_value = "RAG context"
        mock_history.get_last_round_number.return_value = 0
        
        plan = engine.generate_next_round(
            endpoint_hash="test_hash",
            original_context=original_context,
            num_payloads=5
        )
        
        assert plan.round_number == 1
        assert len(plan.payloads) == 2
        assert plan.vuln_class == "IDOR"
    
    @patch('ghost_hunter.core.brain.strategist_v2.engine.get_combined_context')
    def test_generates_round_2_with_history(
        self, mock_rag, engine, original_context, mock_history
    ):
        """Génère le round 2 avec historique."""
        mock_rag.return_value = "RAG context"
        mock_history.get_last_round_number.return_value = 1
        mock_history.get_rounds.return_value = [
            RoundResult(
                round_number=1,
                timestamp=datetime.now(),
                plan=RoundNPlan(round_number=1, vuln_class="IDOR", payloads=[]),
                tests=[]
            )
        ]
        
        plan = engine.generate_next_round(
            endpoint_hash="test_hash",
            original_context=original_context,
            num_payloads=3
        )
        
        assert plan.round_number == 2
    
    @patch('ghost_hunter.core.brain.strategist_v2.engine.get_combined_context')
    def test_fallback_when_llm_fails(
        self, mock_rag, original_context, mock_history
    ):
        """Utilise le fallback si LLM échoue."""
        mock_rag.return_value = ""
        
        # LLM qui lève une exception
        mock_llm = MagicMock()
        mock_llm.chat.side_effect = Exception("LLM error")
        
        engine = StrategistV2Engine(
            llm_client=mock_llm,
            history=mock_history
        )
        
        plan = engine.generate_next_round(
            endpoint_hash="test_hash",
            original_context=original_context
        )
        
        # Doit retourner le fallback
        assert plan.round_number == 1
        assert "Fallback" in plan.reasoning


class TestRecordRoundResult:
    """Tests pour record_round_result."""
    
    def test_records_and_updates_knowledge(self, engine, mock_history):
        """Enregistre les résultats et met à jour la connaissance."""
        plan = RoundNPlan(
            round_number=1,
            vuln_class="IDOR",
            payloads=[PayloadSpec(payload="124", reasoning="Test")]
        )
        
        attempts = [
            AttemptResult(
                payload_original="124",
                payload_sent="124",
                encoding="none",
                injection_point="user_id",
                method="GET",
                url="http://test",
                status_code=200,
                response_time_ms=100,
                response_length=500,
                waf_blocked=False,
                is_interesting=True
            )
        ]
        
        result = engine.record_round_result(
            endpoint_hash="test_hash",
            plan=plan,
            attempts=attempts
        )
        
        assert result.round_number == 1
        assert result.passed_count == 1
        assert result.interesting_count == 1
        
        # Vérifier que l'historique a été mis à jour
        mock_history.save_round.assert_called_once()
        mock_history.save_knowledge.assert_called_once()


class TestShouldContinue:
    """Tests pour should_continue."""
    
    def test_stops_at_max_rounds(self, engine, mock_history):
        """Arrête après max rounds."""
        mock_history.get_last_round_number.return_value = 5
        
        result = engine.should_continue("test_hash", max_rounds=5)
        
        assert result is False
    
    def test_stops_when_all_blocked(self, engine, mock_history):
        """Arrête si tout est bloqué."""
        mock_history.get_last_round_number.return_value = 1
        mock_history.get_rounds.return_value = [
            RoundResult(
                round_number=1,
                timestamp=datetime.now(),
                plan=RoundNPlan(round_number=1, vuln_class="IDOR", payloads=[]),
                tests=[
                    AttemptResult(
                        payload_original="x",
                        payload_sent="x",
                        encoding="none",
                        injection_point="x",
                        method="GET",
                        url="http://test",
                        status_code=403,
                        response_time_ms=100,
                        response_length=100,
                        waf_blocked=True
                    )
                ],
                blocked_count=1,
                passed_count=0
            )
        ]
        
        result = engine.should_continue("test_hash", max_rounds=5)
        
        assert result is False
    
    def test_continues_with_interesting_results(self, engine, mock_history):
        """Continue si résultats intéressants."""
        mock_history.get_last_round_number.return_value = 1
        mock_history.get_rounds.return_value = [
            RoundResult(
                round_number=1,
                timestamp=datetime.now(),
                plan=RoundNPlan(round_number=1, vuln_class="IDOR", payloads=[]),
                tests=[
                    AttemptResult(
                        payload_original="124",
                        payload_sent="124",
                        encoding="none",
                        injection_point="user_id",
                        method="GET",
                        url="http://test",
                        status_code=200,
                        response_time_ms=100,
                        response_length=500,
                        waf_blocked=False,
                        is_interesting=True
                    )
                ],
                blocked_count=0,
                passed_count=1,
                interesting_count=1
            )
        ]
        
        result = engine.should_continue("test_hash", max_rounds=5)
        
        assert result is True
    
    def test_continues_below_max_rounds(self, engine, mock_history):
        """Continue si en dessous du max."""
        mock_history.get_last_round_number.return_value = 2
        mock_history.get_rounds.return_value = []
        
        result = engine.should_continue("test_hash", max_rounds=5)
        
        assert result is True


class TestParseLLMResponse:
    """Tests pour _parse_llm_response."""
    
    def test_parses_valid_json(self, engine):
        """Parse un JSON valide."""
        response = json.dumps({
            "reasoning": "Test reasoning",
            "bypass_techniques": ["tech1"],
            "payloads": [
                {"payload": "test", "encoding": "url", "reasoning": "Test"}
            ]
        })
        
        plan = engine._parse_llm_response(1, "IDOR", response)
        
        assert plan.round_number == 1
        assert plan.reasoning == "Test reasoning"
        assert len(plan.payloads) == 1
        assert plan.payloads[0].encoding == "url"
    
    def test_extracts_json_from_markdown(self, engine):
        """Extrait le JSON du markdown."""
        response = """Here's my analysis:

```json
{
    "reasoning": "Test",
    "payloads": [{"payload": "x", "encoding": "none"}]
}
```

Hope this helps!"""
        
        plan = engine._parse_llm_response(1, "XSS", response)
        
        assert plan.reasoning == "Test"
        assert len(plan.payloads) == 1
    
    def test_fallback_on_invalid_json(self, engine):
        """Utilise le fallback si JSON invalide."""
        response = "This is not valid JSON"
        
        plan = engine._parse_llm_response(1, "SQLi", response)
        
        assert "Fallback" in plan.reasoning


class TestFallbackPlan:
    """Tests pour _fallback_plan."""
    
    def test_idor_fallback(self, engine):
        """Fallback IDOR avec payloads pertinents."""
        plan = engine._fallback_plan(1, "IDOR")
        
        assert plan.round_number == 1
        assert plan.vuln_class == "IDOR"
        assert len(plan.payloads) > 0
        assert any("0" in p.payload or "-1" in p.payload for p in plan.payloads)
    
    def test_sqli_fallback(self, engine):
        """Fallback SQLi avec payloads pertinents."""
        plan = engine._fallback_plan(2, "SQLi")
        
        assert plan.round_number == 2
        assert any("'" in p.payload or "OR" in p.payload for p in plan.payloads)
    
    def test_unknown_vuln_fallback(self, engine):
        """Fallback pour vuln inconnue."""
        plan = engine._fallback_plan(1, "UNKNOWN")
        
        assert len(plan.payloads) > 0

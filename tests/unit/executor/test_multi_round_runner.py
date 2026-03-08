"""
Tests pour multi_round_runner.py

Tests d'intégration entre StrategistV2Engine et CustomHTTPRunner.
"""

import pytest
import json
from datetime import datetime
from unittest.mock import Mock, MagicMock, AsyncMock, patch
from ghost_hunter.core.executor.multi_round_runner import (
    MultiRoundRunner,
    MultiRoundResult,
)
from ghost_hunter.core.brain.strategist_v2.contracts import (
    OriginalContext,
    SecurityProfile,
    RoundNPlan,
    PayloadSpec,
    AttemptResult,
    RoundResult,
    CumulativeKnowledge,
)


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
def mock_strategist():
    """Mock du StrategistV2Engine."""
    strategist = MagicMock()
    
    # Plan par défaut
    default_plan = RoundNPlan(
        round_number=1,
        vuln_class="IDOR",
        payloads=[
            PayloadSpec(payload="124", reasoning="ID increment"),
            PayloadSpec(payload="0", reasoning="Boundary test"),
        ],
        reasoning="Testing IDOR with ID manipulation"
    )
    strategist.generate_next_round.return_value = default_plan
    
    # should_continue retourne False après le premier round
    strategist.should_continue.return_value = False
    
    # record_round_result retourne un RoundResult
    strategist.record_round_result.return_value = RoundResult(
        round_number=1,
        timestamp=datetime.now(),
        plan=default_plan,
        tests=[],
    )
    
    # History mock
    strategist._history = MagicMock()
    strategist._history.get_knowledge.return_value = CumulativeKnowledge()
    
    return strategist


@pytest.fixture
def mock_http_runner():
    """Mock du CustomHTTPRunner."""
    runner = MagicMock()
    return runner


@pytest.fixture
def runner(mock_http_runner, mock_strategist):
    """MultiRoundRunner avec mocks."""
    return MultiRoundRunner(
        http_runner=mock_http_runner,
        strategist=mock_strategist,
        max_rounds=3,
        payloads_per_round=5,
    )


class TestMultiRoundRunnerInit:
    """Tests pour l'initialisation."""
    
    def test_creates_with_defaults(self):
        """Création avec valeurs par défaut."""
        runner = MultiRoundRunner()
        assert runner.max_rounds == 5
        assert runner.payloads_per_round == 5
    
    def test_creates_with_custom_values(self, mock_http_runner, mock_strategist):
        """Création avec valeurs custom."""
        runner = MultiRoundRunner(
            http_runner=mock_http_runner,
            strategist=mock_strategist,
            max_rounds=10,
            payloads_per_round=3,
        )
        assert runner.max_rounds == 10
        assert runner.payloads_per_round == 3


class TestRunAttack:
    """Tests pour run_attack."""
    
    @pytest.mark.asyncio
    async def test_runs_single_round(self, runner, original_context, mock_strategist):
        """Exécute un seul round si should_continue retourne False."""
        with patch.object(runner, '_execute_round_payloads', new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = [
                AttemptResult(
                    payload_original="124",
                    payload_sent="124",
                    encoding="none",
                    injection_point="path",
                    method="GET",
                    url="http://test",
                    status_code=200,
                    response_time_ms=100,
                    response_length=500,
                    waf_blocked=False,
                )
            ]
            
            result = await runner.run_attack(
                endpoint_hash="test_hash",
                original_context=original_context,
            )
            
            assert result.total_rounds == 1
            mock_strategist.generate_next_round.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_runs_multiple_rounds(self, original_context, mock_http_runner):
        """Exécute plusieurs rounds si should_continue retourne True."""
        strategist = MagicMock()
        
        # Configurer pour 2 rounds
        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            return call_count[0] < 2  # True pour round 1, False pour round 2
        
        strategist.should_continue.side_effect = side_effect
        
        plan = RoundNPlan(round_number=1, vuln_class="IDOR", payloads=[])
        strategist.generate_next_round.return_value = plan
        strategist.record_round_result.return_value = RoundResult(
            round_number=1, timestamp=datetime.now(), plan=plan, tests=[]
        )
        strategist._history = MagicMock()
        strategist._history.get_knowledge.return_value = CumulativeKnowledge()
        
        runner = MultiRoundRunner(
            http_runner=mock_http_runner,
            strategist=strategist,
            max_rounds=5,
        )
        
        with patch.object(runner, '_execute_round_payloads', new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = []
            
            result = await runner.run_attack(
                endpoint_hash="test_hash",
                original_context=original_context,
            )
            
            # Doit avoir fait 2 rounds
            assert strategist.generate_next_round.call_count == 2


class TestApplyEncoding:
    """Tests pour _apply_encoding."""
    
    def test_url_encoding(self, runner):
        """Encodage URL."""
        result = runner._apply_encoding("test&value", "url")
        assert "test%26value" == result
    
    def test_double_url_encoding(self, runner):
        """Double encodage URL."""
        result = runner._apply_encoding("test", "double_url")
        assert "test" == result  # 'test' n'a pas de caractères spéciaux
        
        result = runner._apply_encoding("a&b", "double_url")
        assert "%2526" in result  # & devient %26 puis %2526
    
    def test_no_encoding(self, runner):
        """Pas d'encodage."""
        result = runner._apply_encoding("test<payload>", "none")
        assert result == "test<payload>"
    
    def test_base64_encoding(self, runner):
        """Encodage base64."""
        result = runner._apply_encoding("test", "base64")
        import base64
        assert result == base64.b64encode(b"test").decode()


class TestInjectInPath:
    """Tests pour _inject_in_path."""
    
    def test_replaces_numeric_id(self, runner):
        """Remplace les IDs numériques."""
        url = "https://api.example.com/users/123/profile"
        result = runner._inject_in_path(url, "999")
        
        assert "999" in result
        assert "123" not in result
    
    def test_preserves_non_numeric_parts(self, runner):
        """Préserve les parties non-numériques."""
        url = "https://api.example.com/users/123/profile"
        result = runner._inject_in_path(url, "999")
        
        assert "users" in result
        assert "profile" in result


class TestInjectInQuery:
    """Tests pour _inject_in_query."""
    
    def test_modifies_existing_param(self, runner):
        """Modifie un paramètre existant."""
        url = "https://api.example.com/search?id=123&q=test"
        result = runner._inject_in_query(url, "id", "999")
        
        assert "id=999" in result
    
    def test_modifies_first_numeric_param(self, runner):
        """Modifie le premier paramètre numérique si le param n'existe pas."""
        url = "https://api.example.com/search?user_id=456&q=test"
        result = runner._inject_in_query(url, "nonexistent", "999")
        
        # Doit avoir modifié user_id car il contient un ID
        assert "999" in result


class TestMultiRoundResult:
    """Tests pour MultiRoundResult."""
    
    def test_to_dict(self):
        """Sérialisation en dict."""
        result = MultiRoundResult(
            endpoint_hash="test_hash",
            rounds=[],
            findings=[],
            total_rounds=2,
            total_attempts=10,
            total_time_ms=5000,
            success=True,
        )
        
        data = result.to_dict()
        
        assert data["endpoint_hash"] == "test_hash"
        assert data["total_rounds"] == 2
        assert data["total_attempts"] == 10
        assert data["success"] is True
    
    def test_repr(self):
        """Représentation string."""
        result = MultiRoundResult(
            endpoint_hash="test",
            rounds=[],
            findings=[],
            total_rounds=3,
            total_attempts=15,
            total_time_ms=3000,
            success=False,
        )
        
        repr_str = repr(result)
        
        assert "rounds=3" in repr_str
        assert "attempts=15" in repr_str
        assert "success=False" in repr_str
    
    def test_summary_calculation(self):
        """Calcul du résumé."""
        rounds = [
            RoundResult(
                round_number=1,
                timestamp=datetime.now(),
                plan=RoundNPlan(round_number=1, vuln_class="IDOR", payloads=[]),
                tests=[],
                blocked_count=2,
                passed_count=3,
                interesting_count=1,
            ),
            RoundResult(
                round_number=2,
                timestamp=datetime.now(),
                plan=RoundNPlan(round_number=2, vuln_class="IDOR", payloads=[]),
                tests=[],
                blocked_count=1,
                passed_count=4,
                interesting_count=2,
            ),
        ]
        
        result = MultiRoundResult(
            endpoint_hash="test",
            rounds=rounds,
            findings=[],
            total_rounds=2,
            total_attempts=10,
            total_time_ms=1000,
            success=True,
        )
        
        data = result.to_dict()
        
        assert data["summary"]["blocked"] == 3
        assert data["summary"]["passed"] == 7
        assert data["summary"]["interesting"] == 3


class TestExtractFindings:
    """Tests pour _extract_findings."""
    
    def test_creates_finding_for_interesting_result(self, runner, original_context):
        """Crée un finding pour un résultat intéressant."""
        round_result = RoundResult(
            round_number=1,
            timestamp=datetime.now(),
            plan=RoundNPlan(round_number=1, vuln_class="IDOR", payloads=[]),
            tests=[
                AttemptResult(
                    payload_original="124",
                    payload_sent="124",
                    encoding="none",
                    injection_point="path",
                    method="GET",
                    url="http://test",
                    status_code=200,
                    response_time_ms=100,
                    response_length=500,
                    waf_blocked=False,
                    is_interesting=True,
                    diff_indicators=["different_content", "user_data_leak"],
                )
            ],
        )
        
        findings = runner._extract_findings(round_result, original_context)
        
        assert len(findings) == 1
        assert findings[0].vuln_type == "IDOR"
    
    def test_no_finding_for_blocked_result(self, runner, original_context):
        """Pas de finding si bloqué."""
        round_result = RoundResult(
            round_number=1,
            timestamp=datetime.now(),
            plan=RoundNPlan(round_number=1, vuln_class="IDOR", payloads=[]),
            tests=[
                AttemptResult(
                    payload_original="124",
                    payload_sent="124",
                    encoding="none",
                    injection_point="path",
                    method="GET",
                    url="http://test",
                    status_code=403,
                    response_time_ms=100,
                    response_length=500,
                    waf_blocked=True,
                    is_interesting=False,
                    diff_indicators=[],
                )
            ],
        )
        
        findings = runner._extract_findings(round_result, original_context)
        
        assert len(findings) == 0


class TestDetermineSeverity:
    """Tests pour _determine_severity."""
    
    def test_idor_severity(self, runner):
        """IDOR = HIGH."""
        from ghost_hunter.core.contracts import FindingSeverity
        
        severity = runner._determine_severity("IDOR", MagicMock())
        
        assert severity == FindingSeverity.HIGH
    
    def test_sqli_severity(self, runner):
        """SQLi = CRITICAL."""
        from ghost_hunter.core.contracts import FindingSeverity
        
        severity = runner._determine_severity("SQLI", MagicMock())
        
        assert severity == FindingSeverity.CRITICAL
    
    def test_unknown_severity(self, runner):
        """Unknown = MEDIUM."""
        from ghost_hunter.core.contracts import FindingSeverity
        
        severity = runner._determine_severity("UNKNOWN", MagicMock())
        
        assert severity == FindingSeverity.MEDIUM

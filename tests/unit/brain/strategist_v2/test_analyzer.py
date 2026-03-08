"""
Tests pour analyzer.py

TDD: Validation de l'analyse des réponses HTTP et détection WAF.
"""

import pytest
from datetime import datetime
from ghost_hunter.core.brain.strategist_v2.analyzer import (
    analyze_http_response,
    create_round_result,
    _detect_waf_block,
    _compute_diff_indicators,
    _is_interesting_response,
    _extract_blocked_patterns,
    _extract_working_techniques,
    _extract_promising_results,
)
from ghost_hunter.core.brain.strategist_v2.contracts import (
    AttemptResult,
    RoundNPlan,
    PayloadSpec,
)


class TestDetectWafBlock:
    """Tests pour _detect_waf_block."""
    
    def test_cloudflare_block(self):
        """Détecte un blocage Cloudflare."""
        is_blocked, provider, signature = _detect_waf_block(
            status_code=403,
            response_body="Attention Required! Cloudflare Ray ID: abc123",
            response_headers={"cf-ray": "abc123"}
        )
        
        assert is_blocked is True
        assert provider == "cloudflare"
        # Signature peut être "attention required" ou autre pattern cloudflare
        assert signature is not None
    
    def test_aws_waf_block(self):
        """Détecte un blocage AWS WAF."""
        is_blocked, provider, signature = _detect_waf_block(
            status_code=403,
            response_body="Request blocked by AWS WAF",
            response_headers={"x-amzn-requestid": "xyz"}
        )
        
        assert is_blocked is True
        assert provider == "aws_waf"
    
    def test_generic_403_block(self):
        """Détecte un 403 sans signature claire."""
        is_blocked, provider, signature = _detect_waf_block(
            status_code=403,
            response_body="Forbidden",
            response_headers={}
        )
        
        assert is_blocked is True
        assert provider == "unknown"
        assert "403" in signature
    
    def test_rate_limit_429(self):
        """Détecte un rate limit 429."""
        is_blocked, provider, signature = _detect_waf_block(
            status_code=429,
            response_body="Rate limited. Please try again later.",
            response_headers={}
        )
        
        assert is_blocked is True
    
    def test_successful_response(self):
        """Ne détecte pas de blocage pour réponse OK."""
        is_blocked, provider, signature = _detect_waf_block(
            status_code=200,
            response_body='{"id": 123, "name": "test"}',
            response_headers={}
        )
        
        assert is_blocked is False
        assert provider is None
    
    def test_akamai_block(self):
        """Détecte un blocage Akamai."""
        is_blocked, provider, signature = _detect_waf_block(
            status_code=403,
            response_body="Reference #123.456.789 - Access Denied",
            response_headers={"akamai-grn": "xyz"}
        )
        
        assert is_blocked is True
        assert provider == "akamai"


class TestComputeDiffIndicators:
    """Tests pour _compute_diff_indicators."""
    
    def test_status_diff(self):
        """Détecte une différence de status."""
        indicators = _compute_diff_indicators(
            status_code=403,
            response_length=500,
            response_time_ms=100,
            baseline_status=200,
            baseline_length=500,
            baseline_time_ms=100
        )
        
        assert any("status_diff" in i for i in indicators)
        assert "200->403" in indicators[0]
    
    def test_length_diff(self):
        """Détecte une différence de longueur."""
        indicators = _compute_diff_indicators(
            status_code=200,
            response_length=1000,
            response_time_ms=100,
            baseline_status=200,
            baseline_length=500,
            baseline_time_ms=100
        )
        
        assert any("length_diff" in i for i in indicators)
    
    def test_time_diff(self):
        """Détecte une différence de temps significative."""
        indicators = _compute_diff_indicators(
            status_code=200,
            response_length=500,
            response_time_ms=1500,
            baseline_status=200,
            baseline_length=500,
            baseline_time_ms=100
        )
        
        assert any("time_diff" in i for i in indicators)
    
    def test_no_baseline(self):
        """Gère le cas sans baseline."""
        indicators = _compute_diff_indicators(
            status_code=200,
            response_length=500,
            response_time_ms=100,
            baseline_status=None,
            baseline_length=None,
            baseline_time_ms=None
        )
        
        assert indicators == []


class TestIsInterestingResponse:
    """Tests pour _is_interesting_response."""
    
    def test_waf_blocked_not_interesting(self):
        """Réponse bloquée par WAF n'est pas intéressante."""
        result = _is_interesting_response(
            status_code=403,
            diff_indicators=[],
            waf_blocked=True,
            response_body="Blocked"
        )
        
        assert result is False
    
    def test_diff_indicators_interesting(self):
        """Différences avec baseline = intéressant."""
        result = _is_interesting_response(
            status_code=200,
            diff_indicators=["status_diff:200->200", "length_diff:50%"],
            waf_blocked=False,
            response_body="Different content"
        )
        
        assert result is True
    
    def test_user_data_interesting(self):
        """Données utilisateur = intéressant."""
        # Body doit être > 100 chars pour déclencher la détection
        result = _is_interesting_response(
            status_code=200,
            diff_indicators=[],
            waf_blocked=False,
            response_body='{"id": 456, "email": "other@example.com", "name": "John Doe", "address": "123 Main St", "phone": "555-1234"}'
        )
        
        assert result is True
    
    def test_empty_response_not_interesting(self):
        """Réponse vide pas intéressante."""
        result = _is_interesting_response(
            status_code=200,
            diff_indicators=[],
            waf_blocked=False,
            response_body=""
        )
        
        assert result is False


class TestAnalyzeHttpResponse:
    """Tests pour analyze_http_response."""
    
    def test_full_analysis(self):
        """Analyse complète d'une réponse."""
        result = analyze_http_response(
            payload_original="124",
            payload_sent="124",
            encoding="none",
            injection_point="user_id",
            method="GET",
            url="https://api.example.com/users/124",
            status_code=200,
            response_time_ms=150,
            response_body='{"id": 124, "name": "Other User"}',
            response_headers={},
            baseline_status=200,
            baseline_length=100,
            baseline_time_ms=100
        )
        
        assert isinstance(result, AttemptResult)
        assert result.payload_original == "124"
        assert result.waf_blocked is False
        assert result.status_code == 200
    
    def test_waf_blocked_analysis(self):
        """Analyse d'une réponse bloquée."""
        result = analyze_http_response(
            payload_original="' OR 1=1--",
            payload_sent="%27%20OR%201%3D1--",
            encoding="url",
            injection_point="id",
            method="GET",
            url="https://api.example.com/users?id=%27%20OR%201%3D1--",
            status_code=403,
            response_time_ms=50,
            response_body="Access Denied by Cloudflare Ray ID: abc",
            response_headers={"cf-ray": "abc"}
        )
        
        assert result.waf_blocked is True
        assert result.waf_provider == "cloudflare"
        assert result.is_interesting is False


class TestCreateRoundResult:
    """Tests pour create_round_result."""
    
    def test_creates_result_with_stats(self):
        """Crée un RoundResult avec stats calculées."""
        plan = RoundNPlan(
            round_number=1,
            vuln_class="IDOR",
            payloads=[PayloadSpec(payload="124")],
            reasoning="Test"
        )
        
        attempts = [
            AttemptResult(
                payload_original="124",
                payload_sent="124",
                encoding="none",
                injection_point="id",
                method="GET",
                url="http://test",
                status_code=403,
                response_time_ms=100,
                response_length=500,
                waf_blocked=True
            ),
            AttemptResult(
                payload_original="122",
                payload_sent="122",
                encoding="none",
                injection_point="id",
                method="GET",
                url="http://test",
                status_code=200,
                response_time_ms=100,
                response_length=500,
                waf_blocked=False,
                is_interesting=True,
                diff_indicators=["length_diff:10%"]
            ),
        ]
        
        result = create_round_result(1, plan, attempts)
        
        assert result.round_number == 1
        assert result.blocked_count == 1
        assert result.passed_count == 1
        assert result.interesting_count == 1
        assert len(result.blocked_patterns) == 1
        assert len(result.working_techniques) == 1
        assert len(result.promising_results) == 1


class TestExtractPatterns:
    """Tests pour les fonctions d'extraction de patterns."""
    
    def test_extract_blocked_patterns(self):
        """Extrait les patterns bloqués."""
        attempts = [
            AttemptResult(
                payload_original="' OR 1=1--",
                payload_sent="xxx",
                encoding="url",
                injection_point="id",
                method="GET",
                url="http://test",
                status_code=403,
                response_time_ms=100,
                response_length=100,
                waf_blocked=True
            )
        ]
        
        patterns = _extract_blocked_patterns(attempts)
        
        assert len(patterns) == 1
        assert "url:" in patterns[0]
        assert "OR 1=1" in patterns[0]
    
    def test_extract_working_techniques(self):
        """Extrait les techniques qui marchent."""
        attempts = [
            AttemptResult(
                payload_original="test",
                payload_sent="test",
                encoding="unicode",
                injection_point="name",
                method="GET",
                url="http://test",
                status_code=200,
                response_time_ms=100,
                response_length=100,
                waf_blocked=False
            )
        ]
        
        techniques = _extract_working_techniques(attempts)
        
        assert len(techniques) == 1
        assert "unicode" in techniques[0]
        assert "name" in techniques[0]
    
    def test_extract_promising_results(self):
        """Extrait les résultats prometteurs."""
        attempts = [
            AttemptResult(
                payload_original="interesting_payload_here",
                payload_sent="xxx",
                encoding="none",
                injection_point="x",
                method="GET",
                url="http://test",
                status_code=200,
                response_time_ms=100,
                response_length=100,
                is_interesting=True,
                diff_indicators=["length_diff:50%"]
            )
        ]
        
        results = _extract_promising_results(attempts)
        
        assert len(results) == 1
        assert "interesting_payload" in results[0]
        assert "200" in results[0]

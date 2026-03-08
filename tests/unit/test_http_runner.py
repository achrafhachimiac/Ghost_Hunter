"""
Tests unitaires pour http_runner.py
"""

import pytest
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from ghost_hunter.core.executor.http_runner import (
    CustomHTTPRunner,
)
from ghost_hunter.core.executor.constants import (
    ERROR_PATTERNS,
)
from ghost_hunter.core.executor.response_analyzer import ResponseAnalyzer
from ghost_hunter.core.executor.finding_factory import FindingFactory
from ghost_hunter.core.executor.tool_wrapper import (
    ToolConfig,
    ExecutionContext,
)
from ghost_hunter.core.contracts import (
    AttackPlan,
    TriageDecision,
    ScoredRequest,
    FilteredRequest,
    InterceptedRequest,
    TestPhase,
    FindingSeverity,
    PayloadVariant,
    ResponseSignature,
)


# ==================== Fixtures ====================

@pytest.fixture
def http_runner():
    return CustomHTTPRunner()


@pytest.fixture
def sample_attack_plan():
    req = InterceptedRequest(
        method="GET",
        url="https://api.example.com/users/123",
        host="api.example.com",
        path="/users/123",
        query_params={"id": "123"},
    )
    filtered = FilteredRequest(request=req, in_scope=True)
    scored = ScoredRequest(request=filtered, score=75)
    triage = TriageDecision(
        request=scored,
        interesting=True,
        confidence=85,
        suggested_vulns=["SQLi"],
        test_phase=TestPhase.SAFE,
    )
    return AttackPlan(
        request=triage,
        tool="custom",
        vuln_class="SQLi",
        payloads=[
            PayloadVariant(payload="'"),
            PayloadVariant(payload="' OR '1'='1"),
        ],
        injection_points=["id"],
    )


@pytest.fixture
def execution_context(sample_attack_plan, tmp_path):
    return ExecutionContext(
        plan=sample_attack_plan,
        working_dir=tmp_path,
        output_dir=tmp_path / "output",
    )


# ==================== Tests ====================

class TestCustomHTTPRunner:
    
    def test_runner_creation(self, http_runner):
        assert http_runner.config.name == "custom_http"
        assert http_runner.is_available is True
    
    def test_default_config(self, http_runner):
        assert http_runner.config.timeout_seconds == 30
        assert http_runner.follow_redirects is False
        assert http_runner.verify_ssl is False


class TestPayloadEncoding:
    
    def test_encode_none(self, http_runner):
        payload = PayloadVariant(payload="test'payload", encoding="none")
        result = http_runner._encode_payload(payload)
        assert result == "test'payload"
    
    def test_encode_url(self, http_runner):
        payload = PayloadVariant(payload="<script>", encoding="url")
        result = http_runner._encode_payload(payload)
        assert result == "%3Cscript%3E"
    
    def test_encode_double_url(self, http_runner):
        payload = PayloadVariant(payload="<", encoding="double_url")
        result = http_runner._encode_payload(payload)
        assert result == "%253C"
    
    def test_encode_html(self, http_runner):
        payload = PayloadVariant(payload="<script>", encoding="html")
        result = http_runner._encode_payload(payload)
        assert "&lt;script&gt;" in result


class TestRequestBuilding:
    
    def test_build_with_query_param_injection(self, http_runner):
        req = MagicMock()
        req.url = "https://example.com/api?id=123"
        req.query_params = {"id": "123"}
        req.body_json = None
        req.body = None
        req.headers = {}
        req.cookies = {}
        
        url, headers, body, injection_success = http_runner._build_request(req, "PAYLOAD", "id")
        
        assert injection_success
        assert "PAYLOAD" in url
        assert "id=PAYLOAD" in url or "id%3DPAYLOAD" in url.replace("=", "%3D")
    
    def test_build_with_body_json_injection(self, http_runner):
        req = MagicMock()
        req.url = "https://example.com/api"
        req.query_params = {}
        req.body_json = {"user": "test", "pass": "secret"}
        req.body = '{"user": "test", "pass": "secret"}'  # Raw body for text replacement
        req.headers = {}
        req.cookies = {}
        
        url, headers, body, injection_success = http_runner._build_request(req, "PAYLOAD", "user")
        
        assert injection_success
        assert body is not None
        assert '"user":"PAYLOAD"' in body or '"user": "PAYLOAD"' in body
    
    def test_build_with_form_urlencoded_array_injection(self, http_runner):
        """Test injection into form-urlencoded body with array notation like Rails params."""
        req = MagicMock()
        req.url = "https://example.com/bulk_update"
        req.query_params = {}
        req.body_json = None
        # Simulating Rails-style array params: visit_motive_categories_attributes[][id]=500067
        req.body = "authenticity_token=abc123&visit_motive_categories_attributes%5B%5D%5Bid%5D=500067&visit_motive_categories_attributes%5B%5D%5Bname%5D=test"
        req.headers = {"Content-Type": "application/x-www-form-urlencoded"}
        req.cookies = {}
        
        url, headers, body, injection_success = http_runner._build_request(
            req, "999999", "visit_motive_categories_attributes[].id"
        )
        
        assert injection_success, "Should successfully inject into form array param"
        assert "999999" in body
        # Original value should be replaced
        assert "500067" not in body
    
    def test_build_adds_user_agent(self, http_runner):
        req = MagicMock()
        req.url = "https://example.com"
        req.query_params = {}
        req.body_json = None
        req.body = None
        req.headers = {}
        req.cookies = {}
        
        url, headers, body, injection_success = http_runner._build_request(req, "test", "param")
        
        assert "User-Agent" in headers


class TestErrorPatterns:
    
    def test_sqli_patterns_exist(self):
        assert "sqli" in ERROR_PATTERNS
        assert len(ERROR_PATTERNS["sqli"]) > 5
    
    def test_xss_patterns_exist(self):
        assert "xss" in ERROR_PATTERNS
    
    def test_lfi_patterns_exist(self):
        assert "lfi" in ERROR_PATTERNS
    
    def test_pattern_matches_mysql_error(self):
        import re
        content = "You have an error in your SQL syntax near MySQL"
        
        matched = False
        for pattern in ERROR_PATTERNS["sqli"]:
            if re.search(pattern, content, re.IGNORECASE):
                matched = True
                break
        
        assert matched


class TestResponseAnalysis:
    """Tests for ResponseAnalyzer class."""
    
    def test_is_potential_finding_with_error_pattern(self):
        signature = ResponseSignature(
            status_code=200,
            error_patterns_found=["SQL syntax.*MySQL"],
        )
        response = MagicMock()
        response.status_code = 200
        
        result = ResponseAnalyzer.is_potential_finding(signature, "SQLi", response)
        assert result is True
    
    def test_is_potential_finding_with_xss_reflection(self):
        signature = ResponseSignature(
            status_code=200,
            reflection_found=True,
        )
        response = MagicMock()
        response.status_code = 200
        
        result = ResponseAnalyzer.is_potential_finding(signature, "XSS", response)
        assert result is True
    
    def test_is_potential_finding_with_timing(self):
        signature = ResponseSignature(
            status_code=200,
            timing_anomaly=True,
            response_time_ms=6000,
        )
        response = MagicMock()
        response.status_code = 200
        
        result = ResponseAnalyzer.is_potential_finding(signature, "SQLi", response)
        assert result is True
    
    def test_is_potential_finding_500_error(self):
        signature = ResponseSignature(status_code=500)
        response = MagicMock()
        response.status_code = 500
        
        result = ResponseAnalyzer.is_potential_finding(signature, "SQLi", response)
        assert result is True


class TestSeverityDetermination:
    """Tests for FindingFactory.determine_severity()."""
    
    def test_sqli_severity(self):
        signature = ResponseSignature()
        severity = FindingFactory.determine_severity(signature, "SQLi")
        assert severity == FindingSeverity.HIGH
    
    def test_rce_severity(self):
        signature = ResponseSignature()
        severity = FindingFactory.determine_severity(signature, "RCE")
        assert severity == FindingSeverity.CRITICAL
    
    def test_xss_severity(self):
        signature = ResponseSignature()
        severity = FindingFactory.determine_severity(signature, "XSS")
        assert severity == FindingSeverity.MEDIUM
    
    def test_severity_upgrade_with_multiple_patterns(self):
        signature = ResponseSignature(
            error_patterns_found=["pattern1", "pattern2"],
        )
        severity = FindingFactory.determine_severity(signature, "XSS")
        assert severity == FindingSeverity.HIGH


class TestConfidenceCalculation:
    """Tests for FindingFactory.calculate_confidence()."""
    
    def test_base_confidence(self):
        signature = ResponseSignature()
        confidence = FindingFactory.calculate_confidence(signature, "SQLi")
        assert confidence == 30
    
    def test_confidence_with_error_pattern(self):
        signature = ResponseSignature(
            error_patterns_found=["one_pattern"],
        )
        confidence = FindingFactory.calculate_confidence(signature, "SQLi")
        assert confidence == 50
    
    def test_confidence_with_reflection(self):
        signature = ResponseSignature(reflection_found=True)
        confidence = FindingFactory.calculate_confidence(signature, "XSS")
        assert confidence == 55
    
    def test_confidence_capped_at_95(self):
        signature = ResponseSignature(
            error_patterns_found=["p1", "p2", "p3", "p4"],
            reflection_found=True,
            timing_anomaly=True,
        )
        confidence = FindingFactory.calculate_confidence(signature, "SQLi")
        assert confidence <= 95


class TestSubtypeDetermination:
    """Tests for FindingFactory.determine_subtype()."""
    
    def test_time_based_subtype(self):
        signature = ResponseSignature(timing_anomaly=True)
        subtype = FindingFactory.determine_subtype(signature, "SQLi")
        assert subtype == "time-based"
    
    def test_error_based_subtype(self):
        signature = ResponseSignature(error_patterns_found=["pattern"])
        subtype = FindingFactory.determine_subtype(signature, "SQLi")
        assert subtype == "error-based"
    
    def test_reflected_subtype(self):
        signature = ResponseSignature(reflection_found=True)
        subtype = FindingFactory.determine_subtype(signature, "XSS")
        assert subtype == "reflected"


class TestAnalysisGeneration:
    """Tests for FindingFactory.generate_analysis()."""
    
    def test_analysis_with_patterns(self):
        signature = ResponseSignature(
            error_patterns_found=["MySQL error"],
        )
        analysis = FindingFactory.generate_analysis(signature, "SQLi")
        assert "Error patterns" in analysis
    
    def test_analysis_with_reflection(self):
        signature = ResponseSignature(reflection_found=True)
        analysis = FindingFactory.generate_analysis(signature, "XSS")
        assert "reflected" in analysis
    
    def test_analysis_with_timing(self):
        signature = ResponseSignature(
            timing_anomaly=True,
            response_time_ms=8000,
        )
        analysis = FindingFactory.generate_analysis(signature, "SQLi")
        assert "time-based" in analysis.lower()


class TestDryRun:
    
    def test_dry_run_execution(self, http_runner, execution_context):
        import asyncio
        execution_context.dry_run = True
        
        result = asyncio.get_event_loop().run_until_complete(http_runner.execute(execution_context))
        
        assert result.success is True
        assert result.execution_time_ms == 0

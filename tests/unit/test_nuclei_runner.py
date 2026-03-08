"""
Tests unitaires pour nuclei_runner.py
"""

import pytest
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from ghost_hunter.core.executor.nuclei_runner import (
    NucleiRunner,
    SEVERITY_MAP,
    register_nuclei,
)
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
)


# ==================== Fixtures ====================

@pytest.fixture
def nuclei_runner():
    config = ToolConfig(
        name="nuclei",
        executable="nuclei",
        timeout_seconds=60,
    )
    return NucleiRunner(config=config, rate_limit=100)


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
        suggested_vulns=["IDOR"],
        test_phase=TestPhase.SAFE,
    )
    return AttackPlan(
        request=triage,
        tool="nuclei",
        vuln_class="IDOR",
        payloads=[PayloadVariant(payload="1")],
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

class TestNucleiRunner:
    
    def test_runner_creation(self, nuclei_runner):
        assert nuclei_runner.config.name == "nuclei"
        assert nuclei_runner.rate_limit == 100
    
    def test_default_config(self):
        runner = NucleiRunner()
        assert runner.config.name == "nuclei"
        assert runner.config.timeout_seconds == 600
    
    def test_severity_mapping(self):
        assert SEVERITY_MAP["critical"] == FindingSeverity.CRITICAL
        assert SEVERITY_MAP["high"] == FindingSeverity.HIGH
        assert SEVERITY_MAP["medium"] == FindingSeverity.MEDIUM
        assert SEVERITY_MAP["low"] == FindingSeverity.LOW
        assert SEVERITY_MAP["info"] == FindingSeverity.INFO


class TestNucleiOutputParsing:
    
    def test_parse_empty_output(self, nuclei_runner):
        result = nuclei_runner.parse_output("")
        assert result["count"] == 0
        assert result["findings"] == []
    
    def test_parse_single_finding(self, nuclei_runner):
        output = json.dumps({
            "template-id": "test-template",
            "info": {
                "name": "Test Vuln",
                "severity": "high",
            },
            "matched-at": "https://example.com/test",
            "host": "example.com",
        })
        
        result = nuclei_runner.parse_output(output)
        assert result["count"] == 1
    
    def test_parse_multiple_findings(self, nuclei_runner):
        finding1 = json.dumps({"template-id": "t1", "info": {"name": "V1", "severity": "high"}})
        finding2 = json.dumps({"template-id": "t2", "info": {"name": "V2", "severity": "medium"}})
        
        output = f"{finding1}\n{finding2}"
        result = nuclei_runner.parse_output(output)
        
        assert result["count"] == 2
    
    def test_parse_malformed_json(self, nuclei_runner):
        output = "not json at all\n{invalid}"
        result = nuclei_runner.parse_output(output)
        assert result["count"] == 0


class TestNucleiToFinding:
    
    def test_convert_basic_finding(self, nuclei_runner):
        nuclei_result = {
            "template-id": "sqli-test",
            "info": {
                "name": "SQL Injection",
                "severity": "high",
                "description": "SQL injection vulnerability",
            },
            "matched-at": "https://example.com/search?q=test",
            "host": "example.com",
            "type": "http",
            "request": "GET /search?q=' OR 1=1-- HTTP/1.1",
            "response": "Error in SQL syntax",
        }
        
        finding = nuclei_runner._nuclei_to_finding(nuclei_result)
        
        assert finding is not None
        assert finding.vuln_type == "SQL Injection"
        assert finding.vuln_subtype == "sqli-test"
        assert finding.severity == FindingSeverity.HIGH
        assert finding.tool_used == "nuclei"
    
    def test_convert_with_cwe(self, nuclei_runner):
        nuclei_result = {
            "template-id": "xss-test",
            "info": {
                "name": "XSS",
                "severity": "medium",
                "classification": {
                    "cwe-id": ["CWE-79"],
                },
            },
            "matched-at": "https://example.com/page",
        }
        
        finding = nuclei_runner._nuclei_to_finding(nuclei_result)
        
        assert finding.cwe_id == "CWE-79"
    
    def test_convert_invalid_result(self, nuclei_runner):
        # Should handle gracefully
        finding = nuclei_runner._nuclei_to_finding({})
        # Either returns None or a finding with defaults
        assert finding is None or finding.vuln_type == "Unknown"


class TestNucleiConfidenceCalculation:
    
    def test_base_confidence(self, nuclei_runner):
        result = {"info": {}, "matcher-name": ""}
        confidence = nuclei_runner._calculate_confidence(result)
        assert confidence == 50
    
    def test_confidence_with_status_matcher(self, nuclei_runner):
        result = {"info": {}, "matcher-name": "status-200"}
        confidence = nuclei_runner._calculate_confidence(result)
        assert confidence == 60
    
    def test_confidence_with_regex_matcher(self, nuclei_runner):
        result = {"info": {}, "matcher-name": "regex-match"}
        confidence = nuclei_runner._calculate_confidence(result)
        assert confidence == 70
    
    def test_confidence_with_extractor(self, nuclei_runner):
        result = {
            "info": {},
            "matcher-name": "",
            "extracted-results": ["sensitive_data"],
        }
        confidence = nuclei_runner._calculate_confidence(result)
        assert confidence == 65
    
    def test_confidence_high_severity(self, nuclei_runner):
        result = {"info": {"severity": "critical"}, "matcher-name": ""}
        confidence = nuclei_runner._calculate_confidence(result)
        assert confidence == 65


class TestNucleiCommandBuilding:
    
    def test_build_command_basic(self, nuclei_runner, execution_context, tmp_path):
        target_file = tmp_path / "targets.txt"
        target_file.write_text("https://example.com")
        
        args = nuclei_runner._build_command(execution_context, target_file)
        
        assert "nuclei" in args
        assert "-l" in args
        assert "-json" in args
        assert "-silent" in args
    
    def test_build_command_with_tags(self, nuclei_runner, execution_context, tmp_path):
        target_file = tmp_path / "targets.txt"
        execution_context.plan.vuln_class = "SQLi"
        
        args = nuclei_runner._build_command(execution_context, target_file)
        
        assert "-tags" in args
        tags_index = args.index("-tags")
        assert "sqli" in args[tags_index + 1] or "sql-injection" in args[tags_index + 1]


class TestNucleiTemplateGeneration:
    
    def test_generate_custom_template(self, nuclei_runner, sample_attack_plan, tmp_path):
        output_path = tmp_path / "custom_template.yaml"
        
        result = nuclei_runner.generate_custom_template(sample_attack_plan, output_path)
        
        assert result.exists()
        content = result.read_text()
        assert "ghost-hunter" in content
        assert "IDOR" in content.lower() or "idor" in content
    
    def test_template_has_required_fields(self, nuclei_runner, sample_attack_plan, tmp_path):
        import yaml
        
        output_path = tmp_path / "template.yaml"
        nuclei_runner.generate_custom_template(sample_attack_plan, output_path)
        
        template = yaml.safe_load(output_path.read_text())
        
        assert "id" in template
        assert "info" in template
        assert "name" in template["info"]
        assert "severity" in template["info"]

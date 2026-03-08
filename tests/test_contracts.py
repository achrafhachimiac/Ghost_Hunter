"""
Ghost-Hunter Test Contracts
===========================
Tests unitaires pour les contrats de données.
"""

import pytest
from ghost_hunter.core.contracts import *


class TestContractInstantiation:
    """Vérifie que tous les contrats peuvent être instanciés."""
    
    def test_intercepted_request(self):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/123",
            host="example.com",
            path="/api/users/123"
        )
        assert req.id is not None
        assert req.method == "GET"
        assert req.get_endpoint_template() == "/api/users/{id}"
    
    def test_intercepted_request_uuid_template(self):
        req = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users/550e8400-e29b-41d4-a716-446655440000",
            host="example.com",
            path="/api/users/550e8400-e29b-41d4-a716-446655440000"
        )
        assert req.get_endpoint_template() == "/api/users/{uuid}"
    
    def test_filtered_request(self):
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/")
        filtered = FilteredRequest(request=req, in_scope=True, scope_match="*.example.com")
        assert filtered.domain == "example.com"
    
    def test_dedup_result(self):
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/api/users")
        filtered = FilteredRequest(request=req, in_scope=True)
        dedup = DedupResult(request=filtered)
        hash_val = dedup.compute_hash()
        assert len(hash_val) == 16
    
    def test_dedup_hash_consistency(self):
        """Same request should produce same hash."""
        req1 = InterceptedRequest(method="GET", url="https://example.com/api/users/1", host="example.com", path="/api/users/1")
        req2 = InterceptedRequest(method="GET", url="https://example.com/api/users/2", host="example.com", path="/api/users/2")
        
        filtered1 = FilteredRequest(request=req1, in_scope=True)
        filtered2 = FilteredRequest(request=req2, in_scope=True)
        
        dedup1 = DedupResult(request=filtered1)
        dedup2 = DedupResult(request=filtered2)
        
        # Same endpoint template, should have same hash
        assert dedup1.compute_hash() == dedup2.compute_hash()
    
    def test_scored_request(self):
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/")
        filtered = FilteredRequest(request=req, in_scope=True)
        scored = ScoredRequest(request=filtered, score=75)
        scored.compute_priority()
        assert scored.priority == Priority.HIGH
    
    def test_priority_levels(self):
        """Test all priority threshold levels."""
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/")
        filtered = FilteredRequest(request=req, in_scope=True)
        
        # Critical: >= 80
        critical = ScoredRequest(request=filtered, score=85)
        critical.compute_priority()
        assert critical.priority == Priority.CRITICAL
        
        # High: >= 60
        high = ScoredRequest(request=filtered, score=65)
        high.compute_priority()
        assert high.priority == Priority.HIGH
        
        # Medium: >= 40
        medium = ScoredRequest(request=filtered, score=45)
        medium.compute_priority()
        assert medium.priority == Priority.MEDIUM
        
        # Low: < 40
        low = ScoredRequest(request=filtered, score=30)
        low.compute_priority()
        assert low.priority == Priority.LOW
    
    def test_finding_severity_enum(self):
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"
    
    def test_finding_status_enum(self):
        assert FindingStatus.NEW.value == "new"
        assert FindingStatus.VERIFIED.value == "verified"
        assert FindingStatus.FALSE_POSITIVE.value == "false_positive"
    
    def test_finding(self):
        finding = Finding(
            endpoint="/api/users/123",
            method="GET",
            vuln_type="IDOR",
            severity=FindingSeverity.HIGH,
            confidence=90
        )
        assert finding.id is not None
        assert finding.status == FindingStatus.NEW
        assert finding.severity == FindingSeverity.HIGH
    
    def test_triage_decision(self):
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/")
        filtered = FilteredRequest(request=req, in_scope=True)
        scored = ScoredRequest(request=filtered, score=50)
        
        triage = TriageDecision(
            request=scored,
            interesting=True,
            reason="Potential IDOR",
            confidence=80,
            suggested_vulns=["IDOR"]
        )
        assert triage.interesting == True
        assert triage.test_phase == TestPhase.SAFE
    
    def test_attack_plan(self):
        plan = AttackPlan(
            tool="nuclei",
            vuln_class="SQLi",
            payloads=[PayloadVariant(payload="' OR '1'='1", encoding="none")],
            injection_points=["id", "search"]
        )
        assert plan.id is not None
        assert plan.tool == "nuclei"
        assert len(plan.payloads) == 1
    
    def test_baseline_record(self):
        baseline = BaselineRecord(
            endpoint_hash="abc123",
            method="GET",
            url_template="/api/users/{id}",
            status_code=200,
            body_length=1500,
            response_time_ms=150.5
        )
        assert baseline.status_code == 200
        assert baseline.recorded_at > 0
    
    def test_diff_result(self):
        baseline = BaselineRecord(status_code=200)
        diff = DiffResult(
            baseline=baseline,
            status_changed=True,
            body_changed=False,
            timing_anomaly=True,
            timing_delta_ms=600
        )
        assert diff.status_changed == True
        assert diff.timing_anomaly == True
    
    def test_exploit_chain(self):
        step1 = ChainStep(
            step_number=1,
            name="Get user ID",
            vuln_class="Info Disclosure",
            endpoint="/api/users",
            produces=["user_id"]
        )
        step2 = ChainStep(
            step_number=2,
            name="Access private data",
            vuln_class="IDOR",
            endpoint="/api/users/{id}/private",
            depends_on=["user_id"]
        )
        
        chain = ExploitChain(
            name="User Data Access",
            description="Chain to access private user data",
            steps=[step1, step2],
            impact_if_complete="Access to any user's private data"
        )
        assert len(chain.steps) == 2
        assert chain.status == ChainStatus.PENDING
    
    def test_security_profile(self):
        profile = SecurityProfile(
            target="example.com",
            waf_detected=True,
            waf_provider="Cloudflare",
            waf_confidence=95,
            auth_type="jwt",
            recommended_evasion=["unicode_normalization", "header_smuggling"]
        )
        assert profile.waf_detected == True
        assert len(profile.recommended_evasion) == 2
    
    def test_oob_callback(self):
        callback = OOBCallback(
            callback_type="dns",
            token="abc123xyz",
            source_ip="1.2.3.4",
            source_port=53,
            injection_point="user_agent"
        )
        assert callback.id is not None
        assert callback.callback_type == "dns"
    
    def test_session_stats(self):
        stats = SessionStats(
            session_id="session_001",
            target="example.com",
            total_intercepted=1000,
            total_in_scope=500,
            findings_critical=2,
            findings_high=5,
            tokens_used_haiku=50000,
            estimated_cost_usd=0.25
        )
        assert stats.total_intercepted == 1000
        assert stats.findings_critical == 2
    
    def test_validate_contract_helper(self):
        req = InterceptedRequest(method="GET", url="https://example.com", host="example.com", path="/")
        assert validate_contract(req, InterceptedRequest) == True
        assert validate_contract(req, FilteredRequest) == False
    
    def test_http_method_enum(self):
        assert HttpMethod.GET.value == "GET"
        assert HttpMethod.POST.value == "POST"
        assert HttpMethod.DELETE.value == "DELETE"
    
    def test_test_phase_enum(self):
        assert TestPhase.SAFE.value == "safe"
        assert TestPhase.MEDIUM.value == "medium"
        assert TestPhase.RISKY.value == "risky"
    
    def test_chain_status_enum(self):
        assert ChainStatus.PENDING.value == "pending"
        assert ChainStatus.IN_PROGRESS.value == "in_progress"
        assert ChainStatus.COMPLETED.value == "completed"

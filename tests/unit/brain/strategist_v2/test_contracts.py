"""
Tests pour strategist_v2/contracts.py

TDD: Tests écrits AVANT le code (ici validation du code créé).
"""

import pytest
from datetime import datetime
from ghost_hunter.core.brain.strategist_v2.contracts import (
    SecurityProfile,
    OriginalContext,
    AttemptResult,
    PayloadSpec,
    RoundNPlan,
    RoundResult,
    CumulativeKnowledge,
    EncodingType,
    WafProvider,
)


class TestSecurityProfile:
    """Tests pour SecurityProfile."""
    
    def test_has_waf_true(self):
        """has_waf retourne True si WAF détecté."""
        profile = SecurityProfile(waf="cloudflare")
        assert profile.has_waf() is True
    
    def test_has_waf_false(self):
        """has_waf retourne False si pas de WAF."""
        profile = SecurityProfile()
        assert profile.has_waf() is False
    
    def test_to_dict(self):
        """to_dict sérialise correctement."""
        profile = SecurityProfile(
            waf="cloudflare",
            cdn="cloudflare",
            rate_limit=True,
            anti_bot="datadome"
        )
        d = profile.to_dict()
        assert d["waf"] == "cloudflare"
        assert d["cdn"] == "cloudflare"
        assert d["rate_limit"] is True
        assert d["anti_bot"] == "datadome"
    
    def test_from_dict(self):
        """from_dict reconstruit correctement."""
        data = {
            "waf": "aws_waf",
            "cdn": "cloudfront",
            "rate_limit": False,
            "anti_bot": None
        }
        profile = SecurityProfile.from_dict(data)
        assert profile.waf == "aws_waf"
        assert profile.cdn == "cloudfront"
        assert profile.rate_limit is False
        assert profile.anti_bot is None


class TestOriginalContext:
    """Tests pour OriginalContext."""
    
    def test_creation_minimal(self):
        """Création avec params minimaux."""
        ctx = OriginalContext(
            method="GET",
            url="https://api.example.com/users/123",
            headers={"Authorization": "Bearer xxx"}
        )
        assert ctx.method == "GET"
        assert ctx.url == "https://api.example.com/users/123"
        assert ctx.body is None
        assert ctx.vuln_class == ""
    
    def test_creation_full(self):
        """Création avec tous les params."""
        ctx = OriginalContext(
            method="POST",
            url="https://api.example.com/update",
            headers={"Content-Type": "application/json"},
            body='{"id": 123}',
            vuln_class="IDOR",
            confidence=85,
            interesting_params=["id", "user_id"],
            triage_reasoning="Numeric ID manipulation possible",
            security_profile=SecurityProfile(waf="cloudflare")
        )
        assert ctx.vuln_class == "IDOR"
        assert ctx.confidence == 85
        assert "id" in ctx.interesting_params
        assert ctx.security_profile.waf == "cloudflare"
    
    def test_to_dict_from_dict_roundtrip(self):
        """Sérialisation/désérialisation conserve les données."""
        original = OriginalContext(
            method="PUT",
            url="https://api.example.com/profile",
            headers={"Cookie": "session=abc"},
            body='{"name": "test"}',
            vuln_class="SQLi",
            confidence=70,
            interesting_params=["name"],
            triage_reasoning="User input in name field",
            security_profile=SecurityProfile(waf="imperva", rate_limit=True)
        )
        
        data = original.to_dict()
        restored = OriginalContext.from_dict(data)
        
        assert restored.method == original.method
        assert restored.url == original.url
        assert restored.body == original.body
        assert restored.vuln_class == original.vuln_class
        assert restored.security_profile.waf == "imperva"


class TestAttemptResult:
    """Tests pour AttemptResult."""
    
    def test_creation(self):
        """Création d'un résultat de tentative."""
        result = AttemptResult(
            payload_original="' OR 1=1--",
            payload_sent="%27%20OR%201%3D1--",
            encoding="url",
            injection_point="id",
            method="GET",
            url="https://api.example.com/users?id=%27%20OR%201%3D1--",
            status_code=403,
            response_time_ms=150.5,
            response_length=1234,
            response_snippet="Access Denied",
            waf_blocked=True,
            waf_provider="cloudflare",
            waf_signature="SQL injection detected"
        )
        assert result.waf_blocked is True
        assert result.encoding == "url"
    
    def test_to_dict_from_dict_roundtrip(self):
        """Roundtrip sérialisation."""
        original = AttemptResult(
            payload_original="<script>alert(1)</script>",
            payload_sent="<script>alert(1)</script>",
            encoding="none",
            injection_point="comment",
            method="POST",
            url="https://api.example.com/comment",
            status_code=200,
            response_time_ms=89.2,
            response_length=5678,
            is_interesting=True,
            diff_indicators=["content_changed", "reflected_input"]
        )
        
        data = original.to_dict()
        restored = AttemptResult.from_dict(data)
        
        assert restored.payload_original == original.payload_original
        assert restored.is_interesting is True
        assert "content_changed" in restored.diff_indicators


class TestPayloadSpec:
    """Tests pour PayloadSpec."""
    
    def test_creation(self):
        """Création d'une spec de payload."""
        spec = PayloadSpec(
            payload="{{7*7}}",
            encoding="none",
            injection_point="template",
            reasoning="Testing SSTI vulnerability"
        )
        assert spec.payload == "{{7*7}}"
        assert spec.reasoning == "Testing SSTI vulnerability"
    
    def test_default_encoding(self):
        """Encoding par défaut est 'none'."""
        spec = PayloadSpec(payload="test")
        assert spec.encoding == "none"


class TestRoundNPlan:
    """Tests pour RoundNPlan."""
    
    def test_creation(self):
        """Création d'un plan de round."""
        plan = RoundNPlan(
            round_number=2,
            vuln_class="IDOR",
            payloads=[
                PayloadSpec(payload="124", reasoning="ID increment"),
                PayloadSpec(payload="122", reasoning="ID decrement"),
            ],
            reasoning="Testing adjacent IDs",
            bypass_techniques=["unicode_normalization", "case_variation"]
        )
        assert plan.round_number == 2
        assert len(plan.payloads) == 2
        assert "unicode_normalization" in plan.bypass_techniques
    
    def test_to_dict_from_dict_roundtrip(self):
        """Roundtrip sérialisation."""
        original = RoundNPlan(
            round_number=3,
            vuln_class="SQLi",
            payloads=[PayloadSpec(payload="1' AND '1'='1", encoding="url")],
            reasoning="Blind SQLi test"
        )
        
        data = original.to_dict()
        restored = RoundNPlan.from_dict(data)
        
        assert restored.round_number == 3
        assert restored.payloads[0].payload == "1' AND '1'='1"


class TestRoundResult:
    """Tests pour RoundResult."""
    
    def test_compute_stats(self):
        """compute_stats calcule correctement les stats."""
        result = RoundResult(
            round_number=1,
            timestamp=datetime.now(),
            plan=RoundNPlan(round_number=1, vuln_class="XSS", payloads=[]),
            tests=[
                AttemptResult(
                    payload_original="p1", payload_sent="p1", encoding="none",
                    injection_point="x", method="GET", url="http://test",
                    status_code=200, response_time_ms=100, response_length=500,
                    waf_blocked=True
                ),
                AttemptResult(
                    payload_original="p2", payload_sent="p2", encoding="none",
                    injection_point="x", method="GET", url="http://test",
                    status_code=200, response_time_ms=100, response_length=500,
                    waf_blocked=False, is_interesting=True
                ),
                AttemptResult(
                    payload_original="p3", payload_sent="p3", encoding="none",
                    injection_point="x", method="GET", url="http://test",
                    status_code=200, response_time_ms=100, response_length=500,
                    waf_blocked=False, is_interesting=False
                ),
            ]
        )
        
        result.compute_stats()
        
        assert result.blocked_count == 1
        assert result.passed_count == 2
        assert result.interesting_count == 1
    
    def test_to_dict_from_dict_roundtrip(self):
        """Roundtrip sérialisation."""
        now = datetime.now()
        original = RoundResult(
            round_number=1,
            timestamp=now,
            plan=RoundNPlan(round_number=1, vuln_class="SSRF", payloads=[]),
            blocked_count=2,
            passed_count=3,
            blocked_patterns=["http://", "file://"],
            working_techniques=["double_encoding"]
        )
        
        data = original.to_dict()
        restored = RoundResult.from_dict(data)
        
        assert restored.round_number == 1
        assert restored.blocked_count == 2
        assert "http://" in restored.blocked_patterns


class TestCumulativeKnowledge:
    """Tests pour CumulativeKnowledge."""
    
    def test_update_with_round(self):
        """update_with_round enrichit la connaissance."""
        knowledge = CumulativeKnowledge(
            blocked_patterns=["pattern1"],
            working_techniques=["technique1"]
        )
        
        round_result = RoundResult(
            round_number=2,
            timestamp=datetime.now(),
            plan=RoundNPlan(round_number=2, vuln_class="IDOR", payloads=[]),
            tests=[
                AttemptResult(
                    payload_original="p1", payload_sent="p1", encoding="url",
                    injection_point="id", method="GET", url="http://test",
                    status_code=403, response_time_ms=100, response_length=100,
                    waf_blocked=True
                ),
                AttemptResult(
                    payload_original="p2", payload_sent="p2", encoding="unicode",
                    injection_point="id", method="GET", url="http://test",
                    status_code=200, response_time_ms=100, response_length=100,
                    waf_blocked=False
                ),
            ],
            blocked_patterns=["pattern2"],
            working_techniques=["technique2"]
        )
        
        new_knowledge = knowledge.update_with_round(round_result)
        
        # Original inchangé
        assert "pattern2" not in knowledge.blocked_patterns
        
        # Nouveau enrichi
        assert "pattern1" in new_knowledge.blocked_patterns
        assert "pattern2" in new_knowledge.blocked_patterns
        assert "technique2" in new_knowledge.working_techniques
        
        # Stats encoding
        assert new_knowledge.encoding_stats["url"]["blocked"] == 1
        assert new_knowledge.encoding_stats["unicode"]["passed"] == 1
    
    def test_to_dict_from_dict_roundtrip(self):
        """Roundtrip sérialisation."""
        original = CumulativeKnowledge(
            blocked_patterns=["SELECT", "UNION"],
            working_techniques=["hex_encoding"],
            encoding_stats={"hex": {"blocked": 0, "passed": 5}},
            waf_provider="cloudflare"
        )
        
        data = original.to_dict()
        restored = CumulativeKnowledge.from_dict(data)
        
        assert "SELECT" in restored.blocked_patterns
        assert restored.waf_provider == "cloudflare"
        assert restored.encoding_stats["hex"]["passed"] == 5


class TestEnums:
    """Tests pour les enums."""
    
    def test_encoding_type_values(self):
        """EncodingType a les bonnes valeurs."""
        assert EncodingType.NONE.value == "none"
        assert EncodingType.URL.value == "url"
        assert EncodingType.UNICODE.value == "unicode"
    
    def test_waf_provider_values(self):
        """WafProvider a les bonnes valeurs."""
        assert WafProvider.CLOUDFLARE.value == "cloudflare"
        assert WafProvider.AWS_WAF.value == "aws_waf"

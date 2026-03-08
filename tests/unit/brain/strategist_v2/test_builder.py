"""
Tests pour prompts/builder.py

TDD: Validation du constructeur de prompt cumulatif.
"""

import pytest
from datetime import datetime
from ghost_hunter.core.brain.strategist_v2.contracts import (
    OriginalContext,
    SecurityProfile,
    RoundResult,
    RoundNPlan,
    PayloadSpec,
    AttemptResult,
    CumulativeKnowledge,
)
from ghost_hunter.core.brain.strategist_v2.prompts.builder import (
    build_round_n_prompt,
    _build_original_context_section,
    _build_previous_rounds_section,
    _build_rag_section,
    _build_cumulative_section,
    _build_task_section,
)


@pytest.fixture
def original_context():
    """Contexte original de test."""
    return OriginalContext(
        method="GET",
        url="https://api.example.com/users/123/profile",
        headers={
            "Authorization": "Bearer token123",
            "Content-Type": "application/json"
        },
        body=None,
        vuln_class="IDOR",
        confidence=85,
        interesting_params=["123", "user_id"],
        triage_reasoning="Numeric ID in path suggests IDOR vulnerability",
        security_profile=SecurityProfile(waf="cloudflare", cdn="cloudflare")
    )


@pytest.fixture
def round_1_result():
    """Résultat du Round 1."""
    return RoundResult(
        round_number=1,
        timestamp=datetime.now(),
        plan=RoundNPlan(
            round_number=1,
            vuln_class="IDOR",
            payloads=[
                PayloadSpec(payload="124", encoding="none", reasoning="ID increment")
            ],
            reasoning="Testing adjacent IDs",
            bypass_techniques=[]
        ),
        tests=[
            AttemptResult(
                payload_original="124",
                payload_sent="124",
                encoding="none",
                injection_point="user_id",
                method="GET",
                url="https://api.example.com/users/124/profile",
                status_code=403,
                response_time_ms=150,
                response_length=500,
                waf_blocked=True,
                waf_provider="cloudflare",
                waf_signature="IDOR attempt detected"
            ),
            AttemptResult(
                payload_original="122",
                payload_sent="122",
                encoding="none",
                injection_point="user_id",
                method="GET",
                url="https://api.example.com/users/122/profile",
                status_code=200,
                response_time_ms=89,
                response_length=1234,
                waf_blocked=False,
                is_interesting=True,
                diff_indicators=["different_user_data"]
            ),
        ],
        blocked_count=1,
        passed_count=1,
        interesting_count=1,
        blocked_patterns=["direct ID increment"],
        working_techniques=["ID decrement"]
    )


@pytest.fixture
def cumulative_knowledge():
    """Connaissance cumulative de test."""
    return CumulativeKnowledge(
        blocked_patterns=["direct increment", "sequential IDs"],
        working_techniques=["ID decrement", "negative IDs"],
        promising_results=["122 returned different user data"],
        encoding_stats={
            "none": {"blocked": 1, "passed": 1},
            "url": {"blocked": 0, "passed": 2}
        },
        waf_provider="cloudflare"
    )


class TestBuildRoundNPrompt:
    """Tests pour build_round_n_prompt."""
    
    def test_round_1_prompt(self, original_context):
        """Génère un prompt pour Round 1 (pas de previous rounds)."""
        result = build_round_n_prompt(
            round_number=1,
            original_context=original_context,
            previous_rounds=[],
            cumulative_knowledge=CumulativeKnowledge(),
            num_payloads=5
        )
        
        # Doit contenir le contexte original
        assert "ORIGINAL CONTEXT" in result
        assert "https://api.example.com/users/123/profile" in result
        assert "IDOR" in result
        
        # Pas de cumulative knowledge pour round 1
        assert "CUMULATIVE KNOWLEDGE" not in result
        
        # Task section
        assert "YOUR TASK (Round 1)" in result
        assert "Generate" in result
    
    def test_round_2_prompt_with_history(
        self, original_context, round_1_result, cumulative_knowledge
    ):
        """Génère un prompt pour Round 2 avec historique."""
        result = build_round_n_prompt(
            round_number=2,
            original_context=original_context,
            previous_rounds=[round_1_result],
            cumulative_knowledge=cumulative_knowledge,
            num_payloads=5
        )
        
        # Contexte original
        assert "ORIGINAL CONTEXT" in result
        
        # Previous rounds
        assert "PREVIOUS ROUNDS" in result
        assert "ROUND 1 STRATEGY" in result
        assert "ROUND 1 RESULTS" in result
        
        # Cumulative knowledge
        assert "CUMULATIVE KNOWLEDGE (Rounds 1-1)" in result
        assert "direct increment" in result
        assert "ID decrement" in result
        
        # Task
        assert "YOUR TASK (Round 2)" in result
    
    def test_with_rag_context(self, original_context):
        """Inclut le contexte RAG si fourni."""
        rag_context = """## Cloudflare WAF Bypass
        
- Use double URL encoding
- Try Unicode normalization
- Employ case variation
"""
        
        result = build_round_n_prompt(
            round_number=2,
            original_context=original_context,
            previous_rounds=[],
            cumulative_knowledge=CumulativeKnowledge(),
            rag_context=rag_context,
            num_payloads=3
        )
        
        assert "KNOWLEDGE BASE CONTEXT" in result
        assert "Cloudflare WAF Bypass" in result
        assert "double URL encoding" in result


class TestBuildOriginalContextSection:
    """Tests pour _build_original_context_section."""
    
    def test_includes_all_fields(self, original_context):
        """Inclut tous les champs du contexte."""
        result = _build_original_context_section(original_context)
        
        assert "GET" in result
        assert "https://api.example.com/users/123/profile" in result
        assert "IDOR" in result
        assert "85%" in result
        assert "Authorization" in result
        assert "cloudflare" in result.lower()
    
    def test_formats_headers(self, original_context):
        """Formate correctement les headers."""
        result = _build_original_context_section(original_context)
        assert "| Header | Value |" in result


class TestBuildPreviousRoundsSection:
    """Tests pour _build_previous_rounds_section."""
    
    def test_formats_round_results(self, round_1_result):
        """Formate les résultats des rounds."""
        result = _build_previous_rounds_section([round_1_result])
        
        assert "ROUND 1 STRATEGY" in result
        assert "ROUND 1 RESULTS" in result
        assert "Testing adjacent IDs" in result
        assert "124" in result
        assert "❌ BLOCKED" in result or "BLOCKED" in result
        assert "✅ PASSED" in result or "PASSED" in result
    
    def test_multiple_rounds(self, round_1_result):
        """Gère plusieurs rounds."""
        # Créer un round 2
        round_2 = RoundResult(
            round_number=2,
            timestamp=datetime.now(),
            plan=RoundNPlan(
                round_number=2,
                vuln_class="IDOR",
                payloads=[],
                reasoning="Round 2 strategy"
            ),
            tests=[]
        )
        
        result = _build_previous_rounds_section([round_1_result, round_2])
        
        assert "ROUND 1" in result
        assert "ROUND 2" in result


class TestBuildRagSection:
    """Tests pour _build_rag_section."""
    
    def test_wraps_rag_context(self):
        """Emballe le contexte RAG."""
        rag = "Some WAF bypass technique"
        result = _build_rag_section(rag)
        
        assert "KNOWLEDGE BASE CONTEXT" in result
        assert "Some WAF bypass technique" in result


class TestBuildCumulativeSection:
    """Tests pour _build_cumulative_section."""
    
    def test_formats_knowledge(self, cumulative_knowledge):
        """Formate la connaissance cumulative."""
        result = _build_cumulative_section(3, cumulative_knowledge)
        
        assert "CUMULATIVE KNOWLEDGE (Rounds 1-2)" in result
        assert "Patterns that trigger WAF" in result
        assert "direct increment" in result
        assert "Techniques that bypass" in result
        assert "ID decrement" in result
        assert "Encoding effectiveness" in result
        assert "cloudflare" in result


class TestBuildTaskSection:
    """Tests pour _build_task_section."""
    
    def test_includes_round_number(self):
        """Inclut le numéro du round."""
        result = _build_task_section(3, 5)
        assert "YOUR TASK (Round 3)" in result
    
    def test_includes_num_payloads(self):
        """Inclut le nombre de payloads demandés."""
        result = _build_task_section(2, 10)
        assert "10" in result
        assert "payloads" in result
    
    def test_includes_reminders(self):
        """Inclut les rappels critiques."""
        result = _build_task_section(2, 5)
        
        assert "DO NOT repeat" in result
        assert "PRIORITIZE" in result
        assert "JSON" in result

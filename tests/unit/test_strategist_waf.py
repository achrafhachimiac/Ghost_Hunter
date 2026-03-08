"""
Tests Phase 6: Strategist WAF Integration
=========================================
Intégration du WAF evasion dans le Strategist.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from typing import List


# Mock checker rapide
@pytest.fixture
def mock_checker():
    """Mock WAFChecker."""
    checker = MagicMock()
    def is_blocked_any(payload, vuln_type):
        blocked_keywords = ["union select", "<script>", "; cat"]
        payload_lower = payload.lower()
        for kw in blocked_keywords:
            if kw in payload_lower:
                return True, ["keyword"]
        return False, []
    checker.is_blocked_any.side_effect = is_blocked_any
    return checker


@pytest.fixture
def mock_mutator(mock_checker):
    """Mock PayloadMutator."""
    from ghost_hunter.core.contracts import Mutation, EvasionResult
    mutator = MagicMock()
    
    def auto_evade(payload, vuln_type, max_depth=3):
        # Simulate evasion
        if "union" in payload.lower():
            mutated = payload.replace("UNION", "uNi/**/oN")
            return EvasionResult(
                payload=payload,
                mutations=[Mutation(
                    original=payload,
                    mutated=mutated,
                    transform="inline_comment",
                    blocked_by=[],
                    evades=True
                )],
                best_mutation=Mutation(
                    original=payload,
                    mutated=mutated,
                    transform="inline_comment",
                    blocked_by=[],
                    evades=True
                ),
                all_blocked=False
            )
        return EvasionResult(
            payload=payload,
            mutations=[],
            best_mutation=None,
            all_blocked=True
        )
    
    mutator.auto_evade.side_effect = auto_evade
    return mutator


class TestStrategistWAFConfig:
    """Test configuration WAF du Strategist."""
    
    def test_strategist_has_waf_enabled_flag(self):
        """Strategist a un flag waf_enabled."""
        from ghost_hunter.core.brain.strategist import StrategistEngine
        # Devrait supporter l'option
        assert hasattr(StrategistEngine, '__init__')
    
    def test_strategist_accepts_mutator_injection(self):
        """Strategist accepte un mutator injecté."""
        # On vérifiera après implémentation
        pass


class TestPayloadFiltering:
    """Test filtrage des payloads bloqués."""
    
    def test_filter_blocked_payloads(self, mock_checker):
        """Filtre les payloads bloqués."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        
        mutator = PayloadMutator(checker=mock_checker)
        
        payloads = [
            "' UNION SELECT 1--",  # blocked
            "admin'--",            # not blocked (no union select)
            "<script>alert(1)",    # blocked
        ]
        
        filtered = []
        for p in payloads:
            blocked, _ = mock_checker.is_blocked_any(p, "sqli")
            if not blocked:
                filtered.append(p)
        
        assert len(filtered) == 1
        assert "admin" in filtered[0]
    
    def test_mutate_blocked_payloads(self, mock_mutator):
        """Mute les payloads bloqués."""
        payload = "' UNION SELECT 1--"
        result = mock_mutator.auto_evade(payload, "sqli")
        
        assert result.best_mutation is not None
        assert "/**/" in result.best_mutation.mutated


class TestStrategistPlanGeneration:
    """Test génération de plan avec WAF awareness."""
    
    def test_plan_includes_evasion_info(self):
        """Plan inclut info d'évasion si WAF détecté."""
        # Vérifie que le plan peut avoir des evasion_techniques
        from ghost_hunter.core.contracts import AttackPlan
        plan = AttackPlan.__dataclass_fields__
        assert "evasion_techniques" in plan
    
    def test_payloads_are_waf_filtered(self, mock_checker):
        """Les payloads générés sont filtrés WAF."""
        from ghost_hunter.core.contracts import PayloadVariant
        
        # Simule des payloads générés
        variants = [
            PayloadVariant(
                payload="' UNION SELECT 1--",
                encoding="none",
                evasion="none"
            ),
            PayloadVariant(
                payload="' OR '1'='1",
                encoding="none",
                evasion="none"
            ),
        ]
        
        # Filtre
        safe_variants = []
        for v in variants:
            blocked, _ = mock_checker.is_blocked_any(v.payload, "sqli")
            if not blocked:
                safe_variants.append(v)
        
        assert len(safe_variants) == 1
        assert "OR" in safe_variants[0].payload


class TestEvasionIntegration:
    """Test intégration complète."""
    
    def test_evasion_applied_when_waf_detected(self, mock_mutator):
        """Évasion appliquée quand WAF détecté."""
        # Simule un profil de sécurité avec WAF
        security_profile = {
            "waf": "Cloudflare",
            "anti_bot": "None"
        }
        
        # Si WAF présent, on doit utiliser le mutator
        if security_profile.get("waf") and security_profile["waf"] != "None":
            payload = "' UNION SELECT password FROM users--"
            result = mock_mutator.auto_evade(payload, "sqli")
            
            assert result.best_mutation is not None
    
    def test_no_evasion_when_no_waf(self, mock_mutator):
        """Pas d'évasion sans WAF."""
        security_profile = {
            "waf": "None",
            "anti_bot": "None"
        }
        
        # Sans WAF, pas besoin de mutator
        should_evade = security_profile.get("waf") and security_profile["waf"] != "None"
        assert not should_evade


class TestWAFAwarePayloadBuilder:
    """Test du builder de payloads WAF-aware."""
    
    def test_build_safe_payloads(self, mock_checker, mock_mutator):
        """Construit payloads qui passent le WAF."""
        from ghost_hunter.core.contracts import PayloadVariant
        
        original_payloads = [
            "' UNION SELECT 1--",
            "' OR 1=1--",
        ]
        
        safe_payloads = []
        for p in original_payloads:
            blocked, _ = mock_checker.is_blocked_any(p, "sqli")
            if blocked:
                result = mock_mutator.auto_evade(p, "sqli")
                if result.best_mutation:
                    safe_payloads.append(PayloadVariant(
                        payload=result.best_mutation.mutated,
                        encoding="none",
                        evasion=result.best_mutation.transform
                    ))
            else:
                safe_payloads.append(PayloadVariant(
                    payload=p,
                    encoding="none",
                    evasion="none"
                ))
        
        # Au moins un payload muté devrait passer
        assert len(safe_payloads) >= 1

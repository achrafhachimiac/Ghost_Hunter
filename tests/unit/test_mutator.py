"""
Tests Phase 5: Mutator Engine
=============================
Génération de mutations intelligentes avec feedback WAF.
"""

import pytest
from typing import List
from unittest.mock import MagicMock, patch


# Mock checker pour éviter le chargement lent des patterns F5
@pytest.fixture
def mock_checker():
    """Crée un mock WAFChecker rapide."""
    checker = MagicMock()
    # Simule détection basique
    def is_blocked_any(payload, vuln_type):
        blocked_keywords = ["union", "select", "<script", "onerror", "; cat", "| cat"]
        payload_lower = payload.lower()
        for kw in blocked_keywords:
            if kw in payload_lower:
                return True, ["keyword"]
        return False, []
    checker.is_blocked_any.side_effect = is_blocked_any
    return checker


class TestMutatorInit:
    """Test initialisation du mutator."""
    
    def test_mutator_import(self):
        """Mutator peut être importé."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        assert PayloadMutator is not None
    
    def test_mutator_create(self):
        """Mutator peut être instancié."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator()
        assert mutator is not None


class TestMutatorGeneration:
    """Test génération de mutations."""
    
    def test_generate_mutations_sqli(self):
        """Génère mutations pour SQLi."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator()
        
        payload = "' OR 1=1--"
        mutations = mutator.generate_mutations(payload, "sqli")
        
        assert len(mutations) > 0
        assert all(m.original == payload for m in mutations)
        assert all(m.mutated != payload for m in mutations)
    
    def test_generate_mutations_xss(self):
        """Génère mutations pour XSS."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator()
        
        payload = "<script>alert(1)</script>"
        mutations = mutator.generate_mutations(payload, "xss")
        
        assert len(mutations) > 0
        assert all(m.original == payload for m in mutations)
    
    def test_generate_mutations_cmdi(self):
        """Génère mutations pour CMDi."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator()
        
        payload = "; cat /etc/passwd"
        mutations = mutator.generate_mutations(payload, "cmdi")
        
        assert len(mutations) > 0


class TestMutatorEvasion:
    """Test détection évasion."""
    
    def test_check_evasion_blocked(self, mock_checker):
        """Détecte payload bloqué."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator(checker=mock_checker)
        
        # Original devrait être bloqué (contient 'OR')
        result = mutator.check_evasion("' UNION SELECT 1--", "sqli")
        # blocked_by est une liste, len > 0 si bloqué
        assert len(result.blocked_by) > 0 or not result.evades
    
    def test_find_evasion_mutations(self, mock_checker):
        """Trouve mutations qui évadent."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator(checker=mock_checker)
        
        payload = "' UNION SELECT 1--"
        evasions = mutator.find_evasions(payload, "sqli", max_attempts=20)
        
        # Peut ou non trouver des évasions (dépend des patterns)
        assert isinstance(evasions, list)


class TestMutatorChain:
    """Test chaînage de transforms."""
    
    def test_chain_transforms(self):
        """Chaîne plusieurs transforms."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator()
        
        payload = "UNION SELECT"
        chained = mutator.chain_transforms(
            payload, 
            ["case_swap", "inline_comment"],
            "sqli"
        )
        
        # Devrait avoir case swap + inline comments
        assert chained != payload
        assert chained.lower() != payload.lower()  # Case changed
    
    def test_auto_chain_for_evasion(self, mock_checker):
        """Chaîne automatiquement pour évader."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator(checker=mock_checker)
        
        payload = "' UNION SELECT * FROM users--"
        result = mutator.auto_evade(payload, "sqli", max_depth=3)
        
        assert result is not None
        # Au minimum, l'original est tenté
        assert result.payload == payload or result.mutations is not None


class TestMutatorResult:
    """Test structure résultat."""
    
    def test_mutation_has_transform(self):
        """Mutation contient le nom du transform."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator()
        
        mutations = mutator.generate_mutations("SELECT", "sqli")
        assert all(hasattr(m, 'transform') for m in mutations)
        assert all(m.transform is not None for m in mutations)
    
    def test_evasion_result_structure(self, mock_checker):
        """EvasionResult a la bonne structure."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        from ghost_hunter.core.contracts import EvasionResult
        
        mutator = PayloadMutator(checker=mock_checker)
        result = mutator.auto_evade("' UNION SELECT 1--", "sqli")
        
        assert isinstance(result, EvasionResult)
        assert hasattr(result, 'payload')
        assert hasattr(result, 'mutations')
        assert hasattr(result, 'best_mutation')
        assert hasattr(result, 'all_blocked')


class TestMutatorPriority:
    """Test priorité des transforms."""
    
    def test_transforms_ordered_by_effectiveness(self):
        """Transforms triés par efficacité."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator()
        
        # Get ordered transforms
        ordered = mutator.get_ordered_transforms("sqli")
        assert len(ordered) > 0
        # Les plus efficaces en premier
        assert "case_swap" in ordered or "inline_comment" in ordered
    
    def test_update_effectiveness(self):
        """Peut mettre à jour l'efficacité."""
        from ghost_hunter.core.evasion.mutator import PayloadMutator
        mutator = PayloadMutator()
        
        # Record success
        mutator.record_result("url_encode", "sqli", evaded=True)
        mutator.record_result("url_encode", "sqli", evaded=True)
        mutator.record_result("case_swap", "sqli", evaded=False)
        
        # url_encode devrait être mieux classé
        stats = mutator.get_transform_stats("sqli")
        assert "url_encode" in stats
        assert stats["url_encode"]["success_rate"] > 0

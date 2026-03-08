"""
Tests for WAF Evasion Contracts
================================
Phase 1: TDD - Tests d'abord, implémentation après.
"""

import pytest
from dataclasses import asdict


class TestWAFPatternContract:
    """Tests pour le contrat WAFPattern."""
    
    def test_waf_pattern_creation(self):
        """Test création basique d'un WAFPattern."""
        from ghost_hunter.core.contracts import WAFPattern
        
        pattern = WAFPattern(
            id="f5_200000073",
            vuln_type="sqli",
            pattern=r"\bUNION\b.*?\bSELECT\b",
            flags="si",
            risk=3,
            description="UNION SELECT injection",
            location="parameter"
        )
        
        assert pattern.id == "f5_200000073"
        assert pattern.vuln_type == "sqli"
        assert pattern.risk == 3
        assert pattern.location == "parameter"
    
    def test_waf_pattern_validation(self):
        """Test que les champs obligatoires sont présents."""
        from ghost_hunter.core.contracts import WAFPattern
        
        # Création avec valeurs par défaut
        pattern = WAFPattern(
            id="test_001",
            vuln_type="xss",
            pattern=r"<script"
        )
        
        assert pattern.flags == ""
        assert pattern.risk == 3  # Default high risk
        assert pattern.description == ""
        assert pattern.location == "parameter"  # Default
    
    def test_waf_pattern_serialization(self):
        """Test sérialisation en dict."""
        from ghost_hunter.core.contracts import WAFPattern
        
        pattern = WAFPattern(
            id="f5_test",
            vuln_type="cmdi",
            pattern=r";.*?cat",
            flags="i",
            risk=3,
            description="Command injection",
            location="uri"
        )
        
        data = asdict(pattern)
        assert data["id"] == "f5_test"
        assert data["vuln_type"] == "cmdi"
        assert data["location"] == "uri"


class TestTransformContract:
    """Tests pour le contrat Transform."""
    
    def test_transform_creation(self):
        """Test création d'une transformation."""
        from ghost_hunter.core.contracts import Transform
        
        transform = Transform(
            name="case_swap",
            vuln_types=["sqli", "xss"],
            description="Alternate case: UNION → uNiOn"
        )
        
        assert transform.name == "case_swap"
        assert "sqli" in transform.vuln_types
        assert "xss" in transform.vuln_types


class TestMutationContract:
    """Tests pour le contrat Mutation."""
    
    def test_mutation_creation(self):
        """Test création d'une mutation."""
        from ghost_hunter.core.contracts import Mutation
        
        mutation = Mutation(
            original="UNION SELECT",
            mutated="uNiOn SeLeCt",
            transform="case_swap",
            blocked_by=["f5_200000073"],
            evades=["f5_200000072"]
        )
        
        assert mutation.original == "UNION SELECT"
        assert mutation.mutated == "uNiOn SeLeCt"
        assert mutation.transform == "case_swap"
        assert len(mutation.blocked_by) == 1
        assert len(mutation.evades) == 1


class TestEvasionResultContract:
    """Tests pour le contrat EvasionResult."""
    
    def test_evasion_result_creation(self):
        """Test création d'un résultat d'évasion."""
        from ghost_hunter.core.contracts import EvasionResult, Mutation
        
        mutation = Mutation(
            original="<script>",
            mutated="<ScRiPt>",
            transform="tag_case_mix"
        )
        
        result = EvasionResult(
            payload="<script>alert(1)</script>",
            mutations=[mutation],
            best_mutation=mutation,
            all_blocked=False
        )
        
        assert result.payload == "<script>alert(1)</script>"
        assert len(result.mutations) == 1
        assert result.best_mutation is not None
        assert result.all_blocked is False
    
    def test_evasion_result_all_blocked(self):
        """Test quand tous les payloads sont bloqués."""
        from ghost_hunter.core.contracts import EvasionResult
        
        result = EvasionResult(
            payload="SELECT * FROM users",
            mutations=[],
            best_mutation=None,
            all_blocked=True
        )
        
        assert result.all_blocked is True
        assert result.best_mutation is None
        assert len(result.mutations) == 0


class TestContractSerialization:
    """Tests de sérialisation des contracts WAF."""
    
    def test_full_contract_flow_serialization(self):
        """Test sérialisation complète du flow."""
        from ghost_hunter.core.contracts import (
            WAFPattern, Transform, Mutation, EvasionResult
        )
        
        # Créer un pattern
        pattern = WAFPattern(
            id="f5_test",
            vuln_type="sqli",
            pattern=r"UNION.*SELECT",
            flags="i",
            risk=3,
            description="Test pattern",
            location="parameter"
        )
        
        # Créer une transformation
        transform = Transform(
            name="case_swap",
            vuln_types=["sqli"],
            description="Case swap"
        )
        
        # Créer une mutation
        mutation = Mutation(
            original="UNION SELECT",
            mutated="uNiOn SeLeCt",
            transform="case_swap",
            blocked_by=[pattern.id],
            evades=[]
        )
        
        # Créer le résultat
        result = EvasionResult(
            payload="UNION SELECT",
            mutations=[mutation],
            best_mutation=mutation,
            all_blocked=False
        )
        
        # Vérifier sérialisation
        pattern_dict = asdict(pattern)
        transform_dict = asdict(transform)
        mutation_dict = asdict(mutation)
        result_dict = asdict(result)
        
        assert pattern_dict["id"] == "f5_test"
        assert transform_dict["name"] == "case_swap"
        assert mutation_dict["transform"] == "case_swap"
        assert result_dict["all_blocked"] is False

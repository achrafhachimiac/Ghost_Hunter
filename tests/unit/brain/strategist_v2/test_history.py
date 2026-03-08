"""
Tests pour history.py

TDD: Validation du stockage Redis de l'historique d'attaque.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch
from ghost_hunter.core.brain.strategist_v2.history import (
    AttackHistory,
    HISTORY_PREFIX,
    KNOWLEDGE_PREFIX,
)
from ghost_hunter.core.brain.strategist_v2.contracts import (
    RoundResult,
    RoundNPlan,
    PayloadSpec,
    AttemptResult,
    CumulativeKnowledge,
)


@pytest.fixture
def mock_redis():
    """Mock du client Redis."""
    return MagicMock()


@pytest.fixture
def history_with_mock_redis(mock_redis):
    """AttackHistory avec Redis mocké."""
    return AttackHistory(redis_client=mock_redis)


@pytest.fixture
def history_memory():
    """AttackHistory sans Redis (fallback mémoire)."""
    history = AttackHistory(redis_client=None)
    history._redis = None  # Force le fallback
    return history


@pytest.fixture
def sample_round_result():
    """RoundResult de test."""
    return RoundResult(
        round_number=1,
        timestamp=datetime.now(),
        plan=RoundNPlan(
            round_number=1,
            vuln_class="IDOR",
            payloads=[PayloadSpec(payload="124", reasoning="Test")],
            reasoning="Testing IDOR"
        ),
        tests=[
            AttemptResult(
                payload_original="124",
                payload_sent="124",
                encoding="none",
                injection_point="user_id",
                method="GET",
                url="http://test",
                status_code=200,
                response_time_ms=100,
                response_length=500
            )
        ],
        blocked_count=0,
        passed_count=1,
        interesting_count=0
    )


@pytest.fixture
def sample_knowledge():
    """CumulativeKnowledge de test."""
    return CumulativeKnowledge(
        blocked_patterns=["pattern1", "pattern2"],
        working_techniques=["technique1"],
        encoding_stats={"none": {"blocked": 0, "passed": 1}},
        waf_provider="cloudflare"
    )


class TestAttackHistoryKeys:
    """Tests pour les clés Redis."""
    
    def test_history_key_format(self, history_memory):
        """Format correct de la clé d'historique."""
        key = history_memory._get_history_key("abc123")
        assert key == f"{HISTORY_PREFIX}:abc123"
    
    def test_knowledge_key_format(self, history_memory):
        """Format correct de la clé de connaissance."""
        key = history_memory._get_knowledge_key("abc123")
        assert key == f"{KNOWLEDGE_PREFIX}:abc123"


class TestAttackHistoryRounds:
    """Tests pour les opérations sur les rounds."""
    
    def test_get_rounds_empty(self, history_memory):
        """Retourne liste vide si pas d'historique."""
        rounds = history_memory.get_rounds("nonexistent")
        assert rounds == []
    
    def test_save_and_get_round(self, history_memory, sample_round_result):
        """Sauvegarde et récupération d'un round."""
        endpoint_hash = "test_hash"
        
        # Sauvegarder
        success = history_memory.save_round(endpoint_hash, sample_round_result)
        assert success is True
        
        # Récupérer
        rounds = history_memory.get_rounds(endpoint_hash)
        assert len(rounds) == 1
        assert rounds[0].round_number == 1
        assert rounds[0].plan.vuln_class == "IDOR"
    
    def test_save_multiple_rounds(self, history_memory, sample_round_result):
        """Sauvegarde de plusieurs rounds."""
        endpoint_hash = "test_hash"
        
        # Round 1
        history_memory.save_round(endpoint_hash, sample_round_result)
        
        # Round 2
        round2 = RoundResult(
            round_number=2,
            timestamp=datetime.now(),
            plan=RoundNPlan(
                round_number=2,
                vuln_class="IDOR",
                payloads=[],
                reasoning="Round 2"
            ),
            tests=[]
        )
        history_memory.save_round(endpoint_hash, round2)
        
        # Vérifier
        rounds = history_memory.get_rounds(endpoint_hash)
        assert len(rounds) == 2
        assert rounds[0].round_number == 1
        assert rounds[1].round_number == 2
    
    def test_get_last_round_number_empty(self, history_memory):
        """Retourne 0 si pas de rounds."""
        num = history_memory.get_last_round_number("nonexistent")
        assert num == 0
    
    def test_get_last_round_number(self, history_memory, sample_round_result):
        """Retourne le bon numéro de round."""
        endpoint_hash = "test_hash"
        
        history_memory.save_round(endpoint_hash, sample_round_result)
        
        round2 = RoundResult(
            round_number=2,
            timestamp=datetime.now(),
            plan=RoundNPlan(round_number=2, vuln_class="IDOR", payloads=[]),
            tests=[]
        )
        history_memory.save_round(endpoint_hash, round2)
        
        num = history_memory.get_last_round_number(endpoint_hash)
        assert num == 2


class TestAttackHistoryKnowledge:
    """Tests pour la connaissance cumulative."""
    
    def test_get_knowledge_empty(self, history_memory):
        """Retourne connaissance vide si pas d'historique."""
        knowledge = history_memory.get_knowledge("nonexistent")
        assert isinstance(knowledge, CumulativeKnowledge)
        assert knowledge.blocked_patterns == []
    
    def test_save_and_get_knowledge(self, history_memory, sample_knowledge):
        """Sauvegarde et récupération de la connaissance."""
        endpoint_hash = "test_hash"
        
        # Sauvegarder
        success = history_memory.save_knowledge(endpoint_hash, sample_knowledge)
        assert success is True
        
        # Récupérer
        knowledge = history_memory.get_knowledge(endpoint_hash)
        assert "pattern1" in knowledge.blocked_patterns
        assert knowledge.waf_provider == "cloudflare"


class TestAttackHistoryUtilities:
    """Tests pour les utilitaires."""
    
    def test_clear_history(self, history_memory, sample_round_result, sample_knowledge):
        """Supprime tout l'historique."""
        endpoint_hash = "test_hash"
        
        # Créer historique
        history_memory.save_round(endpoint_hash, sample_round_result)
        history_memory.save_knowledge(endpoint_hash, sample_knowledge)
        
        # Vérifier qu'il existe
        assert history_memory.has_history(endpoint_hash) is True
        
        # Supprimer
        success = history_memory.clear_history(endpoint_hash)
        assert success is True
        
        # Vérifier suppression
        assert history_memory.has_history(endpoint_hash) is False
        rounds = history_memory.get_rounds(endpoint_hash)
        assert rounds == []
    
    def test_has_history_false(self, history_memory):
        """has_history retourne False si pas d'historique."""
        assert history_memory.has_history("nonexistent") is False
    
    def test_has_history_true(self, history_memory, sample_round_result):
        """has_history retourne True si historique existe."""
        endpoint_hash = "test_hash"
        history_memory.save_round(endpoint_hash, sample_round_result)
        assert history_memory.has_history(endpoint_hash) is True


class TestAttackHistoryWithRedis:
    """Tests avec Redis mocké."""
    
    def test_get_rounds_from_redis(self, history_with_mock_redis, mock_redis):
        """Récupère depuis Redis."""
        # Simuler données Redis
        mock_redis.get.return_value = '[{"round_number": 1, "timestamp": "2024-01-01T00:00:00", "plan": {"round_number": 1, "vuln_class": "IDOR", "payloads": [], "reasoning": "", "bypass_techniques": []}, "tests": [], "blocked_count": 0, "passed_count": 0, "interesting_count": 0, "error_count": 0, "blocked_patterns": [], "working_techniques": [], "promising_results": []}]'
        
        rounds = history_with_mock_redis.get_rounds("test_hash")
        
        mock_redis.get.assert_called_once()
        assert len(rounds) == 1
        assert rounds[0].round_number == 1
    
    def test_save_round_to_redis(
        self, history_with_mock_redis, mock_redis, sample_round_result
    ):
        """Sauvegarde dans Redis."""
        mock_redis.get.return_value = None
        
        history_with_mock_redis.save_round("test_hash", sample_round_result)
        
        mock_redis.set.assert_called_once()
        call_args = mock_redis.set.call_args
        assert "attack_history:test_hash" in call_args[0][0]

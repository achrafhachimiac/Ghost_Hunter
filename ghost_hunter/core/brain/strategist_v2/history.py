"""
History storage pour le Strategist V2.

Gestion du stockage Redis de l'historique d'attaque multi-round.
~150 lignes max selon les règles du projet.
"""

import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

from .contracts import (
    OriginalContext,
    RoundResult,
    CumulativeKnowledge,
)

logger = logging.getLogger(__name__)

# Key prefix pour Redis
HISTORY_PREFIX = "attack_history"
KNOWLEDGE_PREFIX = "cumulative_knowledge"


class AttackHistory:
    """
    Gestionnaire d'historique d'attaque stocké en Redis.
    
    Chaque endpoint a un historique identifié par son hash.
    Structure Redis:
        attack_history:{hash} -> JSON list of RoundResult
        cumulative_knowledge:{hash} -> JSON CumulativeKnowledge
    """
    
    def __init__(self, redis_client: Optional[Any] = None):
        """
        Args:
            redis_client: Client Redis (optionnel, lazy load sinon)
        """
        self._redis = redis_client
        self._memory_fallback: Dict[str, Dict] = {}
    
    @property
    def redis(self):
        """Lazy load du client Redis."""
        if self._redis is None:
            try:
                from ghost_hunter.core.redis_store import get_redis_store
                store = get_redis_store()
                if store and store.connected:
                    self._redis = store._redis  # Access the internal redis client
            except Exception as e:
                logger.warning(f"Redis unavailable, using memory fallback: {e}")
                self._redis = None
        return self._redis
    
    def _get_history_key(self, endpoint_hash: str) -> str:
        """Génère la clé Redis pour l'historique."""
        return f"{HISTORY_PREFIX}:{endpoint_hash}"
    
    def _get_knowledge_key(self, endpoint_hash: str) -> str:
        """Génère la clé Redis pour la connaissance cumulative."""
        return f"{KNOWLEDGE_PREFIX}:{endpoint_hash}"
    
    # =========================================================================
    # Round Results CRUD
    # =========================================================================
    
    def get_rounds(self, endpoint_hash: str) -> List[RoundResult]:
        """
        Récupère tous les rounds pour un endpoint.
        
        Args:
            endpoint_hash: Hash de l'endpoint
            
        Returns:
            Liste des RoundResult (peut être vide)
        """
        try:
            if self.redis:
                key = self._get_history_key(endpoint_hash)
                data = self.redis.get(key)
                if data:
                    rounds_data = json.loads(data)
                    return [RoundResult.from_dict(r) for r in rounds_data]
            else:
                # Fallback mémoire
                data = self._memory_fallback.get(endpoint_hash, {})
                rounds_data = data.get("rounds", [])
                return [RoundResult.from_dict(r) for r in rounds_data]
                
        except Exception as e:
            logger.error(f"Failed to get rounds for {endpoint_hash}: {e}")
        
        return []
    
    def save_round(self, endpoint_hash: str, round_result: RoundResult) -> bool:
        """
        Sauvegarde un round dans l'historique.
        
        Args:
            endpoint_hash: Hash de l'endpoint
            round_result: Résultat du round à sauvegarder
            
        Returns:
            True si sauvegardé avec succès
        """
        try:
            # Récupérer l'historique existant
            rounds = self.get_rounds(endpoint_hash)
            rounds.append(round_result)
            
            # Sérialiser
            rounds_data = [r.to_dict() for r in rounds]
            
            if self.redis:
                key = self._get_history_key(endpoint_hash)
                self.redis.set(key, json.dumps(rounds_data))
            else:
                # Fallback mémoire
                if endpoint_hash not in self._memory_fallback:
                    self._memory_fallback[endpoint_hash] = {}
                self._memory_fallback[endpoint_hash]["rounds"] = rounds_data
            
            logger.debug(
                f"Saved round {round_result.round_number} for {endpoint_hash}"
            )
            return True
            
        except Exception as e:
            logger.error(f"Failed to save round for {endpoint_hash}: {e}")
            return False
    
    def get_last_round_number(self, endpoint_hash: str) -> int:
        """
        Récupère le numéro du dernier round.
        
        Args:
            endpoint_hash: Hash de l'endpoint
            
        Returns:
            Numéro du dernier round (0 si aucun)
        """
        rounds = self.get_rounds(endpoint_hash)
        if not rounds:
            return 0
        return max(r.round_number for r in rounds)
    
    # =========================================================================
    # Cumulative Knowledge CRUD
    # =========================================================================
    
    def get_knowledge(self, endpoint_hash: str) -> CumulativeKnowledge:
        """
        Récupère la connaissance cumulative pour un endpoint.
        
        Args:
            endpoint_hash: Hash de l'endpoint
            
        Returns:
            CumulativeKnowledge (vide si aucune)
        """
        try:
            if self.redis:
                key = self._get_knowledge_key(endpoint_hash)
                data = self.redis.get(key)
                if data:
                    return CumulativeKnowledge.from_dict(json.loads(data))
            else:
                # Fallback mémoire
                data = self._memory_fallback.get(endpoint_hash, {})
                knowledge_data = data.get("knowledge")
                if knowledge_data:
                    return CumulativeKnowledge.from_dict(knowledge_data)
                    
        except Exception as e:
            logger.error(f"Failed to get knowledge for {endpoint_hash}: {e}")
        
        return CumulativeKnowledge()
    
    def save_knowledge(
        self, endpoint_hash: str, knowledge: CumulativeKnowledge
    ) -> bool:
        """
        Sauvegarde la connaissance cumulative.
        
        Args:
            endpoint_hash: Hash de l'endpoint
            knowledge: Connaissance cumulative à sauvegarder
            
        Returns:
            True si sauvegardé avec succès
        """
        try:
            knowledge_data = knowledge.to_dict()
            
            if self.redis:
                key = self._get_knowledge_key(endpoint_hash)
                self.redis.set(key, json.dumps(knowledge_data))
            else:
                # Fallback mémoire
                if endpoint_hash not in self._memory_fallback:
                    self._memory_fallback[endpoint_hash] = {}
                self._memory_fallback[endpoint_hash]["knowledge"] = knowledge_data
            
            logger.debug(f"Saved cumulative knowledge for {endpoint_hash}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save knowledge for {endpoint_hash}: {e}")
            return False
    
    # =========================================================================
    # Utilities
    # =========================================================================
    
    def clear_history(self, endpoint_hash: str) -> bool:
        """
        Supprime tout l'historique d'un endpoint.
        
        Args:
            endpoint_hash: Hash de l'endpoint
            
        Returns:
            True si supprimé avec succès
        """
        try:
            if self.redis:
                self.redis.delete(self._get_history_key(endpoint_hash))
                self.redis.delete(self._get_knowledge_key(endpoint_hash))
            else:
                self._memory_fallback.pop(endpoint_hash, None)
            
            logger.info(f"Cleared history for {endpoint_hash}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear history for {endpoint_hash}: {e}")
            return False
    
    def has_history(self, endpoint_hash: str) -> bool:
        """
        Vérifie si un endpoint a un historique.
        
        Args:
            endpoint_hash: Hash de l'endpoint
            
        Returns:
            True si l'endpoint a au moins un round
        """
        return self.get_last_round_number(endpoint_hash) > 0

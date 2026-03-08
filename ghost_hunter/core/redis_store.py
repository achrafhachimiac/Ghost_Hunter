"""
Ghost Hunter - Redis Centralized Store
=======================================
Single Source of Truth pour toutes les données Ghost Hunter.

Clés Redis:
- ghost:endpoints:{hash}     → Endpoint complet (JSON)
- ghost:security:{domain}    → Security Profile (JSON)
- ghost:triage:{hash}        → Triage Result (JSON)
- ghost:findings:{id}        → Finding (JSON)
- ghost:stats                → Stats globales (JSON)
- ghost:config               → Configuration runtime (JSON)
"""

import json
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any
from dataclasses import asdict

logger = logging.getLogger(__name__)


class RedisStore:
    """
    Store Redis centralisé pour Ghost Hunter.
    
    Toutes les données passent par cette classe.
    """
    
    # Préfixes des clés
    PREFIX = "ghost"
    ENDPOINTS_KEY = f"{PREFIX}:endpoints"      # Hash: {hash} -> JSON
    SECURITY_KEY = f"{PREFIX}:security"        # Hash: {domain} -> JSON
    TRIAGE_KEY = f"{PREFIX}:triage"            # List: JSON items
    FINDINGS_KEY = f"{PREFIX}:findings"        # Hash: {id} -> JSON
    STATS_KEY = f"{PREFIX}:stats"              # String: JSON
    DEDUP_KEY = f"{PREFIX}:dedup"              # Set: seen hashes
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        socket_timeout: int = 2
    ):
        self._redis = None
        self._connected = False
        self.host = host
        self.port = port
        self.db = db
        self.socket_timeout = socket_timeout
        
        self._connect()
    
    def _connect(self) -> bool:
        """Connexion à Redis."""
        try:
            import redis
            self._redis = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                decode_responses=True,
                socket_timeout=self.socket_timeout
            )
            self._redis.ping()
            self._connected = True
            logger.info(f"✓ RedisStore connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.warning(f"✗ RedisStore: Redis unavailable ({e})")
            self._connected = False
            return False
    
    @property
    def connected(self) -> bool:
        return self._connected and self._redis is not None
    
    # ==================== ENDPOINTS ====================
    
    def save_endpoint(self, endpoint_hash: str, data: Dict) -> bool:
        """Sauvegarde un endpoint."""
        if not self.connected:
            return False
        try:
            data["updated_at"] = datetime.now().timestamp()
            self._redis.hset(self.ENDPOINTS_KEY, endpoint_hash, json.dumps(data))
            return True
        except Exception as e:
            logger.error(f"save_endpoint error: {e}")
            return False
    
    def get_endpoint(self, endpoint_hash: str) -> Optional[Dict]:
        """Récupère un endpoint."""
        if not self.connected:
            return None
        try:
            data = self._redis.hget(self.ENDPOINTS_KEY, endpoint_hash)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"get_endpoint error: {e}")
            return None
    
    def get_all_endpoints(self) -> Dict[str, Dict]:
        """Récupère tous les endpoints."""
        if not self.connected:
            return {}
        try:
            data = self._redis.hgetall(self.ENDPOINTS_KEY)
            return {k: json.loads(v) for k, v in data.items()}
        except Exception as e:
            logger.error(f"get_all_endpoints error: {e}")
            return {}
    
    def delete_endpoint(self, endpoint_hash: str) -> bool:
        """Supprime un endpoint."""
        if not self.connected:
            return False
        try:
            self._redis.hdel(self.ENDPOINTS_KEY, endpoint_hash)
            return True
        except Exception as e:
            logger.error(f"delete_endpoint error: {e}")
            return False
    
    def endpoint_count(self) -> int:
        """Nombre d'endpoints."""
        if not self.connected:
            return 0
        try:
            return self._redis.hlen(self.ENDPOINTS_KEY)
        except:
            return 0
    
    # ==================== DEDUP (seen hashes) ====================
    
    def is_seen(self, request_hash: str) -> bool:
        """Vérifie si un hash a déjà été vu."""
        if not self.connected:
            return False
        try:
            return self._redis.sismember(self.DEDUP_KEY, request_hash)
        except:
            return False
    
    def mark_seen(self, request_hash: str) -> bool:
        """Marque un hash comme vu."""
        if not self.connected:
            return False
        try:
            self._redis.sadd(self.DEDUP_KEY, request_hash)
            return True
        except:
            return False
    
    def seen_count(self) -> int:
        """Nombre de hashes vus."""
        if not self.connected:
            return 0
        try:
            return self._redis.scard(self.DEDUP_KEY)
        except:
            return 0
    
    # ==================== SECURITY PROFILES ====================
    
    def save_security_profile(self, domain: str, data: Dict) -> bool:
        """Sauvegarde un security profile."""
        if not self.connected:
            return False
        try:
            data["updated_at"] = datetime.now().timestamp()
            self._redis.hset(self.SECURITY_KEY, domain, json.dumps(data))
            return True
        except Exception as e:
            logger.error(f"save_security_profile error: {e}")
            return False
    
    def get_security_profile(self, domain: str) -> Optional[Dict]:
        """Récupère un security profile."""
        if not self.connected:
            return None
        try:
            data = self._redis.hget(self.SECURITY_KEY, domain)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"get_security_profile error: {e}")
            return None
    
    def get_all_security_profiles(self) -> Dict[str, Dict]:
        """Récupère tous les security profiles."""
        if not self.connected:
            return {}
        try:
            data = self._redis.hgetall(self.SECURITY_KEY)
            return {k: json.loads(v) for k, v in data.items()}
        except Exception as e:
            logger.error(f"get_all_security_profiles error: {e}")
            return {}
    
    def security_profile_count(self) -> int:
        """Nombre de security profiles."""
        if not self.connected:
            return 0
        try:
            return self._redis.hlen(self.SECURITY_KEY)
        except:
            return 0
    
    # ==================== TRIAGE HISTORY ====================
    
    def add_triage(self, triage_data: Dict) -> bool:
        """Ajoute un résultat de triage à l'historique."""
        if not self.connected:
            return False
        try:
            triage_data["timestamp"] = datetime.now().timestamp()
            self._redis.lpush(self.TRIAGE_KEY, json.dumps(triage_data))
            # Garder seulement les 1000 derniers
            self._redis.ltrim(self.TRIAGE_KEY, 0, 999)
            return True
        except Exception as e:
            logger.error(f"add_triage error: {e}")
            return False
    
    def get_triage_history(self, limit: int = 100) -> List[Dict]:
        """Récupère l'historique de triage."""
        if not self.connected:
            return []
        try:
            data = self._redis.lrange(self.TRIAGE_KEY, 0, limit - 1)
            return [json.loads(item) for item in data]
        except Exception as e:
            logger.error(f"get_triage_history error: {e}")
            return []
    
    def get_triage_by_hash(self, endpoint_hash: str) -> Optional[Dict]:
        """Récupère un triage spécifique par son hash."""
        if not self.connected:
            return None
        try:
            all_triages = self._redis.lrange(self.TRIAGE_KEY, 0, -1)
            for item in all_triages:
                triage = json.loads(item)
                if triage.get("hash") == endpoint_hash:
                    return triage
            return None
        except Exception as e:
            logger.error(f"get_triage_by_hash error: {e}")
            return None
    
    def update_triage_test_result(self, endpoint_hash: str, test_result: Dict) -> bool:
        """Met à jour le résultat de test dans l'historique de triage."""
        if not self.connected:
            return False
        try:
            # Récupérer tous les triages
            all_triages = self._redis.lrange(self.TRIAGE_KEY, 0, -1)
            
            for i, item in enumerate(all_triages):
                triage = json.loads(item)
                if triage.get("hash") == endpoint_hash:
                    # Mettre à jour
                    triage["tested"] = True
                    triage["test_result"] = test_result
                    # Remplacer dans la liste
                    self._redis.lset(self.TRIAGE_KEY, i, json.dumps(triage))
                    logger.info(f"✅ Updated triage test result for {endpoint_hash}")
                    return True
            
            logger.warning(f"Triage not found for hash {endpoint_hash}")
            return False
        except Exception as e:
            logger.error(f"update_triage_test_result error: {e}")
            return False
    
    def triage_count(self) -> int:
        """Nombre de triages."""
        if not self.connected:
            return 0
        try:
            return self._redis.llen(self.TRIAGE_KEY)
        except:
            return 0
    
    # ==================== FINDINGS ====================
    
    def save_finding(self, finding_id: str, data: Dict) -> bool:
        """Sauvegarde un finding."""
        if not self.connected:
            return False
        try:
            data["updated_at"] = datetime.now().timestamp()
            self._redis.hset(self.FINDINGS_KEY, finding_id, json.dumps(data))
            return True
        except Exception as e:
            logger.error(f"save_finding error: {e}")
            return False
    
    def get_finding(self, finding_id: str) -> Optional[Dict]:
        """Récupère un finding."""
        if not self.connected:
            return None
        try:
            data = self._redis.hget(self.FINDINGS_KEY, finding_id)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"get_finding error: {e}")
            return None
    
    def get_all_findings(self) -> Dict[str, Dict]:
        """Récupère tous les findings."""
        if not self.connected:
            return {}
        try:
            data = self._redis.hgetall(self.FINDINGS_KEY)
            return {k: json.loads(v) for k, v in data.items()}
        except Exception as e:
            logger.error(f"get_all_findings error: {e}")
            return {}
    
    def finding_count(self) -> int:
        """Nombre de findings."""
        if not self.connected:
            return 0
        try:
            return self._redis.hlen(self.FINDINGS_KEY)
        except:
            return 0
    
    # ==================== STATS ====================
    
    def save_stats(self, stats: Dict) -> bool:
        """Sauvegarde les stats."""
        if not self.connected:
            return False
        try:
            self._redis.set(self.STATS_KEY, json.dumps(stats))
            return True
        except Exception as e:
            logger.error(f"save_stats error: {e}")
            return False
    
    def get_stats(self) -> Dict:
        """Récupère les stats."""
        default = {
            "intercepted": 0,
            "in_scope": 0,
            "deduplicated": 0,
            "scored": 0,
            "triaged": 0,
            "findings": 0,
            "start_time": datetime.now().timestamp()
        }
        if not self.connected:
            return default
        try:
            data = self._redis.get(self.STATS_KEY)
            return json.loads(data) if data else default
        except:
            return default
    
    def increment_stat(self, key: str, amount: int = 1) -> bool:
        """Incrémente une stat."""
        if not self.connected:
            return False
        try:
            stats = self.get_stats()
            stats[key] = stats.get(key, 0) + amount
            return self.save_stats(stats)
        except:
            return False
    
    # ==================== RESET ====================
    
    def reset_all(self) -> Dict[str, int]:
        """
        RESET COMPLET - Efface toutes les données Ghost Hunter.
        
        Returns:
            Dict avec le nombre d'éléments effacés par catégorie
        """
        results = {
            "endpoints": 0,
            "security_profiles": 0,
            "triages": 0,
            "findings": 0,
            "dedup_hashes": 0,
            "total_keys": 0
        }
        
        if not self.connected:
            return results
        
        try:
            # Compter avant de supprimer
            results["endpoints"] = self.endpoint_count()
            results["security_profiles"] = self.security_profile_count()
            results["triages"] = self.triage_count()
            results["findings"] = self.finding_count()
            results["dedup_hashes"] = self.seen_count()
            
            # Supprimer toutes les clés ghost:*
            keys = self._redis.keys(f"{self.PREFIX}:*")
            if keys:
                self._redis.delete(*keys)
                results["total_keys"] = len(keys)
            
            # Aussi supprimer les anciennes clés (migration)
            for pattern in ["ghost_hunter:*", "dedup:*"]:
                old_keys = self._redis.keys(pattern)
                if old_keys:
                    self._redis.delete(*old_keys)
                    results["total_keys"] += len(old_keys)
            
            logger.info(f"🗑️ RedisStore RESET: {results}")
            return results
            
        except Exception as e:
            logger.error(f"reset_all error: {e}")
            return results
    
    # ==================== UTILS ====================
    
    def get_all_keys(self) -> List[str]:
        """Liste toutes les clés Ghost Hunter."""
        if not self.connected:
            return []
        try:
            return [k for k in self._redis.keys(f"{self.PREFIX}:*")]
        except:
            return []
    
    def get_memory_usage(self) -> Dict[str, int]:
        """Retourne l'usage mémoire par catégorie."""
        if not self.connected:
            return {}
        try:
            return {
                "endpoints": self._redis.memory_usage(self.ENDPOINTS_KEY) or 0,
                "security": self._redis.memory_usage(self.SECURITY_KEY) or 0,
                "triage": self._redis.memory_usage(self.TRIAGE_KEY) or 0,
                "findings": self._redis.memory_usage(self.FINDINGS_KEY) or 0,
                "stats": self._redis.memory_usage(self.STATS_KEY) or 0,
            }
        except:
            return {}


# ==================== Singleton ====================

_store: Optional[RedisStore] = None


def get_redis_store() -> RedisStore:
    """Retourne l'instance singleton du RedisStore."""
    global _store
    if _store is None:
        _store = RedisStore()
    return _store


def reset_redis_store():
    """Reset le singleton (pour les tests)."""
    global _store
    _store = None

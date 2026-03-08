"""
Baseline Engine - Enregistrement et comparaison des réponses de référence.

Le baseline permet de détecter les anomalies en comparant les réponses
d'attaque avec les réponses normales enregistrées.
"""

import hashlib
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
import logging

from ..contracts import (
    BaselineRecord,
    DiffResult,
    InterceptedRequest,
)


logger = logging.getLogger(__name__)


class BaselineEngine:
    """
    Moteur de baseline pour la détection d'anomalies.
    
    Fonctionnalités:
    - Enregistrement de réponses de référence
    - Comparaison baseline vs attack
    - Détection d'anomalies (timing, status, body)
    - Persistance JSON
    """
    
    def __init__(
        self,
        storage_dir: Path,
        timing_threshold_ms: float = 500.0,
        body_length_threshold: float = 0.1,  # 10% de différence
    ):
        """
        Args:
            storage_dir: Dossier de stockage des baselines
            timing_threshold_ms: Seuil de différence de temps (anomalie)
            body_length_threshold: Seuil de différence de taille (ratio)
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.timing_threshold_ms = timing_threshold_ms
        self.body_length_threshold = body_length_threshold
        
        # Cache en mémoire
        self._cache: Dict[str, BaselineRecord] = {}
        
        # Charger les baselines existants
        self._load_all()
    
    def _load_all(self) -> None:
        """Charge tous les baselines du stockage."""
        for file_path in self.storage_dir.glob("*.json"):
            try:
                data = json.loads(file_path.read_text())
                record = self._dict_to_record(data)
                self._cache[record.endpoint_hash] = record
            except Exception as e:
                logger.warning(f"Failed to load baseline {file_path}: {e}")
    
    def _dict_to_record(self, data: dict) -> BaselineRecord:
        """Convertit un dict en BaselineRecord."""
        return BaselineRecord(
            endpoint_hash=data.get("endpoint_hash", ""),
            method=data.get("method", "GET"),
            url_template=data.get("url_template", ""),
            status_code=data.get("status_code", 0),
            body_hash=data.get("body_hash", ""),
            body_length=data.get("body_length", 0),
            response_time_ms=data.get("response_time_ms", 0),
            headers_hash=data.get("headers_hash", ""),
            content_type=data.get("content_type", ""),
            known_variations=data.get("known_variations", []),
            recorded_at=data.get("recorded_at", datetime.now().timestamp()),
        )
    
    def _record_to_dict(self, record: BaselineRecord) -> dict:
        """Convertit un BaselineRecord en dict."""
        return {
            "endpoint_hash": record.endpoint_hash,
            "method": record.method,
            "url_template": record.url_template,
            "status_code": record.status_code,
            "body_hash": record.body_hash,
            "body_length": record.body_length,
            "response_time_ms": record.response_time_ms,
            "headers_hash": record.headers_hash,
            "content_type": record.content_type,
            "known_variations": record.known_variations,
            "recorded_at": record.recorded_at,
        }
    
    def compute_endpoint_hash(self, request: InterceptedRequest) -> str:
        """Calcule un hash unique pour un endpoint."""
        # Template = path avec IDs généralisés
        template = request.get_endpoint_template()
        
        # Hash = method + host + template
        key = f"{request.method}:{request.host}:{template}"
        return hashlib.md5(key.encode()).hexdigest()[:16]
    
    def record(
        self,
        request: InterceptedRequest,
        response_body: Optional[str] = None,
    ) -> BaselineRecord:
        """
        Enregistre une baseline pour un endpoint.
        
        Args:
            request: Requête avec réponse
            response_body: Body de la réponse (optionnel si dans request)
            
        Returns:
            BaselineRecord créé
        """
        endpoint_hash = self.compute_endpoint_hash(request)
        
        # Utiliser le body de la requête ou celui passé en paramètre
        body = response_body or request.response_body or ""
        
        # Calculer les hashes
        body_hash = hashlib.md5(body.encode()).hexdigest()
        headers_hash = ""
        if request.response_headers:
            headers_str = json.dumps(request.response_headers, sort_keys=True)
            headers_hash = hashlib.md5(headers_str.encode()).hexdigest()
        
        record = BaselineRecord(
            endpoint_hash=endpoint_hash,
            method=request.method,
            url_template=request.get_endpoint_template(),
            status_code=request.response_status or 0,
            body_hash=body_hash,
            body_length=len(body),
            response_time_ms=request.response_time_ms or 0,
            headers_hash=headers_hash,
            content_type=request.response_headers.get("content-type", "") if request.response_headers else "",
            recorded_at=datetime.now().timestamp(),
        )
        
        # Sauvegarder
        self._cache[endpoint_hash] = record
        self._save(record)
        
        logger.debug(f"Recorded baseline for {record.url_template}: status={record.status_code}")
        
        return record
    
    def _save(self, record: BaselineRecord) -> None:
        """Sauvegarde un baseline sur disque."""
        file_path = self.storage_dir / f"{record.endpoint_hash}.json"
        file_path.write_text(json.dumps(self._record_to_dict(record), indent=2))
    
    def get(self, request: InterceptedRequest) -> Optional[BaselineRecord]:
        """Récupère le baseline pour un endpoint."""
        endpoint_hash = self.compute_endpoint_hash(request)
        return self._cache.get(endpoint_hash)
    
    def has_baseline(self, request: InterceptedRequest) -> bool:
        """Vérifie si un baseline existe pour cet endpoint."""
        return self.get(request) is not None
    
    def compare(
        self,
        baseline: BaselineRecord,
        attack_response: Dict[str, Any],
    ) -> DiffResult:
        """
        Compare une réponse d'attaque avec le baseline.
        
        Args:
            baseline: Baseline de référence
            attack_response: Réponse de l'attaque (dict avec status, body, time, headers)
            
        Returns:
            DiffResult avec les anomalies détectées
        """
        result = DiffResult(
            baseline=baseline,
            attack_response=attack_response,
        )
        
        # Comparer le status code
        attack_status = attack_response.get("status_code", 0)
        if attack_status != baseline.status_code:
            result.status_changed = True
            result.anomalies.append(
                f"Status changed: {baseline.status_code} → {attack_status}"
            )
            result.anomaly_score += 30
        
        # Comparer le body
        attack_body = attack_response.get("body", "")
        attack_body_hash = hashlib.md5(attack_body.encode()).hexdigest()
        attack_body_length = len(attack_body)
        
        if attack_body_hash != baseline.body_hash:
            result.body_changed = True
            result.anomaly_score += 10
        
        # Différence de taille
        if baseline.body_length > 0:
            length_ratio = abs(attack_body_length - baseline.body_length) / baseline.body_length
            result.body_length_delta = attack_body_length - baseline.body_length
            
            if length_ratio > self.body_length_threshold:
                result.anomalies.append(
                    f"Body length changed significantly: {baseline.body_length} → {attack_body_length} ({length_ratio*100:.1f}%)"
                )
                result.anomaly_score += 15
        
        # Comparer le timing
        attack_time = attack_response.get("response_time_ms", 0)
        result.timing_delta_ms = attack_time - baseline.response_time_ms
        
        if abs(result.timing_delta_ms) > self.timing_threshold_ms:
            result.timing_anomaly = True
            result.anomalies.append(
                f"Response time anomaly: {baseline.response_time_ms:.0f}ms → {attack_time:.0f}ms (delta: {result.timing_delta_ms:.0f}ms)"
            )
            
            # Score plus élevé pour les délais longs (time-based attacks)
            if result.timing_delta_ms > 5000:
                result.anomaly_score += 40
            elif result.timing_delta_ms > 2000:
                result.anomaly_score += 25
            else:
                result.anomaly_score += 10
        
        # Comparer les headers
        attack_headers = attack_response.get("headers", {})
        if attack_headers:
            attack_headers_str = json.dumps(attack_headers, sort_keys=True)
            attack_headers_hash = hashlib.md5(attack_headers_str.encode()).hexdigest()
            
            if attack_headers_hash != baseline.headers_hash:
                result.headers_changed = True
                
                # Vérifier les nouveaux cookies
                baseline_cookies = set()
                attack_cookies = set()
                
                if "set-cookie" in attack_headers:
                    attack_cookies = set(
                        c.split("=")[0] for c in attack_headers.get("set-cookie", "").split(";")
                    )
                
                result.new_cookies = list(attack_cookies - baseline_cookies)
                
                if result.new_cookies:
                    result.anomalies.append(f"New cookies: {result.new_cookies}")
                    result.anomaly_score += 20
        
        # Déterminer si c'est suspect
        result.is_suspicious = result.anomaly_score >= 30
        
        return result
    
    def record_variation(
        self,
        request: InterceptedRequest,
        variation_description: str,
    ) -> None:
        """Enregistre une variation connue (pas une vraie anomalie)."""
        record = self.get(request)
        if record:
            record.known_variations.append({
                "description": variation_description,
                "recorded_at": datetime.now().timestamp(),
            })
            self._save(record)
    
    def clear(self) -> None:
        """Efface tous les baselines."""
        self._cache.clear()
        for file_path in self.storage_dir.glob("*.json"):
            file_path.unlink()
    
    def count(self) -> int:
        """Retourne le nombre de baselines enregistrés."""
        return len(self._cache)
    
    def list_endpoints(self) -> List[str]:
        """Liste tous les endpoints avec baseline."""
        return [r.url_template for r in self._cache.values()]

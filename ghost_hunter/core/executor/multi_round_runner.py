"""
Multi-Round Attack Runner - Orchestrateur d'attaques multi-rounds.

Intègre StrategistV2Engine avec CustomHTTPRunner pour exécuter
des attaques en plusieurs rounds avec apprentissage adaptatif.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, List, Dict, Any, TYPE_CHECKING
from datetime import datetime

from ..brain.strategist_v2 import (
    StrategistV2Engine,
    OriginalContext,
    SecurityProfile,
    AttemptResult,
    RoundNPlan,
    RoundResult,
    CumulativeKnowledge,
)
from ..brain.strategist_v2.analyzer import analyze_http_response, create_round_result
from ..contracts import (
    AttackPlan,
    Finding,
    ExecutionResult,
)
from .http_runner import CustomHTTPRunner
from .tool_wrapper import ExecutionContext
from .constants import MAX_PAYLOADS

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


logger = logging.getLogger(__name__)


class MultiRoundRunner:
    """
    Exécuteur multi-rounds avec apprentissage adaptatif.
    
    Coordonne StrategistV2Engine et CustomHTTPRunner pour:
    1. Générer un plan d'attaque initial (round 1)
    2. Exécuter les payloads
    3. Analyser les résultats (WAF blocks, réponses intéressantes)
    4. Générer le round suivant basé sur l'apprentissage
    5. Répéter jusqu'à max_rounds ou succès/abandon
    """
    
    def __init__(
        self,
        http_runner: Optional[CustomHTTPRunner] = None,
        strategist: Optional[StrategistV2Engine] = None,
        max_rounds: int = 5,
        payloads_per_round: int = 5,
    ):
        """
        Args:
            http_runner: Runner HTTP custom (créé si None)
            strategist: Moteur de stratégie (créé si None)
            max_rounds: Nombre max de rounds
            payloads_per_round: Nombre de payloads par round
        """
        self._http_runner = http_runner or CustomHTTPRunner()
        self._strategist = strategist or StrategistV2Engine()
        self.max_rounds = max_rounds
        self.payloads_per_round = payloads_per_round
    
    async def run_attack(
        self,
        endpoint_hash: str,
        original_context: OriginalContext,
        session_cookies: Optional[Dict[str, str]] = None,
    ) -> MultiRoundResult:
        """
        Exécute une attaque multi-rounds.
        
        Args:
            endpoint_hash: Hash unique de l'endpoint
            original_context: Contexte initial (URL, méthode, vulnérabilité)
            session_cookies: Cookies de session pour auth
            
        Returns:
            MultiRoundResult avec tous les rounds et findings
        """
        logger.info(f"Starting multi-round attack on {endpoint_hash}")
        logger.info(f"Vuln class: {original_context.vuln_class}, Max rounds: {self.max_rounds}")
        
        all_rounds: List[RoundResult] = []
        all_findings: List[Finding] = []
        start_time = datetime.now()
        
        round_num = 0
        while round_num < self.max_rounds:
            round_num += 1
            logger.info(f"═══ Round {round_num}/{self.max_rounds} ═══")
            
            # 1. Générer le plan pour ce round
            plan = self._strategist.generate_next_round(
                endpoint_hash=endpoint_hash,
                original_context=original_context,
                num_payloads=self.payloads_per_round,
            )
            
            logger.info(f"Round {round_num} plan: {len(plan.payloads)} payloads")
            logger.debug(f"Reasoning: {plan.reasoning[:100]}...")
            
            # 2. Exécuter les payloads
            attempts = await self._execute_round_payloads(
                plan=plan,
                original_context=original_context,
                session_cookies=session_cookies,
            )
            
            # 3. Créer le RoundResult
            round_result = create_round_result(round_num, plan, attempts)
            all_rounds.append(round_result)
            
            # 4. Enregistrer dans l'historique
            self._strategist.record_round_result(
                endpoint_hash=endpoint_hash,
                plan=plan,
                attempts=attempts,
            )
            
            # 5. Extraire les findings potentiels
            findings = self._extract_findings(round_result, original_context)
            all_findings.extend(findings)
            
            # Log du résumé
            logger.info(
                f"Round {round_num} complete: "
                f"{round_result.passed_count} passed, "
                f"{round_result.blocked_count} blocked, "
                f"{round_result.interesting_count} interesting"
            )
            
            # 6. Vérifier si on doit continuer
            if not self._strategist.should_continue(endpoint_hash, self.max_rounds):
                reason = "all blocked" if round_result.blocked_count == len(attempts) else "max reached or no progress"
                logger.info(f"Stopping after round {round_num}: {reason}")
                break
            
            # Si on a trouvé des vulnérabilités confirmées, on peut s'arrêter
            if any(f.status.value == "confirmed" for f in findings):
                logger.info(f"🎯 Confirmed finding in round {round_num}, stopping")
                break
        
        # Calcul final
        total_time = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return MultiRoundResult(
            endpoint_hash=endpoint_hash,
            rounds=all_rounds,
            findings=all_findings,
            total_rounds=len(all_rounds),
            total_attempts=sum(len(r.tests) for r in all_rounds),
            total_time_ms=total_time,
            success=len(all_findings) > 0,
            cumulative_knowledge=self._strategist._history.get_knowledge(endpoint_hash),
        )
    
    async def _execute_round_payloads(
        self,
        plan: RoundNPlan,
        original_context: OriginalContext,
        session_cookies: Optional[Dict[str, str]] = None,
    ) -> List[AttemptResult]:
        """
        Exécute tous les payloads d'un round.
        
        Args:
            plan: Plan du round avec payloads
            original_context: Contexte original
            session_cookies: Cookies de session
            
        Returns:
            Liste des AttemptResult
        """
        attempts = []
        
        if not HTTPX_AVAILABLE:
            logger.error("httpx not available - cannot execute payloads")
            return attempts
        
        # Configurer le client HTTP
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=30,
        ) as client:
            # Apply rate limit - max 30 payloads per round
            payloads_to_execute = plan.payloads[:MAX_PAYLOADS]
            if len(plan.payloads) > MAX_PAYLOADS:
                logger.warning(
                    f"⚠️ Rate limit: truncating {len(plan.payloads)} payloads to {MAX_PAYLOADS}"
                )
            
            for payload_spec in payloads_to_execute:
                try:
                    attempt = await self._execute_single_payload(
                        client=client,
                        payload_spec=payload_spec,
                        original_context=original_context,
                        session_cookies=session_cookies,
                    )
                    attempts.append(attempt)
                    
                    # Log du résultat
                    status_emoji = "🚫" if attempt.waf_blocked else ("⭐" if attempt.is_interesting else "✅")
                    logger.info(
                        f"{status_emoji} Payload '{payload_spec.payload[:30]}...' "
                        f"→ {attempt.status_code} ({attempt.response_time_ms}ms)"
                    )
                    
                except Exception as e:
                    logger.error(f"Failed to execute payload: {e}")
                    # Créer un AttemptResult d'erreur
                    attempts.append(AttemptResult(
                        payload_original=payload_spec.payload,
                        payload_sent=payload_spec.payload,
                        encoding=payload_spec.encoding or "none",
                        injection_point=payload_spec.injection_point or "unknown",
                        method=original_context.method,
                        url=original_context.url,
                        status_code=0,
                        response_time_ms=0,
                        response_length=0,
                        response_snippet=f"Error: {str(e)}",
                        waf_blocked=False,
                    ))
        
        return attempts
    
    async def _execute_single_payload(
        self,
        client: 'httpx.AsyncClient',
        payload_spec,
        original_context: OriginalContext,
        session_cookies: Optional[Dict[str, str]] = None,
    ) -> AttemptResult:
        """
        Exécute un seul payload et analyse la réponse.
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        from ..brain.strategist_v2.analyzer import analyze_http_response
        
        # Construire la requête avec le payload injecté
        url = original_context.url
        method = original_context.method
        headers = dict(original_context.headers or {})
        
        # Ajouter les cookies de session
        if session_cookies:
            existing_cookies = headers.get('cookie', '')
            new_cookies = '; '.join(f"{k}={v}" for k, v in session_cookies.items())
            if existing_cookies:
                headers['cookie'] = f"{existing_cookies}; {new_cookies}"
            else:
                headers['cookie'] = new_cookies
        
        # Déterminer le point d'injection
        injection_point = payload_spec.injection_point or "url_param"
        payload_value = payload_spec.payload
        
        # Appliquer l'encodage si spécifié
        if payload_spec.encoding and payload_spec.encoding != "none":
            payload_value = self._apply_encoding(payload_value, payload_spec.encoding)
        
        # Préparer le body (sera modifié si injection dans body)
        body_to_send = original_context.body
        content_type = headers.get('content-type', headers.get('Content-Type', ''))
        
        # Injecter le payload selon le point d'injection
        if injection_point == "path" or "path" in injection_point.lower():
            # Remplacer les IDs dans le path
            url = self._inject_in_path(url, payload_value)
        elif injection_point == "query" or "param" in injection_point.lower():
            url = self._inject_in_query(url, injection_point, payload_value)
        elif injection_point == "header":
            headers[payload_spec.injection_point] = payload_value
        elif injection_point.startswith("body:"):
            # Format: "body:field_name" - injecter dans un champ spécifique du JSON
            field_name = injection_point.split(":", 1)[1]
            body_to_send = self._inject_in_json_body(body_to_send, field_name, payload_value)
        elif injection_point == "body":
            # Remplacer tout le body
            body_to_send = payload_value
        
        # Exécuter la requête
        start_time = datetime.now()
        
        try:
            # Préparer les arguments de la requête
            request_kwargs = {
                "method": method,
                "url": url,
                "headers": headers,
            }
            
            # Ajouter le body si présent (POST, PUT, PATCH)
            if body_to_send and method.upper() in ("POST", "PUT", "PATCH"):
                # Détecter le content-type pour envoyer correctement
                if "json" in content_type.lower() or body_to_send.strip().startswith("{"):
                    # Body JSON - recalculer Content-Length
                    request_kwargs["content"] = body_to_send.encode('utf-8') if isinstance(body_to_send, str) else body_to_send
                    # Mettre à jour Content-Length
                    headers['content-length'] = str(len(request_kwargs["content"]))
                else:
                    request_kwargs["content"] = body_to_send
            
            response = await client.request(**request_kwargs)
            
            response_time = int((datetime.now() - start_time).total_seconds() * 1000)
            response_body = response.text
            
            # Analyser la réponse avec la fonction complète
            result = analyze_http_response(
                payload_original=payload_spec.payload,
                payload_sent=payload_value,
                encoding=payload_spec.encoding or "none",
                injection_point=injection_point,
                method=method,
                url=url,
                status_code=response.status_code,
                response_time_ms=response_time,
                response_body=response_body,
                response_headers=dict(response.headers),
            )
            
            return result
            
        except Exception as e:
            response_time = int((datetime.now() - start_time).total_seconds() * 1000)
            logger.warning(f"Request failed: {e}")
            return AttemptResult(
                payload_original=payload_spec.payload,
                payload_sent=payload_value,
                encoding=payload_spec.encoding or "none",
                injection_point=injection_point,
                method=method,
                url=url,
                status_code=0,
                response_time_ms=response_time,
                response_length=0,
                response_snippet=f"Error: {str(e)}",
                waf_blocked=False,
            )
    
    def _apply_encoding(self, payload: str, encoding: str) -> str:
        """Applique un encodage au payload."""
        import urllib.parse
        
        if encoding == "url":
            return urllib.parse.quote(payload)
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == "unicode":
            return payload.encode('unicode_escape').decode('ascii')
        elif encoding == "base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "hex":
            return payload.encode().hex()
        
        return payload
    
    def _inject_in_path(self, url: str, payload: str) -> str:
        """Injecte le payload dans le path (remplace les IDs numériques)."""
        import re
        from urllib.parse import urlparse, urlunparse
        
        parsed = urlparse(url)
        # Remplacer les segments numériques par le payload
        path_parts = parsed.path.split('/')
        new_parts = []
        for part in path_parts:
            if part.isdigit():
                new_parts.append(payload)
            else:
                new_parts.append(part)
        
        new_path = '/'.join(new_parts)
        return urlunparse(parsed._replace(path=new_path))
    
    def _inject_in_query(self, url: str, param_name: str, payload: str) -> str:
        """Injecte le payload dans un paramètre de query string."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Trouver le paramètre à modifier
        target_param = param_name.replace("param:", "").replace("query:", "")
        
        # Si on trouve le paramètre, le modifier
        if target_param in params:
            params[target_param] = [payload]
        else:
            # Sinon, essayer le premier paramètre avec un ID
            for key, values in params.items():
                if any(v.isdigit() for v in values):
                    params[key] = [payload]
                    break
        
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    def _inject_in_json_body(self, body: str, field_name: str, payload: str) -> str:
        """
        Injecte le payload dans un champ spécifique du JSON body.
        
        Supporte les champs imbriqués avec notation point:
        - "customer_id" -> remplace $.customer_id
        - "billing_address.email" -> remplace $.billing_address.email
        """
        import json
        
        if not body:
            return json.dumps({field_name: payload})
        
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse JSON body, returning raw payload")
            return body
        
        # Naviguer vers le champ à modifier
        parts = field_name.split(".")
        current = data
        
        # Naviguer jusqu'au parent du champ final
        for part in parts[:-1]:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                logger.warning(f"Field path {field_name} not found in body")
                # Créer le chemin si nécessaire
                if isinstance(current, dict):
                    current[part] = {}
                    current = current[part]
        
        # Modifier le champ final
        final_field = parts[-1]
        if isinstance(current, dict):
            current[final_field] = payload
        
        return json.dumps(data)
    
    def _extract_findings(
        self,
        round_result: RoundResult,
        original_context: OriginalContext,
    ) -> List[Finding]:
        """
        Extrait les findings potentiels d'un round.
        """
        from ..contracts import FindingSeverity, FindingStatus
        
        findings = []
        
        for attempt in round_result.tests:
            if attempt.is_interesting and attempt.diff_indicators:
                # Créer un finding pour chaque résultat intéressant
                finding = Finding(
                    endpoint=original_context.url,
                    method=original_context.method,
                    vuln_type=original_context.vuln_class,
                    severity=self._determine_severity(original_context.vuln_class, attempt),
                    status=FindingStatus.NEW,
                    payload_successful=attempt.payload_sent,
                    ai_analysis=f"Interesting response detected. Indicators: {attempt.diff_indicators}",
                    request_sent=f"{attempt.method} {attempt.url}",
                    confidence=70,  # Default confidence for interesting results
                )
                findings.append(finding)
        
        return findings
    
    def _determine_severity(self, vuln_class: str, attempt: AttemptResult) -> 'FindingSeverity':
        """Détermine la sévérité basée sur le type de vuln."""
        from ..contracts import FindingSeverity
        
        severity_map = {
            "IDOR": FindingSeverity.HIGH,
            "SQLI": FindingSeverity.CRITICAL,
            "XSS": FindingSeverity.MEDIUM,
            "SSRF": FindingSeverity.HIGH,
            "RCE": FindingSeverity.CRITICAL,
            "PATH_TRAVERSAL": FindingSeverity.HIGH,
        }
        
        return severity_map.get(vuln_class.upper(), FindingSeverity.MEDIUM)


class MultiRoundResult:
    """
    Résultat d'une attaque multi-rounds.
    """
    
    def __init__(
        self,
        endpoint_hash: str,
        rounds: List[RoundResult],
        findings: List[Finding],
        total_rounds: int,
        total_attempts: int,
        total_time_ms: int,
        success: bool,
        cumulative_knowledge: Optional[CumulativeKnowledge] = None,
    ):
        self.endpoint_hash = endpoint_hash
        self.rounds = rounds
        self.findings = findings
        self.total_rounds = total_rounds
        self.total_attempts = total_attempts
        self.total_time_ms = total_time_ms
        self.success = success
        self.cumulative_knowledge = cumulative_knowledge
    
    def to_dict(self) -> Dict[str, Any]:
        """Sérialise en dict."""
        return {
            "endpoint_hash": self.endpoint_hash,
            "rounds": [r.to_dict() for r in self.rounds],
            "findings": [f.__dict__ if hasattr(f, '__dict__') else str(f) for f in self.findings],
            "total_rounds": self.total_rounds,
            "total_attempts": self.total_attempts,
            "total_time_ms": self.total_time_ms,
            "success": self.success,
            "summary": {
                "blocked": sum(r.blocked_count for r in self.rounds),
                "passed": sum(r.passed_count for r in self.rounds),
                "interesting": sum(r.interesting_count for r in self.rounds),
            }
        }
    
    def __repr__(self) -> str:
        return (
            f"MultiRoundResult(rounds={self.total_rounds}, "
            f"attempts={self.total_attempts}, "
            f"findings={len(self.findings)}, "
            f"success={self.success})"
        )

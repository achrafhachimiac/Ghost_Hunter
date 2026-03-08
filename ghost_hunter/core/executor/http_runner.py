"""
Custom HTTP Runner - Exécuteur HTTP personnalisé pour les tests.

Permet d'exécuter des requêtes HTTP avec les payloads générés par l'IA,
sans dépendre d'outils externes comme Nuclei.
"""

import asyncio
import json
from datetime import datetime
from typing import Optional, Dict, Any
import logging

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# Stealth browser availability check
try:
    from .stealth_browser import get_stealth_browser  # noqa: F401
    STEALTH_AVAILABLE = True
except ImportError:
    STEALTH_AVAILABLE = False

from ..evasion import get_proxy_manager
from ..evasion.user_agent import UserAgentRotator
from ..evasion.mutator import PayloadMutator
from ..evasion.checker import WAFChecker
from ..ai_logger import get_ai_logger

from .tool_wrapper import (
    ToolWrapper,
    ToolConfig,
    ExecutionContext,
)
from ..contracts import (
    ExecutionResult,
    Finding,
    FindingSeverity,
    FindingStatus,
    PayloadVariant,
    SecurityProfile,
)

# Import constants from extracted module
from .constants import (
    MAX_PAYLOADS,
    MAX_INJECTION_POINTS,
    _safe_get_payload_value,
)
from .payload_encoder import PayloadEncoder
from .waf_detector import WAFDetector
from .response_analyzer import ResponseAnalyzer
from .request_builder import RequestBuilder
from .stealth_executor import StealthExecutor
from .waf_evasion_handler import WAFEvasionHandler


logger = logging.getLogger(__name__)


class CustomHTTPRunner(ToolWrapper):
    """
    Exécuteur HTTP personnalisé.
    
    Envoie des requêtes HTTP avec les payloads du plan d'attaque
    et analyse les réponses pour détecter des vulnérabilités.
    
    Supports stealth mode with Puppeteer for bypassing anti-bot protections.
    """
    
    DEFAULT_CONFIG = ToolConfig(
        name="custom_http",
        executable="python",  # Pas besoin d'exécutable externe
        timeout_seconds=30,
        max_concurrent=5,
    )
    
    def __init__(
        self,
        config: Optional[ToolConfig] = None,
        follow_redirects: bool = False,
        verify_ssl: bool = False,
        user_agent: Optional[str] = None,  # None = utilise le vrai UA du navigateur si dispo
        use_proxy: bool = True,  # Use residential proxy
        rotate_ua_for_attacks: bool = True,  # Rotate UA pour les attaques non-authentifiées
        use_stealth: bool = False,  # Use puppeteer stealth mode for anti-bot bypass
        waf_evasion: bool = True,  # Enable automatic WAF evasion transforms
        security_profile: Optional[SecurityProfile] = None,  # Detected WAF/CDN info
    ):
        super().__init__(config or self.DEFAULT_CONFIG)
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self._fallback_user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.rotate_ua_for_attacks = rotate_ua_for_attacks
        self._ua_rotator = UserAgentRotator(mode="per_host")  # Différent UA par domaine
        self.use_proxy = use_proxy
        self._proxy_manager = get_proxy_manager() if use_proxy else None
        self.use_stealth = use_stealth  # Stealth mode for Friendly Captcha bypass
        self._stealth_browser = None
        
        # WAF Evasion system
        self.waf_evasion = waf_evasion
        self.security_profile = security_profile
        self._waf_checker = WAFChecker() if waf_evasion else None
        self._payload_mutator = PayloadMutator(self._waf_checker) if waf_evasion else None
        
        # WAF Evasion handler (delegates to checker + mutator)
        self._waf_evasion_handler = WAFEvasionHandler(
            waf_checker=self._waf_checker,
            payload_mutator=self._payload_mutator,
            security_profile=security_profile,
        ) if waf_evasion else None
        
        # Request builder for payload injection
        self._request_builder = RequestBuilder(
            ua_rotator=self._ua_rotator,
            fallback_user_agent=self._fallback_user_agent,
            rotate_ua_for_attacks=self.rotate_ua_for_attacks,
        )
        
        # Stealth executor for anti-bot bypass
        self._stealth_executor = StealthExecutor(
            payload_encoder=PayloadEncoder,
            request_builder=self._request_builder,
        )
        
        if not HTTPX_AVAILABLE:
            logger.warning("httpx not installed - CustomHTTPRunner will be limited")

    def _log_result(self, original_req, vuln_class: str, payload: str, 
                    injection_point: str, result: str, status_code: int = 0,
                    evidence: str = "") -> None:
        """Log le résultat d'un test pour le path déterministe."""
        try:
            ai_logger = get_ai_logger()
            ai_logger.log_result(
                endpoint=original_req.get_endpoint_template() if hasattr(original_req, 'get_endpoint_template') else original_req.path,
                method=original_req.method,
                vuln_class=vuln_class,
                payload_used=payload,
                injection_point=injection_point,
                result=result,
                status_code=status_code,
                evidence=evidence,
                host=original_req.host,
            )
        except Exception as e:
            logger.debug(f"Failed to log test result: {e}")
    
    @property
    def is_available(self) -> bool:
        return HTTPX_AVAILABLE
    
    async def execute(self, context: ExecutionContext) -> ExecutionResult:
        """Exécute les tests HTTP avec les payloads du plan."""
        result = self._create_base_result(context)
        start_time = datetime.now()
        
        # Liste des détails de chaque test pour le debug
        test_details = []
        
        if context.dry_run:
            result.success = True
            result.execution_time_ms = 0
            result.test_details = []
            return result
        
        if not HTTPX_AVAILABLE:
            result.success = False
            result.error = "httpx not installed"
            return result
        
        plan = context.plan
        
        try:
            # Récupérer les infos de la requête originale - navigation dans la structure imbriquée
            # TriageDecision -> ScoredRequest -> FilteredRequest -> InterceptedRequest
            original_req = plan.request.request.request.request
            
            logger.info(f"🔍 HTTP Runner: {len(plan.payloads)} payloads, {len(plan.injection_points)} injection points")
            logger.info(f"🔍 Original request: {original_req.method} {original_req.url}")
            
            # ═══ DEBUG: Log original_req details ═══
            logger.info(f"═══════════════════════════════════════════════════")
            logger.info(f"🔍 [HTTP_RUNNER] === ORIGINAL REQUEST FROM PLAN ===")
            logger.info(f"🔍 [HTTP_RUNNER] original_req.headers keys: {list(original_req.headers.keys()) if hasattr(original_req, 'headers') and original_req.headers else 'None'}")
            logger.info(f"🔍 [HTTP_RUNNER] original_req.cookies: {list(original_req.cookies.keys()) if hasattr(original_req, 'cookies') and original_req.cookies else 'None'}")
            if hasattr(original_req, 'headers') and original_req.headers:
                if 'cookie' in original_req.headers:
                    logger.info(f"🔍 [HTTP_RUNNER] original_req.headers['cookie'] length: {len(original_req.headers['cookie'])}")
                    # Check for auth/session cookie presence
                    cookie_val = original_req.headers.get('cookie', '')
                    logger.info(f"🔍 [HTTP_RUNNER] session cookie markers present: {any(marker in cookie_val.lower() for marker in ['session', 'token', 'auth'])}")
            logger.info(f"═══════════════════════════════════════════════════")
            
            # Tester chaque payload sur chaque point d'injection
            findings = []
            
            # Get residential proxy if enabled
            proxy_url = None
            if self.use_proxy and self._proxy_manager and self._proxy_manager.enabled:
                proxy = self._proxy_manager.get_proxy()
                if proxy:
                    proxy_url = proxy.url
                    logger.info(f"🌐 HTTP Runner using residential proxy: {proxy}")
            
            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                timeout=self.config.timeout_seconds,
                proxy=proxy_url,
            ) as client:
                for payload in plan.payloads[:MAX_PAYLOADS]:
                    for injection_point in plan.injection_points[:MAX_INJECTION_POINTS]:
                        payload_str = str(getattr(payload, 'payload', payload))[:50]
                        logger.debug(f"Testing payload '{payload_str}...' on {injection_point}")
                        try:
                            # Use stealth mode if enabled and available
                            if self.use_stealth and STEALTH_AVAILABLE:
                                finding, detail = await self._stealth_executor.test_payload(
                                    original_req,
                                    plan.vuln_class,
                                    payload,
                                    injection_point,
                                    context,
                                )
                            else:
                                finding, detail = await self._test_payload_with_details(
                                    client,
                                    original_req,
                                    plan.vuln_class,
                                    payload,
                                    injection_point,
                                    context,
                                )
                            test_details.append(detail)
                            response_info = detail.get('response') or {}
                            logger.info(f"✅ Test done: {injection_point} - status={response_info.get('status_code', 'N/A')}")
                            if finding:
                                findings.append(finding)
                        except Exception as test_err:
                            logger.error(f"❌ Test failed for {injection_point}: {test_err}")
                            test_details.append({
                                "payload": getattr(payload, 'payload', str(payload)),
                                "injection_point": injection_point,
                                "error": str(test_err),
                            })
            
            logger.info(f"📊 HTTP Runner completed: {len(test_details)} tests, {len(findings)} findings")
            
            result.execution_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            result.success = True
            result.test_details = test_details  # Ajouter les détails
            
            if findings:
                result.finding = findings[0]  # Premier finding
                result.raw_response = json.dumps([f.__dict__ for f in findings], default=str)
            
        except Exception as e:
            result.success = False
            result.error = str(e)
            result.test_details = test_details
            logger.exception("HTTP execution failed")
        
        self.executions.append(result)
        return result
    
    async def _test_payload_with_details(
        self,
        client: 'httpx.AsyncClient',
        original_req,
        vuln_class: str,
        payload: PayloadVariant,
        injection_point: str,
        context: ExecutionContext,
    ) -> tuple[Optional[Finding], dict]:
        """Teste un payload et retourne les détails complets."""
        # Handle None payload
        if payload is None:
            return None, {
                "payload": None,
                "injection_point": injection_point,
                "error": "Payload is None - skipping",
                "skipped": True,
            }
        
        # Defensive extraction of payload info - handle all edge cases
        payload_value = ''
        payload_encoding = 'none'
        
        try:
            if isinstance(payload, dict):
                # Dict payload - extract values safely
                payload_value = str(payload.get('payload', '')) if payload.get('payload') is not None else ''
                payload_encoding = payload.get('encoding', 'none') or 'none'
            elif hasattr(payload, 'payload') and payload.payload is not None:
                # PayloadVariant object
                payload_value = str(payload.payload)
                payload_encoding = getattr(payload, 'encoding', 'none') or 'none'
            elif isinstance(payload, (str, int, float)):
                # Raw value
                payload_value = str(payload)
            else:
                # Fallback - try to convert to string
                payload_value = str(payload) if payload else ''
        except Exception as e:
            logger.warning(f"⚠️ Error extracting payload info: {e}")
            payload_value = ''
        
        detail = {
            "payload": payload_value,
            "injection_point": injection_point,
            "encoding": payload_encoding,
            "waf_evasion": None,
            "request": None,
            "response": None,
            "response_time_ms": 0,
            "finding": None,
            "error": None,
        }
        
        try:
            # ═══ WAF EVASION: Transform payload if it would be blocked ═══
            original_payload_value = payload_value
            if self.waf_evasion and self._waf_evasion_handler and payload_value:
                evaded_payload, transform_used, was_transformed = self._waf_evasion_handler.apply_evasion(
                    payload_value, 
                    vuln_class
                )
                if was_transformed:
                    # Update payload with evaded version
                    if isinstance(payload, dict):
                        payload['payload'] = evaded_payload
                    elif hasattr(payload, 'payload'):
                        payload.payload = evaded_payload
                    payload_value = evaded_payload
                    detail["waf_evasion"] = {
                        "original": original_payload_value,
                        "transformed": evaded_payload,
                        "transform": transform_used,
                        "bypassed": True,
                    }
                    logger.info(f"🛡️ [WAF_EVASION] Payload transformed: {transform_used}")
            
            # Encoder le payload si nécessaire
            encoded_payload = self._encode_payload(payload)
            
            # Construire la requête modifiée
            url, headers, body, injection_success = self._build_request(
                original_req,
                encoded_payload,
                injection_point,
            )
            
            # Skip request if injection failed - prevents sending unchanged requests
            # which can trigger rate limiting or replay detection
            if not injection_success:
                logger.warning(f"⏭️ [HTTP_RUNNER] SKIPPING request - injection point '{injection_point}' not found in request")
                detail["error"] = f"Injection point '{injection_point}' not found in request"
                detail["skipped"] = True
                return None, detail
            
            # ═══ DEBUG: DETAILED REQUEST LOGGING ═══
            logger.info(f"═══════════════════════════════════════════════════")
            logger.info(f"🔍 [HTTP_RUNNER] Building request for payload: {encoded_payload[:30]}...")
            logger.info(f"🔍 [HTTP_RUNNER] Injection point: {injection_point}")
            logger.info(f"🔍 [HTTP_RUNNER] Final URL: {url}")
            logger.info(f"🔍 [HTTP_RUNNER] All headers keys: {list(headers.keys())}")
            
            # Check cookie header
            has_cookie_header = 'Cookie' in headers or 'cookie' in headers
            logger.info(f"🔍 [HTTP_RUNNER] Cookie header present: {has_cookie_header}")
            if has_cookie_header:
                cookie_val = headers.get('Cookie') or headers.get('cookie') or ''
                logger.info(f"🔍 [HTTP_RUNNER] Cookie value length: {len(cookie_val)}")
                logger.info(f"🔍 [HTTP_RUNNER] Auth/session markers present: {any(marker in cookie_val.lower() for marker in ['session', 'token', 'auth'])}")
            else:
                logger.warning(f"🔍 [HTTP_RUNNER] ⚠️ NO COOKIE HEADER!")
            
            # Check User-Agent
            ua_keys = [k for k in headers.keys() if k.lower() == 'user-agent']
            logger.info(f"🔍 [HTTP_RUNNER] User-Agent headers: {ua_keys}")
            for ua_key in ua_keys:
                logger.info(f"🔍 [HTTP_RUNNER] {ua_key}: {headers[ua_key][:60]}...")
            
            logger.info(f"═══════════════════════════════════════════════════")
            
            # Stocker les détails de la requête
            # NOTE: Masquer les valeurs sensibles mais MONTRER que les headers existent
            masked_headers = {}
            for k, v in headers.items():
                if k.lower() == 'cookie':
                    # Count cookies and mask the value
                    cookie_count = v.count(';') + 1 if v else 0
                    masked_headers[k] = f"[{cookie_count} cookies - PRÉSENT MAIS MASQUÉ]"
                elif k.lower() == 'authorization':
                    masked_headers[k] = "[PRÉSENT MAIS MASQUÉ]"
                else:
                    masked_headers[k] = v
            
            detail["request"] = {
                "method": original_req.method,
                "url": url,
                "headers": masked_headers,
                "headers_count": len(headers),
                "has_cookie": any(k.lower() == 'cookie' for k in headers),
                "has_auth": any(k.lower() == 'authorization' for k in headers),
                "body_preview": (body[:500] + "...") if body and len(body) > 500 else body,
            }
            
            # ═══ CRITICAL: Verify cookie is present before sending ═══
            has_cookie_before_send = any(k.lower() == 'cookie' for k in headers)
            if has_cookie_before_send:
                cookie_val = next((v for k, v in headers.items() if k.lower() == 'cookie'), '')
                logger.info(f"🍪 [HTTP_RUNNER] ✓ COOKIE WILL BE SENT: {len(cookie_val)} chars")
            else:
                logger.error(f"🍪 [HTTP_RUNNER] ❌ NO COOKIE IN FINAL HEADERS - request will likely fail!")
                logger.error(f"🍪 [HTTP_RUNNER] Headers keys: {list(headers.keys())}")
            
            # Envoyer la requête
            start = datetime.now()
            response = await client.request(
                method=original_req.method,
                url=url,
                headers=headers,
                content=body,
            )
            response_time = (datetime.now() - start).total_seconds() * 1000
            detail["response_time_ms"] = round(response_time, 2)
            
            # ═══ WAF BLOCK DETECTION ═══
            is_waf_blocked, waf_provider = self._is_waf_block_response(response)
            if is_waf_blocked:
                logger.warning(f"🛡️ [WAF_BLOCK] Request blocked by {waf_provider} (status {response.status_code})")
                detail["waf_blocked"] = {
                    "blocked": True,
                    "provider": waf_provider,
                    "status_code": response.status_code,
                }
                # Update evasion stats if we tried to evade
                waf_evasion_info = detail.get("waf_evasion") or {}
                if waf_evasion_info.get("bypassed"):
                    logger.error(f"❌ [WAF_EVASION] Evasion FAILED - {waf_provider} still blocked the request")
            
            # Stocker les détails de la réponse - FULL body, not truncated
            # Let the frontend handle truncation if needed for display
            detail["response"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body_preview": response.text[:2000] if len(response.text) > 2000 else response.text,  # Preview for quick view
                "body_full": response.text,  # Full body for detailed analysis
                "body_length": len(response.text),
                "waf_blocked": is_waf_blocked,
                "waf_provider": waf_provider if is_waf_blocked else None,
            }
            
            # Analyser la réponse
            finding = self._analyze_response(
                response,
                response_time,
                vuln_class,
                payload,
                injection_point,
                url,
            )
            
            if finding:
                detail["finding"] = {
                    "vuln_type": finding.vuln_type,
                    "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    "confidence": finding.confidence,
                    "analysis": finding.ai_analysis,
                }
                # Log le finding
                self._log_result(original_req, vuln_class, payload_value, injection_point, 
                                "vulnerable", response.status_code, finding.ai_analysis[:100] if finding.ai_analysis else "")
            else:
                # Log le résultat safe
                self._log_result(original_req, vuln_class, payload_value, injection_point,
                                "safe", response.status_code)
            
            return finding, detail
            
        except httpx.TimeoutException:
            detail["error"] = "Timeout"
            detail["response_time_ms"] = self.config.timeout_seconds * 1000
            
            # Timeout peut indiquer une vuln (time-based SQLi, etc.)
            if vuln_class.upper() in ["SQLI", "CMDI", "RCE"]:
                finding = Finding(
                    endpoint=original_req.url,
                    method=original_req.method,
                    vuln_type=vuln_class,
                    vuln_subtype="time-based",
                    severity=FindingSeverity.MEDIUM,
                    status=FindingStatus.NEW,
                    confidence=40,
                    payload_successful=_safe_get_payload_value(payload),
                    ai_analysis="Request timed out - potential time-based vulnerability",
                    tool_used="custom_http",
                )
                detail["finding"] = {
                    "vuln_type": finding.vuln_type,
                    "severity": "medium",
                    "confidence": 40,
                    "analysis": "Timeout - potential time-based vulnerability",
                }
                return finding, detail
            return None, detail
        except Exception as e:
            import traceback
            detail["error"] = str(e)
            detail["error_type"] = type(e).__name__
            detail["error_traceback"] = traceback.format_exc()
            logger.error(f"❌ [HTTP_RUNNER] Payload test failed: {type(e).__name__}: {e}")
            logger.error(f"❌ [HTTP_RUNNER] Traceback: {traceback.format_exc()}")
            return None, detail

    def _encode_payload(self, payload: PayloadVariant) -> str:
        """Encode le payload selon le type spécifié."""
        return PayloadEncoder.encode(payload)

    def _build_request(
        self,
        original_req,
        payload: str,
        injection_point: str,
    ) -> tuple[str, dict, Optional[str], bool]:
        """
        Construit la requête avec le payload injecté.
        
        Delegates to RequestBuilder for injection logic.
        
        Returns:
            tuple: (url, headers, body, injection_success)
            - injection_success: True if payload was actually injected, False otherwise
        """
        return self._request_builder.build(original_req, payload, injection_point)

    def _analyze_response(
        self,
        response: 'httpx.Response',
        response_time: float,
        vuln_class: str,
        payload: PayloadVariant,
        injection_point: str,
        url: str,
    ) -> Optional[Finding]:
        """
        Analyse la réponse pour détecter des vulnérabilités.
        
        Delegates to ResponseAnalyzer for detection logic.
        """
        return ResponseAnalyzer.analyze(
            response=response,
            response_time=response_time,
            vuln_class=vuln_class,
            payload=payload,
            injection_point=injection_point,
            url=url,
        )
    
    def _is_waf_block_response(self, response: 'httpx.Response') -> tuple[bool, str]:
        """
        Detect if response is a WAF block page.
        
        Delegates to WAFDetector for detection logic.
        
        Returns:
            tuple: (is_blocked, waf_provider)
        """
        return WAFDetector.is_blocked(response)
    
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse la sortie (format JSON des findings)."""
        try:
            return json.loads(raw_output)
        except Exception:
            return {"raw": raw_output}

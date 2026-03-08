"""
Test routes - Execute vulnerability tests on endpoints.

Routes:
- POST /api/endpoints/{endpoint_hash}/test - Execute attack plan on endpoint
- POST /api/run - Direct HTTP request execution (for Pivot Agent)
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
import json

from fastapi import APIRouter, HTTPException
import logging

from dashboard.deps import get_pipeline, get_redis_store
from dashboard.utils.storage import storage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["test"])

# Findings persistence directory
FINDINGS_DIR = Path("data/findings")
FINDINGS_DIR.mkdir(parents=True, exist_ok=True)


def persist_finding_to_disk(finding: Dict[str, Any]) -> bool:
    """Persist a finding to disk for durability."""
    try:
        finding_id = finding.get("id", f"finding_{datetime.now().timestamp()}")
        file_path = FINDINGS_DIR / f"{finding_id}.json"
        with open(file_path, "w") as f:
            json.dump(finding, f, indent=2, default=str)
        return True
    except Exception as e:
        logger.error(f"Failed to persist finding to disk: {e}")
        return False


@router.post("/endpoints/{endpoint_hash}/test")
async def test_endpoint(endpoint_hash: str, body: Dict[str, Any] = None):
    """
    Lance les tests de vulnérabilité sur un endpoint.
    
    Crée un AttackPlan basé sur le triage et l'exécute avec le HTTP Runner.
    
    Body params:
        - suggested_vulns: List of vuln types to test
        - confidence: Confidence level (default: 50)
        - use_stealth: Use puppeteer stealth mode for anti-bot bypass (default: False)
    """
    try:
        pipeline = get_pipeline()
        if not pipeline:
            raise HTTPException(status_code=503, detail="Pipeline not available")
        
        if not pipeline.strategist:
            raise HTTPException(status_code=503, detail="AI Strategist not available - check API key")
        
        if not pipeline.http_runner:
            raise HTTPException(status_code=503, detail="HTTP Runner not available")
        
        # Check for stealth mode option
        use_stealth = body.get("use_stealth", False) if body else False
        if use_stealth:
            logger.info("🥷 Stealth mode enabled - will use Puppeteer for anti-bot bypass")
            pipeline.http_runner.use_stealth = True
        else:
            pipeline.http_runner.use_stealth = False
        
        # Récupérer l'endpoint depuis dedup OU depuis triage history
        endpoints = pipeline.dedup.get_all_endpoints_data()
        endpoint = None
        for ep in endpoints:
            if ep.get("hash") == endpoint_hash:
                endpoint = ep
                break
        
        # Si non trouvé dans dedup, chercher dans le triage history (Redis)
        if not endpoint:
            logger.info(f"🔍 Endpoint {endpoint_hash} not in dedup, checking triage history...")
            triage_entry = get_redis_store().get_triage_by_hash(endpoint_hash)
            if triage_entry:
                # Construire un endpoint-like dict depuis le triage entry
                original_req = triage_entry.get("original_request", {})
                endpoint = {
                    "hash": endpoint_hash,
                    "method": triage_entry.get("method", "GET"),
                    "host": triage_entry.get("host", ""),
                    "path": triage_entry.get("path", ""),
                    "example_url": original_req.get("url", ""),
                    "example_headers": original_req.get("headers", {}),
                    "example_cookies": original_req.get("cookies", {}),
                    "example_body": original_req.get("body", ""),
                    "example_body_json": original_req.get("body_json"),
                    "example_query_params": original_req.get("query_params", {}),
                    "example_content_type": original_req.get("headers", {}).get("content-type", 
                                           original_req.get("headers", {}).get("Content-Type", "")),
                    "potential_vulns": triage_entry.get("suggested_vulns", ["IDOR"]),
                    "example_paths": [triage_entry.get("path", "")],
                }
                logger.info(f"✅ Found endpoint in triage history: {endpoint['method']} {endpoint['path']}")
        
        if not endpoint:
            raise HTTPException(status_code=404, detail="Endpoint not found in dedup or triage history")
        
        # Vérifier si on a des infos de triage (vulns suggérées)
        suggested_vulns = body.get("suggested_vulns", []) if body else []
        confidence = body.get("confidence", 50) if body else 50
        
        if not suggested_vulns:
            # Fallback: utiliser les vulns potentielles de l'heuristique
            suggested_vulns = endpoint.get("potential_vulns", ["IDOR"])
        
        # Récupérer les headers/body stockés pour cette endpoint
        # ═══════════════════════════════════════════════════════════════
        # RÉCUPÉRER LA REQUÊTE COMPLÈTE STOCKÉE - NE RIEN RATER!
        # ═══════════════════════════════════════════════════════════════
        stored_url = endpoint.get("example_url", "")
        stored_headers = endpoint.get("example_headers", {})
        stored_cookies = endpoint.get("example_cookies", {})
        stored_body = endpoint.get("example_body", "")
        stored_body_json = endpoint.get("example_body_json")
        stored_query_params = endpoint.get("example_query_params", {})
        stored_content_type = endpoint.get("example_content_type", "")
        
        # Construire l'URL avec les query params si pas d'URL stockée
        example_path = endpoint.get("example_paths", [""])[0]
        if stored_url:
            base_url = stored_url
        else:
            base_url = f"https://{endpoint.get('host', '')}{example_path}"
            if stored_query_params:
                from urllib.parse import urlencode
                base_url = f"{base_url}?{urlencode(stored_query_params)}"
        
        logger.info(f"🔍 Test with FULL request data:")
        logger.info(f"   - URL: {base_url}")
        logger.info(f"   - Headers: {list(stored_headers.keys())}")
        logger.info(f"   - Cookies: {list(stored_cookies.keys())}")
        logger.info(f"   - Body: {len(stored_body)} bytes")
        logger.info(f"   - Content-Type: {stored_content_type}")
        
        # ═══ DEBUG: DETAILED LOGGING OF WHAT'S IN REDIS ═══
        logger.info("═══════════════════════════════════════════════════")
        logger.info(f"🔍 [API] === DATA FROM REDIS FOR {endpoint_hash} ===")
        # Check for cookie header (case-insensitive)
        cookie_header_key = next((k for k in stored_headers.keys() if k.lower() == 'cookie'), None)
        logger.info(f"🔍 [API] Cookie header found with key: {cookie_header_key}")
        if cookie_header_key:
            cookie_val = stored_headers[cookie_header_key]
            logger.info(f"🔍 [API] Cookie header length: {len(cookie_val)}")
            logger.info(f"🔍 [API] Cookie preview: {cookie_val[:100]}...")
        else:
            logger.warning(f"🔍 [API] ⚠️ NO COOKIE HEADER in stored_headers!")
            logger.warning(f"🔍 [API] All header keys: {list(stored_headers.keys())}")
        logger.info(f"🔍 [API] stored_cookies dict keys: {list(stored_cookies.keys())}")
        logger.info("═══════════════════════════════════════════════════")
        
        # Créer un TriageDecision simulé pour le Strategist
        from ghost_hunter.core.contracts import (
            InterceptedRequest, FilteredRequest, ScoredRequest, TriageDecision
        )
        
        intercepted = InterceptedRequest(
            id=f"test_{endpoint_hash}",
            method=endpoint.get("method", "GET"),
            url=base_url,
            host=endpoint.get("host", ""),
            path=example_path,
            # TOUT transmettre!
            headers=stored_headers,
            cookies=stored_cookies,
            body=stored_body,
            body_json=stored_body_json,
            query_params=stored_query_params,
            timestamp=datetime.now().timestamp(),
        )
        
        filtered = FilteredRequest(
            request=intercepted,
            in_scope=True,
            is_static=False,
            scope_match=endpoint.get("host", ""),
            domain=endpoint.get("host", ""),
        )
        
        scored = ScoredRequest(
            request=filtered,
            score=endpoint.get("heuristic_score", 0),
            potential_vulns=suggested_vulns,
        )
        
        # Créer le triage avec les vulns suggérées
        triage = TriageDecision(
            request=scored,
            interesting=True,
            confidence=confidence,
            reason="Manual test triggered from dashboard",
            suggested_vulns=suggested_vulns,
        )
        
        logger.info(f"🎯 Creating attack plan for {endpoint.get('method')} {endpoint.get('path')} - vulns: {suggested_vulns}")
        
        # Créer le plan d'attaque via Strategist
        plan = pipeline.create_attack_plan(triage)
        
        if not plan or not plan.payloads:
            return {
                "status": "no_plan",
                "message": "Could not generate attack plan",
                "findings": [],
                "test_details": []
            }
        
        # DEBUG: Log les payloads générés
        logger.info(f"📝 Plan created: {len(plan.payloads)} payloads, {len(plan.injection_points)} injection points")
        for i, p in enumerate(plan.payloads[:5]):
            logger.info(f"   Payload {i+1}: {repr(p.payload)[:100]} (type: {type(p.payload).__name__})")
        logger.info(f"   Injection points: {plan.injection_points}")
        
        # Exécuter le plan - retourne maintenant (findings, test_details)
        findings, test_details = pipeline.execute_plan_sync(plan)
        
        # Formater les findings pour la réponse
        findings_data = []
        for f in findings:
            findings_data.append({
                "id": f.id,
                "endpoint": f.endpoint,
                "method": f.method,
                "vuln_type": f.vuln_type,
                "vuln_subtype": f.vuln_subtype,
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "confidence": f.confidence,
                "payload": f.payload_successful,
                "analysis": f.ai_analysis,
            })
        
        # Mettre à jour le statut de l'endpoint
        from ghost_hunter.core.interceptor.dedup import EndpointStatus
        if findings:
            pipeline.dedup.update_endpoint_status(
                filtered,
                EndpointStatus.VULNERABLE,
                f"Found {len(findings)} vulnerability(ies)"
            )
            new_status = "vulnerable"
            
            # ═══ PERSIST FINDINGS TO REDIS AND DISK ═══
            for f in findings:
                finding_id = f.id
                finding_record = {
                    "id": finding_id,
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "vuln_type": f.vuln_type,
                    "vuln_subtype": f.vuln_subtype,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "confidence": f.confidence,
                    "payload": f.payload_successful,
                    "analysis": f.ai_analysis,
                    "source": "ai_triage",
                    "discovered_at": datetime.now().timestamp(),
                    "endpoint_hash": endpoint_hash,
                }
                # Save to Redis
                get_redis_store().save_finding(finding_id, finding_record)
                # Save to disk for persistence
                persist_finding_to_disk(finding_record)
                logger.info(f"💾 Finding {finding_id} persisted to Redis and disk")
        else:
            pipeline.dedup.update_endpoint_status(
                filtered,
                EndpointStatus.TESTED,
                "Tested, no vulnerabilities found"
            )
            new_status = "tested"
        
        # Mettre à jour l'historique du triage avec les résultats du test (Redis + local)
        test_result_data = {
            "payloads_tested": len(plan.payloads),
            "injection_points": plan.injection_points,
            "vuln_class": plan.vuln_class,
            "findings": findings_data,
            "test_details": test_details,
            "new_status": new_status,
            # Debug info: prompt and AI response for UI display
            "strategy_prompt": plan.debug_prompt,
            "strategy_response": plan.debug_response,
            "strategy_model": plan.model_used,
            "strategy_tokens": plan.tokens_input + plan.tokens_output,
        }
        
        # Mettre à jour dans Redis
        get_redis_store().update_triage_test_result(endpoint_hash, test_result_data)
        
        # Aussi dans storage local pour compatibilité
        for entry in storage["triage_history"]:
            if entry["hash"] == endpoint_hash:
                entry["tested"] = True
                entry["test_result"] = test_result_data
                break
        
        return {
            "status": "ok",
            "payloads_tested": len(plan.payloads),
            "injection_points": plan.injection_points,
            "vuln_class": plan.vuln_class,
            "findings": findings_data,
            "test_details": test_details,  # Détails de chaque requête/réponse
            "new_status": new_status,
            # Debug info for Strategist UI popup
            "strategy_prompt": plan.debug_prompt,
            "strategy_response": plan.debug_response,
            "strategy_model": plan.model_used,
            "strategy_tokens": plan.tokens_input + plan.tokens_output,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Test execution error")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/run")
async def run_request(request_data: Dict[str, Any]):
    """
    Exécute une requête HTTP directe (utilisé par le Pivot Agent).
    
    Body params:
        - method: HTTP method (GET, POST, etc.)
        - url: Target URL
        - headers: Optional headers dict
        - body: Optional request body
        - cookies: Optional cookies dict
        - timeout: Optional timeout in seconds
    """
    try:
        import httpx
        
        method = request_data.get("method", "GET").upper()
        url = request_data.get("url")
        
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        headers = request_data.get("headers", {})
        body = request_data.get("body")
        cookies = request_data.get("cookies", {})
        timeout = request_data.get("timeout", 30)
        
        # Normalize headers (ensure proper case)
        normalized_headers = {}
        for k, v in headers.items():
            # Keep original case but ensure value is string
            normalized_headers[k] = str(v) if v is not None else ""
        
        logger.info(f"🚀 Direct HTTP request: {method} {url}")
        
        # Check if proxy is available
        proxy_url = None
        try:
            pipeline = get_pipeline()
            if pipeline and hasattr(pipeline, 'gonzo_proxy') and pipeline.gonzo_proxy:
                proxy_url = f"http://127.0.0.1:{pipeline.gonzo_proxy.port}"
                logger.info(f"   Using GonzoProxy: {proxy_url}")
        except Exception as e:
            logger.debug(f"No proxy available: {e}")
        
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            proxies=proxy_url
        ) as client:
            response = await client.request(
                method=method,
                url=url,
                headers=normalized_headers,
                content=body if body else None,
                cookies=cookies
            )
        
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:50000],  # Limit response size
            "url": str(response.url),
            "elapsed_ms": response.elapsed.total_seconds() * 1000 if response.elapsed else 0
        }
        
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Request timeout")
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Direct request execution error")
        raise HTTPException(status_code=500, detail=str(e))

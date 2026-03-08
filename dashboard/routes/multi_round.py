"""
Multi-Round Attack routes - Execute multi-round attacks with adaptive learning.

Routes:
- POST /api/endpoints/{endpoint_hash}/multi-round - Execute multi-round attack
- GET /api/multi-round/{endpoint_hash}/history - Get attack history for endpoint
- DELETE /api/multi-round/{endpoint_hash}/history - Clear attack history
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from dashboard.deps import get_pipeline, get_redis_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["multi-round"])


class MultiRoundRequest(BaseModel):
    """Request body for multi-round attack."""
    vuln_class: str = "IDOR"
    max_rounds: int = 5
    payloads_per_round: int = 5
    use_stealth: bool = False
    session_cookies: Optional[Dict[str, str]] = None


class MultiRoundStatus(BaseModel):
    """Status of a multi-round attack."""
    endpoint_hash: str
    status: str  # running, completed, error
    current_round: int = 0
    total_rounds: int = 0
    total_attempts: int = 0
    total_time_ms: int = 0
    findings_count: int = 0
    message: str = ""


# In-memory store for running attacks
_running_attacks: Dict[str, MultiRoundStatus] = {}


@router.post("/endpoints/{endpoint_hash}/multi-round")
async def start_multi_round_attack(
    endpoint_hash: str,
    request: MultiRoundRequest,
    background_tasks: BackgroundTasks,
):
    """
    Lance une attaque multi-rounds avec apprentissage adaptatif.
    
    Utilise StrategistV2Engine pour générer des payloads intelligents
    qui s'adaptent aux blocages WAF détectés.
    """
    try:
        # Check if already running
        if endpoint_hash in _running_attacks:
            status = _running_attacks[endpoint_hash]
            if status.status == "running":
                return {
                    "status": "already_running",
                    "message": f"Attack already in progress (round {status.current_round}/{status.total_rounds})",
                    "current_status": status.dict()
                }
        
        pipeline = get_pipeline()
        if not pipeline:
            raise HTTPException(status_code=503, detail="Pipeline not available")
        
        # Get endpoint data
        endpoint = _get_endpoint_data(endpoint_hash, pipeline)
        if not endpoint:
            raise HTTPException(status_code=404, detail="Endpoint not found")
        
        # Initialize status
        _running_attacks[endpoint_hash] = MultiRoundStatus(
            endpoint_hash=endpoint_hash,
            status="running",
            current_round=0,
            total_rounds=request.max_rounds,
            message="Initializing attack..."
        )
        
        # Run in background
        background_tasks.add_task(
            _run_multi_round_attack,
            endpoint_hash=endpoint_hash,
            endpoint=endpoint,
            request=request,
        )
        
        return {
            "status": "started",
            "message": f"Multi-round attack started with {request.max_rounds} max rounds",
            "endpoint_hash": endpoint_hash,
            "vuln_class": request.vuln_class,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Failed to start multi-round attack: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/endpoints/{endpoint_hash}/multi-round/status")
async def get_multi_round_status(endpoint_hash: str):
    """Get the status of a running multi-round attack."""
    # First check in-memory store
    if endpoint_hash in _running_attacks:
        return _running_attacks[endpoint_hash].model_dump()
    
    # If not in memory, check Redis for persisted result
    try:
        redis_store = get_redis_store()
        if redis_store and redis_store.connected:
            import json
            data = redis_store._redis.hget("multi_round_results", endpoint_hash)
            if data:
                return json.loads(data)
    except Exception as e:
        logger.warning(f"Failed to load result from Redis: {e}")
    
    return {
        "status": "not_found",
        "message": "No attack running or completed for this endpoint"
    }


@router.get("/multi-round/{endpoint_hash}/history")
async def get_attack_history(endpoint_hash: str):
    """Get the attack history for an endpoint."""
    try:
        from ghost_hunter.core.brain.strategist_v2 import AttackHistory
        
        history = AttackHistory()
        rounds = history.get_rounds(endpoint_hash)
        knowledge = history.get_knowledge(endpoint_hash)
        
        return {
            "endpoint_hash": endpoint_hash,
            "total_rounds": len(rounds),
            "rounds": [r.to_dict() for r in rounds],
            "cumulative_knowledge": knowledge.to_dict() if knowledge else {},
        }
        
    except Exception as e:
        logger.exception(f"Failed to get attack history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/multi-round/{endpoint_hash}/dump")
async def download_attack_dump(endpoint_hash: str):
    """Download a full text dump of attack history with all requests and responses."""
    from fastapi.responses import PlainTextResponse
    from datetime import datetime
    
    try:
        from ghost_hunter.core.brain.strategist_v2 import AttackHistory
        
        history = AttackHistory()
        rounds = history.get_rounds(endpoint_hash)
        knowledge = history.get_knowledge(endpoint_hash)
        
        # Build the dump
        lines = []
        lines.append("=" * 80)
        lines.append(f"GHOST-HUNTER MULTI-ROUND ATTACK DUMP")
        lines.append(f"Endpoint: {endpoint_hash}")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append(f"Total Rounds: {len(rounds)}")
        lines.append("=" * 80)
        lines.append("")
        
        # Summary
        total_tests = sum(len(r.tests) for r in rounds)
        total_blocked = sum(r.blocked_count for r in rounds)
        total_passed = sum(r.passed_count for r in rounds)
        total_interesting = sum(r.interesting_count for r in rounds)
        
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Total Attempts: {total_tests}")
        lines.append(f"Blocked by WAF: {total_blocked}")
        lines.append(f"Passed: {total_passed}")
        lines.append(f"Interesting: {total_interesting}")
        lines.append("")
        
        # Cumulative Knowledge
        if knowledge:
            lines.append("CUMULATIVE KNOWLEDGE")
            lines.append("-" * 40)
            if knowledge.blocked_patterns:
                lines.append(f"Blocked Patterns: {', '.join(knowledge.blocked_patterns[:10])}")
            if knowledge.working_techniques:
                lines.append(f"Working Techniques: {', '.join(knowledge.working_techniques[:10])}")
            if knowledge.failed_encodings:
                lines.append(f"Failed Encodings: {', '.join(knowledge.failed_encodings)}")
            if knowledge.waf_provider:
                lines.append(f"WAF Provider: {knowledge.waf_provider}")
            lines.append("")
        
        # Each Round
        for round_result in rounds:
            lines.append("")
            lines.append("=" * 80)
            lines.append(f"ROUND {round_result.round_number}")
            lines.append(f"Timestamp: {round_result.timestamp}")
            lines.append(f"Stats: {round_result.passed_count} passed, {round_result.blocked_count} blocked, {round_result.interesting_count} interesting")
            lines.append("=" * 80)
            
            # AI Prompt & Response (DEBUG)
            if round_result.plan:
                if round_result.plan.debug_prompt:
                    lines.append("")
                    lines.append("┌" + "─" * 78 + "┐")
                    lines.append("│ AI PROMPT SENT" + " " * 63 + "│")
                    lines.append("└" + "─" * 78 + "┘")
                    lines.append(round_result.plan.debug_prompt)
                    lines.append("")
                
                if round_result.plan.debug_response:
                    lines.append("┌" + "─" * 78 + "┐")
                    lines.append("│ AI RESPONSE RECEIVED" + " " * 57 + "│")
                    lines.append("└" + "─" * 78 + "┘")
                    lines.append(round_result.plan.debug_response)
                    lines.append("")
            
            # Plan info
            if round_result.plan:
                lines.append("")
                lines.append("ATTACK PLAN:")
                lines.append(f"  Vuln Class: {round_result.plan.vuln_class}")
                lines.append(f"  Reasoning: {round_result.plan.reasoning}")
                if round_result.plan.bypass_techniques:
                    lines.append(f"  Bypass Techniques: {', '.join(round_result.plan.bypass_techniques)}")
            
            # Each test/attempt
            for idx, test in enumerate(round_result.tests, 1):
                lines.append("")
                lines.append("-" * 60)
                lines.append(f"TEST #{idx}")
                lines.append("-" * 60)
                
                # Request info
                lines.append(f"Payload (original): {test.payload_original}")
                lines.append(f"Payload (sent):     {test.payload_sent}")
                lines.append(f"Encoding:           {test.encoding}")
                lines.append(f"Injection Point:    {test.injection_point}")
                lines.append("")
                lines.append(f"REQUEST: {test.method} {test.url}")
                
                # Response info
                lines.append("")
                status_indicator = "🚫 BLOCKED" if test.waf_blocked else ("⭐ INTERESTING" if test.is_interesting else "✓")
                lines.append(f"RESPONSE: HTTP {test.status_code} [{status_indicator}]")
                lines.append(f"Time: {test.response_time_ms}ms | Size: {test.response_length} bytes")
                
                if test.waf_blocked and test.waf_provider:
                    lines.append(f"WAF: {test.waf_provider}")
                    if test.waf_signature:
                        lines.append(f"WAF Signature: {test.waf_signature}")
                
                if test.diff_indicators:
                    lines.append(f"Diff Indicators: {', '.join(test.diff_indicators)}")
                
                # Response body snippet
                if test.response_snippet:
                    lines.append("")
                    lines.append("Response Body (snippet):")
                    lines.append("-" * 40)
                    # Limit to first 500 chars
                    snippet = test.response_snippet[:500]
                    if len(test.response_snippet) > 500:
                        snippet += "\n... [truncated]"
                    lines.append(snippet)
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF DUMP")
        lines.append("=" * 80)
        
        dump_text = "\n".join(lines)
        
        # Return as downloadable file
        filename = f"attack_dump_{endpoint_hash[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        return PlainTextResponse(
            content=dump_text,
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
        
    except Exception as e:
        logger.exception(f"Failed to generate attack dump: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/multi-round/{endpoint_hash}/history")
async def clear_attack_history(endpoint_hash: str):
    """Clear the attack history for an endpoint."""
    try:
        from ghost_hunter.core.brain.strategist_v2 import AttackHistory
        
        history = AttackHistory()
        history.clear_history(endpoint_hash)
        
        # Also clear from running attacks
        if endpoint_hash in _running_attacks:
            del _running_attacks[endpoint_hash]
        
        return {
            "status": "cleared",
            "message": f"Attack history cleared for {endpoint_hash}"
        }
        
    except Exception as e:
        logger.exception(f"Failed to clear attack history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _run_multi_round_attack(
    endpoint_hash: str,
    endpoint: Dict[str, Any],
    request: MultiRoundRequest,
):
    """Execute the multi-round attack in background."""
    try:
        from ghost_hunter.core.executor import MultiRoundRunner
        from ghost_hunter.core.brain.strategist_v2 import (
            OriginalContext,
            SecurityProfile,
        )
        
        # Build OriginalContext from endpoint data
        stored_headers = endpoint.get("example_headers", {})
        stored_url = endpoint.get("example_url", "")
        if not stored_url:
            example_path = endpoint.get("example_paths", [""])[0]
            stored_url = f"https://{endpoint.get('host', '')}{example_path}"
        
        # Get security profile if available
        security_profile = SecurityProfile()  # Default empty profile
        try:
            redis_store = get_redis_store()
            if redis_store:
                host = endpoint.get("host", "")
                profile_data = redis_store.redis.hget("security_profiles", host)
                if profile_data:
                    import json
                    profile_dict = json.loads(profile_data)
                    security_profile = SecurityProfile(
                        waf=profile_dict.get("waf"),
                        cdn=profile_dict.get("cdn"),
                        rate_limit=profile_dict.get("rate_limit", False),
                        anti_bot=profile_dict.get("anti_bot"),
                    )
        except Exception as e:
            logger.warning(f"Could not load security profile: {e}")
        
        # Build context
        context = OriginalContext(
            method=endpoint.get("method", "GET"),
            url=stored_url,
            headers=stored_headers,
            body=endpoint.get("example_body"),
            vuln_class=request.vuln_class,
            confidence=70,
            interesting_params=endpoint.get("interesting_params", []),
            triage_reasoning=f"Multi-round attack for {request.vuln_class}",
            security_profile=security_profile,
        )
        
        # Create runner
        runner = MultiRoundRunner(
            max_rounds=request.max_rounds,
            payloads_per_round=request.payloads_per_round,
        )
        
        # Update status callback
        def update_status(round_num: int, message: str):
            if endpoint_hash in _running_attacks:
                _running_attacks[endpoint_hash].current_round = round_num
                _running_attacks[endpoint_hash].message = message
        
        # Get session cookies
        session_cookies = request.session_cookies
        if not session_cookies:
            # Try to get from stored headers
            cookie_header = stored_headers.get("cookie") or stored_headers.get("Cookie", "")
            if cookie_header:
                session_cookies = {}
                for part in cookie_header.split(";"):
                    if "=" in part:
                        key, value = part.strip().split("=", 1)
                        session_cookies[key] = value
        
        logger.info(f"Starting multi-round attack on {endpoint_hash}")
        logger.info(f"Vuln class: {request.vuln_class}, Max rounds: {request.max_rounds}")
        
        # Run the attack
        result = await runner.run_attack(
            endpoint_hash=endpoint_hash,
            original_context=context,
            session_cookies=session_cookies,
        )
        
        # Update final status - update all values BEFORE setting status to "completed"
        # to avoid race condition where frontend sees "completed" but with old values
        if endpoint_hash in _running_attacks:
            attack_status = _running_attacks[endpoint_hash]
            attack_status.current_round = result.total_rounds
            attack_status.total_rounds = result.total_rounds
            attack_status.total_attempts = result.total_attempts
            attack_status.total_time_ms = result.total_time_ms
            attack_status.findings_count = len(result.findings)
            attack_status.message = (
                f"Completed {result.total_rounds} rounds, "
                f"{result.total_attempts} attempts, "
                f"{len(result.findings)} findings"
            )
            # Set status LAST to ensure all values are updated
            attack_status.status = "completed"
            
            # Also persist the final result in Redis for survival across restarts
            try:
                redis_store = get_redis_store()
                if redis_store and redis_store.connected:
                    import json
                    redis_store._redis.hset(
                        "multi_round_results",
                        endpoint_hash,
                        json.dumps(attack_status.model_dump())
                    )
            except Exception as persist_err:
                logger.warning(f"Failed to persist result to Redis: {persist_err}")
        
        # Store findings
        if result.findings:
            from dashboard.utils.storage import storage
            for finding in result.findings:
                finding_dict = {
                    "id": finding.id,
                    "endpoint": finding.endpoint,
                    "method": finding.method,
                    "vuln_type": finding.vuln_type,
                    "severity": finding.severity.value,
                    "status": finding.status.value,
                    "payload_successful": finding.payload_successful,
                    "ai_analysis": finding.ai_analysis,
                    "discovered_at": finding.discovered_at,
                    "tool_used": "strategist_v2_multi_round",
                }
                storage.add_finding(finding_dict)
        
        logger.info(f"Multi-round attack completed: {result}")
        
    except Exception as e:
        logger.exception(f"Multi-round attack failed: {e}")
        if endpoint_hash in _running_attacks:
            _running_attacks[endpoint_hash].status = "error"
            _running_attacks[endpoint_hash].message = str(e)


def _get_endpoint_data(endpoint_hash: str, pipeline) -> Optional[Dict[str, Any]]:
    """Get endpoint data from dedup or triage history."""
    # Try dedup first
    endpoints = pipeline.dedup.get_all_endpoints_data()
    for ep in endpoints:
        if ep.get("hash") == endpoint_hash:
            return ep
    
    # Try triage history
    triage_entry = get_redis_store().get_triage_by_hash(endpoint_hash)
    if triage_entry:
        original_req = triage_entry.get("original_request", {})
        return {
            "hash": endpoint_hash,
            "method": triage_entry.get("method", "GET"),
            "host": triage_entry.get("host", ""),
            "path": triage_entry.get("path", ""),
            "example_url": original_req.get("url", ""),
            "example_headers": original_req.get("headers", {}),
            "example_cookies": original_req.get("cookies", {}),
            "example_body": original_req.get("body", ""),
            "example_paths": [triage_entry.get("path", "")],
            "interesting_params": triage_entry.get("interesting_params", []),
        }
    
    return None

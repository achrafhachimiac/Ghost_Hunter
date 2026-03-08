"""
Executor Node
Executes attack plans through Ghost-Hunter with replay mutation support
"""

import json
import asyncio
import re
import uuid
from typing import Any, Optional
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..state import AgentState, AttackStep, HistoryEntry
from ..config import RATE_LIMIT_DELAY, MAX_REQUESTS_PER_CYCLE
from ..tools import get_client, get_extractor, get_checker
from ..redis_logger import get_agent_logger


async def replay_with_mutation(
    request_log: list[dict],
    request_id: str,
    parameter_to_swap: str,
    new_value: str,
    client
) -> dict[str, Any]:
    """
    Replay an existing request with a parameter mutation.
    
    This is the most reliable IDOR testing method because:
    - It preserves ALL original headers (cookies, CSRF, auth)
    - Only changes the specific parameter being tested
    - The request structure is 100% legitimate to the server
    
    Args:
        request_log: List of previously executed requests
        request_id: ID of the request to replay
        parameter_to_swap: Name of the parameter to mutate
        new_value: New value to inject
        client: Ghost-Hunter API client
    
    Returns:
        Response dict with {status_code, headers, body, time_ms, mutation_applied}
    """
    
    # Find the original request
    original_request = None
    for req in request_log:
        if req.get("id") == request_id:
            original_request = req
            break
    
    if not original_request:
        return {
            "error": f"Request {request_id} not found in request_log",
            "status_code": 0
        }
    
    # Clone the original request
    method = original_request.get("method", "GET")
    url = original_request.get("url", "")
    headers = dict(original_request.get("headers", {}))
    body = original_request.get("body", "")
    
    mutation_applied = False
    mutation_location = ""
    original_value = ""
    
    # Try to apply mutation in different locations
    
    # 1. URL Path - e.g., /api/users/123 -> /api/users/456
    if f"/{parameter_to_swap}/" in url or url.endswith(f"/{parameter_to_swap}"):
        # Parameter is in path - try to find numeric/uuid patterns after it
        pass  # Path mutation is complex, try query params first
    
    # 2. URL Query Parameters - e.g., ?user_id=123 -> ?user_id=456
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    
    if parameter_to_swap in query_params:
        original_value = query_params[parameter_to_swap][0]
        query_params[parameter_to_swap] = [new_value]
        new_query = urlencode(query_params, doseq=True)
        url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        mutation_applied = True
        mutation_location = "query_param"
    
    # 3. Request Body (JSON) - e.g., {"user_id": 123} -> {"user_id": 456}
    elif body:
        try:
            body_json = json.loads(body)
            
            def mutate_json(obj, param_name, new_val):
                """Recursively find and mutate parameter in JSON"""
                mutated = False
                orig_val = None
                
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        if key == param_name:
                            orig_val = obj[key]
                            obj[key] = new_val
                            return True, orig_val
                        elif isinstance(value, (dict, list)):
                            mutated, orig_val = mutate_json(value, param_name, new_val)
                            if mutated:
                                return True, orig_val
                                
                elif isinstance(obj, list):
                    for item in obj:
                        mutated, orig_val = mutate_json(item, param_name, new_val)
                        if mutated:
                            return True, orig_val
                
                return False, None
            
            mutation_applied, original_value = mutate_json(body_json, parameter_to_swap, new_value)
            if mutation_applied:
                body = json.dumps(body_json)
                mutation_location = "json_body"
                
        except json.JSONDecodeError:
            # Try form-data or other body formats
            pass
    
    # 4. URL Path segment - /api/resource/{id}/action
    if not mutation_applied:
        # Look for parameter value in URL path
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            # Check if this looks like an ID that matches our parameter context
            if part and (
                part.isdigit() or 
                len(part) == 36 and "-" in part or  # UUID
                part.endswith("==")  # Base64
            ):
                original_value = part
                path_parts[i] = new_value
                new_path = "/".join(path_parts)
                url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    new_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
                mutation_applied = True
                mutation_location = "url_path"
                break
    
    if not mutation_applied:
        return {
            "error": f"Could not find parameter '{parameter_to_swap}' to mutate",
            "original_request": original_request,
            "status_code": 0
        }
    
    # Execute the mutated request
    try:
        result = await client.run_request(
            method=method,
            url=url,
            headers=headers,
            body=body if body else None
        )
        
        result["mutation_applied"] = {
            "parameter": parameter_to_swap,
            "location": mutation_location,
            "original_value": str(original_value),
            "new_value": new_value,
            "original_request_id": request_id
        }
        
        return result
        
    except Exception as e:
        return {
            "error": str(e),
            "mutation_applied": {
                "parameter": parameter_to_swap,
                "location": mutation_location,
                "original_value": str(original_value),
                "new_value": new_value
            },
            "status_code": 0
        }



async def executor_node(state: AgentState) -> dict[str, Any]:
    """
    Executor Node - Executes attack plans with replay support
    
    Responsibilities:
    1. Execute attack steps through Ghost-Hunter API
    2. Support REPLAY mode for mutation-based IDOR testing
    3. Capture responses and store in request_log for future replay
    4. Apply diff checking to detect vulnerabilities
    5. Update data_provenance with response data
    """
    
    # Get logger for live thoughts
    logger = get_agent_logger()
    logger.set_iteration(state.get("iteration", 0))
    
    attack_plan = state.get("attack_plan", [])
    replay_config = state.get("replay_config")
    action_type = state.get("action_type", "execute")
    request_log = state.get("request_log", [])
    
    # Get tools
    extractor = get_extractor()
    checker = get_checker()
    
    # Track results
    executed_steps: list[AttackStep] = []
    history_entries: list[HistoryEntry] = []
    new_findings: list[dict[str, Any]] = []
    new_request_log: list[dict] = []
    last_response: Optional[dict] = None
    
    async with get_client() as client:
        # First, check Ghost-Hunter health
        if not await client.health_check():
            logger.log_error("executor", "Ghost-Hunter API not responding!")
            return {
                "error": "Ghost-Hunter API not available",
                "reasoning_trace": state.get("reasoning_trace", []) + [
                    "[Executor] ERROR: Ghost-Hunter API not responding"
                ]
            }
        
        # =====================================================================
        # REPLAY MODE - Replay existing request with parameter mutation
        # =====================================================================
        if action_type == "replay" and replay_config:
            request_id = replay_config.get("request_id", "")
            param_to_swap = replay_config.get("parameter_to_swap", "")
            new_value = replay_config.get("new_value", "")
            
            logger.executor_replay(request_id, param_to_swap, new_value)
            
            if request_id and param_to_swap and new_value:
                result = await replay_with_mutation(
                    request_log=request_log,
                    request_id=request_id,
                    parameter_to_swap=param_to_swap,
                    new_value=new_value,
                    client=client
                )
                
                if result.get("error"):
                    logger.log_error("executor", f"Replay failed: {result.get('error')}")
                    history_entries.append({
                        "timestamp": datetime.now().isoformat(),
                        "action": f"REPLAY {request_id} [{param_to_swap}={new_value}]",
                        "target": request_id,
                        "modification": replay_config,
                        "outcome": "error",
                        "response_summary": {},
                        "learnings": f"Replay failed: {result.get('error')}"
                    })
                else:
                    status_code = result.get("status_code", 0)
                    response_body = result.get("body", "")
                    
                    logger.executor_result(status_code, suspicious=(status_code == 200))
                    
                    # Find original request for comparison
                    original_req = next(
                        (r for r in request_log if r.get("id") == request_id), 
                        {}
                    )
                    original_body = original_req.get("response_body", "")
                    original_status = original_req.get("response_status", 0)
                    
                    # Compare responses
                    comparison = checker.compare_responses(
                        baseline_body=original_body,
                        baseline_status=original_status,
                        modified_body=response_body,
                        modified_status=status_code
                    )
                    
                    # Detect IDOR
                    idor_result = checker.detect_idor(
                        original_response=original_body,
                        original_status=original_status,
                        tampered_response=response_body,
                        tampered_status=status_code,
                        tampered_id=new_value
                    )
                    
                    outcome = "no_finding"
                    learnings = ""
                    
                    if idor_result.get("is_vulnerable"):
                        outcome = "idor_confirmed"
                        learnings = f"IDOR CONFIRMED: {'; '.join(idor_result.get('evidence', []))}"
                        
                        # LOG THE FINDING
                        logger.idor_detected(
                            param=param_to_swap,
                            original_value=result.get("mutation_applied", {}).get("original_value", ""),
                            new_value=new_value,
                            evidence=learnings
                        )
                        
                        new_findings.append({
                            "type": "IDOR_CONFIRMED",
                            "url": original_req.get("url", ""),
                            "method": original_req.get("method", ""),
                            "parameter": param_to_swap,
                            "original_value": result.get("mutation_applied", {}).get("original_value"),
                            "injected_value": new_value,
                            "evidence": idor_result,
                            "severity": "critical",
                            "provenance": replay_config.get("source_provenance", "")
                        })
                    elif comparison.has_data_leak:
                        outcome = "data_leak"
                        learnings = "Potential data leak detected"
                        logger.log_finding("executor", "Potential data leak detected", severity="high")
                        new_findings.append({
                            "type": "POTENTIAL_DATA_LEAK",
                            "url": original_req.get("url", ""),
                            "parameter": param_to_swap,
                            "evidence": comparison.to_dict(),
                            "severity": "high"
                        })
                    else:
                        learnings = f"Replay completed: status={status_code}, no significant difference"
                        logger.log_result("executor", learnings)
                    
                    # Store last response for pivoter extraction
                    last_response = {
                        "url": original_req.get("url", ""),
                        "method": original_req.get("method", ""),
                        "status": status_code,
                        "headers": result.get("headers", {}),
                        "body": response_body,
                        "timestamp": datetime.now().isoformat(),
                        "content_type": result.get("headers", {}).get("content-type", "")
                    }
                    
                    history_entries.append({
                        "timestamp": datetime.now().isoformat(),
                        "action": f"REPLAY {request_id} [{param_to_swap}={new_value[:30]}...]",
                        "target": original_req.get("url", ""),
                        "modification": result.get("mutation_applied", {}),
                        "outcome": outcome,
                        "response_summary": {
                            "status": status_code,
                            "size": len(response_body),
                            "differs": not comparison.is_identical
                        },
                        "learnings": learnings
                    })
                
                # Return after replay
                confirmed_vulns = state.get("confirmed_vulns", [])
                for finding in new_findings:
                    if finding.get("severity") in ("critical", "high"):
                        confirmed_vulns.append(finding)
                
                return {
                    "history": state.get("history", []) + history_entries,
                    "confirmed_vulns": confirmed_vulns,
                    "last_response": last_response,
                    "replay_config": None,  # Clear after execution
                    "reasoning_trace": state.get("reasoning_trace", []) + [
                        f"[Executor] REPLAY completed: {outcome}"
                    ]
                }
        
        # =====================================================================
        # NORMAL EXECUTION MODE
        # =====================================================================
        
        if not attack_plan:
            logger.log_thought("executor", "No attack steps to execute")
            return {
                "reasoning_trace": state.get("reasoning_trace", []) + [
                    "[Executor] No attack steps to execute"
                ]
            }
        
        # Capture baseline response (original request)
        baseline_responses: dict[str, dict] = {}
        
        # Filter to pending steps
        pending_steps = [s for s in attack_plan if s.get("status") == "pending"]
        steps_to_execute = pending_steps[:MAX_REQUESTS_PER_CYCLE]
        
        logger.log_thought("executor", f"Executing {len(steps_to_execute)} attack steps")
        
        # Get base URL from target lead for template resolution
        target_lead = state.get("target_lead", {})
        actual_base_url = target_lead.get("url", "")
        if not actual_base_url:
            # Try to get from pivot_queue
            pivot_queue = state.get("pivot_queue", [])
            if pivot_queue:
                actual_base_url = pivot_queue[0].get("url", "")
        
        # =====================================================================
        # GET SESSION CONTEXT (headers/cookies from captured request)
        # =====================================================================
        session_context = state.get("session_context", {})
        session_headers = session_context.get("headers", {})
        session_cookies = session_context.get("cookies", {})
        
        # Headers that should NOT be sent (managed by httpx or cause issues)
        SKIP_HEADERS = {
            'host', 'content-length', 'transfer-encoding', 'connection',
            'keep-alive', 'proxy-authenticate', 'proxy-authorization',
            'te', 'trailers', 'upgrade', 'accept-encoding'
        }
        
        # Build base headers from session (for authentication!)
        # Normalize header names and skip problematic ones
        base_headers = {}
        for key, value in session_headers.items():
            key_lower = key.lower()
            if key_lower not in SKIP_HEADERS:
                # Use the original key casing
                base_headers[key] = value
        
        # Handle cookies: merge session_cookies with any existing cookie header
        existing_cookie = None
        cookie_key = None
        for key in list(base_headers.keys()):
            if key.lower() == 'cookie':
                existing_cookie = base_headers.pop(key)
                cookie_key = key
                break
        
        # Merge cookies
        all_cookies = {}
        
        # Parse existing cookie header (handle both ; and , separators)
        if existing_cookie:
            # Normalize: convert comma separator to semicolon if needed
            normalized = existing_cookie
            if ', ' in normalized and '; ' not in normalized:
                normalized = normalized.replace(', ', '; ')
            for part in normalized.split(';'):
                if '=' in part:
                    k, v = part.strip().split('=', 1)
                    all_cookies[k] = v
        
        # Add session cookies (may override)
        if session_cookies:
            all_cookies.update(session_cookies)
        
        # Rebuild single Cookie header with correct semicolon separator
        if all_cookies:
            base_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in all_cookies.items()])
        
        # Log session info
        if base_headers:
            logger.log_thought("executor", f"Using session headers: {list(base_headers.keys())}")
        else:
            logger.log_warning("executor", "⚠️ No session headers - requests may fail with 401!")
        
        # Track all HTTP requests for debugging
        http_request_history: list[dict] = []
        
        # Parse base URL components for template resolution
        if actual_base_url:
            parsed_base = urlparse(actual_base_url)
            base_scheme_host = f"{parsed_base.scheme}://{parsed_base.netloc}"
            base_full = actual_base_url.split("?")[0]  # URL without query params
        else:
            base_scheme_host = ""
            base_full = ""
        
        # Helper to resolve URL templates (both {var} and {{var}} formats)
        def resolve_url_template(url: str) -> str:
            """Replace URL templates with actual values."""
            if not url:
                return url
            
            # Skip if URL looks valid (starts with http)
            if url.startswith("http://") or url.startswith("https://"):
                return url
            
            # Resolve various template formats
            templates_to_replace = [
                # Double braces
                ("{{base_url}}", base_scheme_host),
                ("{{ base_url }}", base_scheme_host),
                # Single braces (LLM often uses these)
                ("{base_url}", base_full),
                ("{session_url}", base_full),
                ("{target_url}", base_full),
                ("{url}", base_full),
            ]
            
            for template, replacement in templates_to_replace:
                if template in url and replacement:
                    url = url.replace(template, replacement)
            
            # If URL still doesn't start with http, prepend base
            if not url.startswith("http") and base_scheme_host:
                if url.startswith("/"):
                    url = f"{base_scheme_host}{url}"
                else:
                    url = f"{base_scheme_host}/{url}"
            
            if not url.startswith("http"):
                logger.log_error("executor", f"Cannot resolve URL template: {url[:50]} - no base URL available")
            
            return url
        
        for step in steps_to_execute:
            url = resolve_url_template(step.get("target_url", ""))
            method = step.get("method", "GET")
            
            # Prepare headers for baseline - remove Content-Type for GET requests
            baseline_headers = dict(base_headers)
            if method.upper() in ("GET", "HEAD", "DELETE", "OPTIONS"):
                baseline_headers = {k: v for k, v in baseline_headers.items() if k.lower() != 'content-type'}
            
            # Get baseline if not already captured
            baseline_key = f"{method}:{url}"
            if baseline_key not in baseline_responses:
                try:
                    logger.log_action("executor", f"Capturing baseline: {method} {url[:50]}...")
                    # USE SESSION HEADERS for baseline!
                    baseline = await client.run_request(
                        method=method,
                        url=url,
                        headers=baseline_headers,  # Include auth headers! (no Content-Type for GET)
                        body=None
                    )
                    baseline_responses[baseline_key] = baseline
                    
                    # Log detailed request for debugging panel
                    logger.log_http_request_detail(
                        step="baseline",
                        method=method,
                        url=url,
                        headers=baseline_headers,
                        body="",
                        status=baseline.get("status_code", 0),
                        response_body=baseline.get("body", "")
                    )
                    
                    # Log detailed request for debugging
                    http_request_history.append({
                        "step": "baseline",
                        "method": method,
                        "url": url,
                        "headers": base_headers,
                        "body": None,
                        "status": baseline.get("status_code", 0),
                        "response_preview": baseline.get("body", "")[:200]
                    })
                    
                    # Store in request_log for future replay
                    req_id = str(uuid.uuid4())[:8]
                    new_request_log.append({
                        "id": req_id,
                        "method": method,
                        "url": url,
                        "headers": base_headers,
                        "body": None,
                        "timestamp": datetime.now().isoformat(),
                        "response_status": baseline.get("status_code", 0),
                        "response_body": baseline.get("body", "")[:10000]  # Limit size
                    })
                    
                except Exception as e:
                    logger.log_error("executor", f"Baseline capture failed: {e}")
                    baseline_responses[baseline_key] = {
                        "status_code": 0,
                        "body": "",
                        "error": str(e)
                    }
            
            await asyncio.sleep(RATE_LIMIT_DELAY)
        
        # Execute modified requests
        for i, step in enumerate(steps_to_execute):
            step_id = step.get("step_id", "unknown")
            url = resolve_url_template(step.get("target_url", ""))
            method = step.get("method", "GET")
            modifications = step.get("modifications", {})
            expected = step.get("expected_outcome", {})
            
            logger.log_progress("executor", i + 1, len(steps_to_execute), 
                f"Executing step: {step_id}")
            logger.executor_running(method, url)
            
            # Apply modifications to request
            modified_url = url
            # START WITH SESSION HEADERS, then apply modifications
            modified_headers = dict(base_headers)  # Copy session headers!
            modified_body = None
            
            # CRITICAL: Remove Content-Type for GET/HEAD requests without body
            # Some servers return 400 if Content-Type is sent on GET
            if method.upper() in ("GET", "HEAD", "DELETE", "OPTIONS"):
                modified_headers = {k: v for k, v in modified_headers.items() if k.lower() != 'content-type'}
            
            mod_type = modifications.get("type", "")
            param_name = modifications.get("param_name", "")
            modified_value = modifications.get("modified", "")
            
            if mod_type == "parameter":
                if "?" in url and param_name in url:
                    pattern = f"({param_name}=)[^&]+"
                    # Use lambda to avoid regex backreference issues with special chars
                    modified_url = re.sub(pattern, lambda m: f"{m.group(1)}{modified_value}", url)
                elif "?" in url:
                    modified_url = f"{url}&{param_name}={modified_value}"
                else:
                    modified_url = f"{url}?{param_name}={modified_value}"
            
            elif mod_type == "path":
                original_value = modifications.get("original", "")
                if original_value and original_value in url:
                    modified_url = url.replace(original_value, modified_value)
            
            elif mod_type == "header":
                modified_headers[param_name] = modified_value
            
            elif mod_type == "body":
                modified_body = modified_value
            
            # Execute modified request
            try:
                result = await client.run_request(
                    method=method,
                    url=modified_url,
                    headers=modified_headers,  # Now includes session headers!
                    body=modified_body
                )
                
                status_code = result.get("status_code", 0)
                response_body = result.get("body", "")
                response_time = result.get("time_ms", 0)
                
                logger.executor_result(status_code)
                
                # Log detailed HTTP request for debugging panel
                logger.log_http_request_detail(
                    step=step_id,
                    method=method,
                    url=modified_url,
                    headers=modified_headers,
                    body=modified_body or "",
                    status=status_code,
                    response_body=response_body
                )
                
                # Log detailed HTTP request for debugging
                http_request_history.append({
                    "step": step_id,
                    "method": method,
                    "url": modified_url,
                    "headers": modified_headers,
                    "body": modified_body,
                    "status": status_code,
                    "response_preview": response_body[:200] if response_body else ""
                })
                
                # Store in request_log
                req_id = str(uuid.uuid4())[:8]
                new_request_log.append({
                    "id": req_id,
                    "method": method,
                    "url": modified_url,
                    "headers": modified_headers,
                    "body": modified_body,
                    "timestamp": datetime.now().isoformat(),
                    "response_status": status_code,
                    "response_body": response_body[:10000],
                    "modification": modifications
                })
                
                # Store last response for pivoter
                last_response = {
                    "url": modified_url,
                    "method": method,
                    "status": status_code,
                    "headers": result.get("headers", {}),
                    "body": response_body,
                    "timestamp": datetime.now().isoformat(),
                    "content_type": result.get("headers", {}).get("content-type", "")
                }
                
                # Compare with baseline
                baseline_key = f"{method}:{url}"
                baseline = baseline_responses.get(baseline_key, {})
                
                comparison = checker.compare_responses(
                    baseline_body=baseline.get("body", ""),
                    baseline_status=baseline.get("status_code", 0),
                    modified_body=response_body,
                    modified_status=status_code
                )
                
                # Determine outcome
                outcome = "no_finding"
                learnings = ""
                
                if comparison.has_data_leak:
                    outcome = "data_leak"
                    learnings = "Detected potential data leak - different data returned"
                    new_findings.append({
                        "type": "DATA_LEAK",
                        "step_id": step_id,
                        "url": modified_url,
                        "method": method,
                        "modification": modifications,
                        "evidence": comparison.to_dict(),
                        "severity": "high"
                    })
                
                elif comparison.has_privilege_issue:
                    outcome = "privilege_bypass"
                    learnings = "Detected privilege escalation - unauthorized access"
                    new_findings.append({
                        "type": "PRIVILEGE_BYPASS",
                        "step_id": step_id,
                        "url": modified_url,
                        "method": method,
                        "modification": modifications,
                        "evidence": comparison.to_dict(),
                        "severity": "critical"
                    })
                
                elif not comparison.is_identical:
                    expected_status = expected.get("status_code", [])
                    if expected_status and status_code in expected_status:
                        if expected.get("response_differs", False):
                            outcome = "potential_idor"
                            learnings = "Response differs with modified ID - potential IDOR"
                            new_findings.append({
                                "type": "POTENTIAL_IDOR",
                                "step_id": step_id,
                                "url": modified_url,
                                "method": method,
                                "modification": modifications,
                                "evidence": {
                                    "baseline_status": baseline.get("status_code"),
                                    "modified_status": status_code,
                                    "differences": len(comparison.differences)
                                },
                                "severity": "medium"
                            })
                    else:
                        learnings = f"Response changed but status {status_code} not in expected {expected_status}"
                else:
                    learnings = "No difference detected - ID may not be valid or accessible"
                
                # Check if success criteria met
                success = False
                if expected.get("status_code") and status_code in expected["status_code"]:
                    success = True
                if expected.get("response_contains"):
                    for pattern in expected["response_contains"]:
                        if pattern in response_body:
                            success = True
                
                step["actual_outcome"] = {
                    "status_code": status_code,
                    "response_size": len(response_body),
                    "response_time_ms": response_time,
                    "comparison": comparison.summary,
                    "success": success,
                    "request_log_id": req_id
                }
                step["status"] = "completed"
                
                history_entries.append({
                    "timestamp": datetime.now().isoformat(),
                    "action": f"{method} {modified_url}",
                    "target": step.get("target_url", ""),
                    "modification": modifications,
                    "outcome": outcome,
                    "response_summary": {
                        "status": status_code,
                        "size": len(response_body),
                        "time_ms": response_time
                    },
                    "learnings": learnings,
                    "request_log_id": req_id
                })
                
            except Exception as e:
                step["status"] = "failed"
                step["actual_outcome"] = {"error": str(e)}
                
                history_entries.append({
                    "timestamp": datetime.now().isoformat(),
                    "action": f"{method} {modified_url}",
                    "target": step.get("target_url", ""),
                    "modification": modifications,
                    "outcome": "error",
                    "response_summary": {},
                    "learnings": f"Request failed: {str(e)}"
                })
            
            executed_steps.append(step)
            await asyncio.sleep(RATE_LIMIT_DELAY)
        
        # =====================================================================
        # LOG HTTP REQUEST HISTORY FOR DEBUGGING
        # =====================================================================
        if http_request_history:
            logger.log_thought("executor", f"📋 HTTP Request History ({len(http_request_history)} requests):")
            for req in http_request_history:
                # Mask sensitive headers for display
                display_headers = {k: ("***" if k.lower() in ("authorization", "cookie", "x-csrf-token") else str(v)[:50]) 
                                   for k, v in req.get("headers", {}).items()}
                logger.log_thought("executor", 
                    f"  [{req.get('step', '?')}] {req.get('method')} {req.get('url', '')[:80]} → {req.get('status')}\n"
                    f"    Headers: {list(display_headers.keys())}\n"
                    f"    Response: {req.get('response_preview', '')[:100]}..."
                )
    
    # Update attack plan with executed steps
    updated_plan = []
    for step in attack_plan:
        executed = next((s for s in executed_steps if s["step_id"] == step["step_id"]), None)
        if executed:
            updated_plan.append(executed)
        else:
            updated_plan.append(step)
    
    # Update confirmed vulns
    confirmed_vulns = state.get("confirmed_vulns", [])
    for finding in new_findings:
        if finding.get("severity") in ("critical", "high"):
            confirmed_vulns.append(finding)
    
    # Merge request logs
    updated_request_log = request_log + new_request_log
    # Keep last 50 requests
    updated_request_log = updated_request_log[-50:]
    
    # =========================================================================
    # BUILD BASELINE RESPONSE FOR IDOR COMPARISON
    # =========================================================================
    # The baseline is the FIRST successful response (with original ID)
    # This will be compared against attack responses by the pivoter
    baseline_response = state.get("baseline_response")
    
    # If no baseline yet and we have a first response, use it
    if not baseline_response and baseline_responses:
        first_key = next(iter(baseline_responses), None)
        if first_key:
            baseline = baseline_responses[first_key]
            # Extract the request_id from query params or state
            target_lead = state.get("target_lead", {})
            request_id = ""
            
            # Try to extract ID from URL params
            if target_lead.get("url"):
                parsed = urlparse(target_lead["url"])
                query_params = parse_qs(parsed.query)
                # Look for ID-like params
                for param in ("subject_id", "user_id", "patient_id", "id", "account_id"):
                    if param in query_params:
                        request_id = query_params[param][0]
                        break
            
            baseline_response = {
                "url": baseline.get("url", ""),
                "method": baseline.get("method", "GET"),
                "status": baseline.get("status_code", 0),
                "headers": baseline.get("headers", {}),
                "body": baseline.get("body", ""),
                "request_id": request_id,  # The ID used in the baseline request
                "timestamp": datetime.now().isoformat()
            }
    
    # If last_response is from an attack (different ID), add request_id for comparison
    if last_response and attack_plan:
        # Try to extract the attacked ID from modifications
        for step in executed_steps:
            if step.get("modifications"):
                for mod in step["modifications"]:
                    param = mod.get("param", "")
                    attack_value = mod.get("attack_value", "")
                    if param and attack_value:
                        last_response["request_id"] = f"{param}={attack_value}"
                        break
    
    return {
        "attack_plan": updated_plan,
        "history": state.get("history", []) + history_entries,
        "confirmed_vulns": confirmed_vulns,
        "request_log": updated_request_log,
        "last_response": last_response,
        "baseline_response": baseline_response,  # NEW: For IDOR semantic comparison
        "http_request_history": http_request_history,  # Include for debugging
        "reasoning_trace": state.get("reasoning_trace", []) + [
            f"[Executor] Executed {len(executed_steps)} steps, found {len(new_findings)} potential issues"
        ]
    }


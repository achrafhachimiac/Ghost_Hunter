"""
Pivoter Node
Analyzes execution results and decides next pivot with full data provenance

CRITICAL RULES:
1. NEVER invent endpoints - only use URLs from request_log or real_endpoints
2. Use SEMANTIC IDOR detection - compare internal IDs in responses
3. Continue exploiting findings (horizontal movement)
"""

import json
from typing import Any, Literal
from langchain_core.messages import SystemMessage, HumanMessage

from ..state import AgentState, TargetLead
from ..config import get_attack_llm, MAX_ITERATIONS
from ..tools import get_extractor
from ..tools.diff_checker import get_checker, get_token_decoder
from ..redis_logger import get_agent_logger


PIVOTER_SYSTEM_PROMPT = """You are a senior penetration tester analyzing attack results to decide the next move.
You have access to DATA PROVENANCE - you know exactly where each piece of data came from.

**CRITICAL RULE: NEVER INVENT ENDPOINTS!**
You can ONLY use URLs that exist in:
1. `request_log` - requests we actually made
2. `real_endpoints` - endpoints from captured traffic

If you need to test a new endpoint, pick one from `real_endpoints` list.
DO NOT hallucinate URLs like `/api/validate` or `/api/user/profile` unless they exist.

Your role is to:
1. **Analyze IDOR Detection Results**: Look at the SEMANTIC IDOR analysis
2. **Use Provenance**: Know which IDs came from which endpoints and users
3. **Horizontal Movement**: If IDOR found, find OTHER endpoints with same ID type
4. **Decide Next Action**: Continue, pivot, replay, or conclude

SEMANTIC IDOR DETECTION RULES:
- If `idor_detection.has_idor == true` → IDOR IS CONFIRMED!
- Look at `idor_evidence` for proof: different internal IDs for different request IDs
- Example: Request(subject_id=163738712) → id=89563121
           Request(subject_id=1) → id=10507384
  → CONFIRMED IDOR because internal IDs differ!

HORIZONTAL MOVEMENT:
When IDOR is confirmed on one endpoint:
1. Search `real_endpoints` for other endpoints using same parameter (e.g., subject_id)
2. Add those endpoints to `next_targets` to test them too
3. Keep exploiting until all endpoints with that parameter are tested

Output your decision as JSON:
{
    "decision": "continue|pivot|replay|conclude|report",
    "action": "execute|replay",
    "reasoning": "Detailed reasoning using provenance data",
    "is_idor_confirmed": true/false,
    "idor_evidence_summary": "Brief summary of IDOR evidence if found",
    "replay_config": {
        "request_id": "ID of request to replay (from request_log)",
        "parameter_to_swap": "name of parameter to change",
        "new_value": "value to inject",
        "source_provenance": "where the new_value came from"
    },
    "next_targets": [
        {
            "url": "MUST BE from real_endpoints or request_log!",
            "method": "HTTP method",
            "vulnerability_type": "IDOR|AUTH_BYPASS|DATA_LEAK",
            "parameter_to_test": "specific param",
            "test_value": "value to inject",
            "value_provenance": "where this value came from"
        }
    ],
    "horizontal_movement": {
        "confirmed_idor_param": "e.g. subject_id",
        "other_endpoints_to_test": ["list of other endpoints from real_endpoints with same param"]
    },
    "confidence": 0.8,
    "should_report": true/false
}

Decision types:
- CONTINUE: Same target, different technique (or horizontal movement)
- PIVOT: Move to new target from real_endpoints using extracted data
- REPLAY: Replay an existing request with parameter mutation
- REPORT: Critical finding that needs immediate attention (IDOR confirmed!)
- CONCLUDE: No more productive paths (ONLY after testing all candidates)

IMPORTANT: 
- When IDOR is confirmed, ALWAYS use decision=report with should_report=true
- Always specify request_id from request_log for REPLAY
- NEVER invent URLs - use real_endpoints list
"""



async def pivoter_node(state: AgentState) -> dict[str, Any]:
    """
    Pivoter Node - Decides next action based on results with full provenance
    
    ENHANCED with:
    1. SEMANTIC IDOR detection using DiffChecker
    2. Real endpoints constraint (no hallucination)
    3. Horizontal movement logic
    4. Token decoding for hidden IDs
    """
    
    # Get logger for live thoughts
    logger = get_agent_logger()
    logger.set_iteration(state.get("iteration", 0))
    
    # Use Sonnet (attack model) for strategic decisions
    llm = get_attack_llm()
    
    extractor = get_extractor()
    diff_checker = get_checker()
    token_decoder = get_token_decoder()
    
    # Get current state
    iteration = state.get("iteration", 0) + 1
    history = state.get("history", [])
    attack_plan = state.get("attack_plan", [])
    confirmed_vulns = state.get("confirmed_vulns", [])
    data_provenance = state.get("data_provenance", {})
    last_response = state.get("last_response", {})
    baseline_response = state.get("baseline_response", {})  # For IDOR comparison
    request_log = state.get("request_log", [])
    real_endpoints = state.get("real_endpoints", [])  # Endpoints from captured traffic
    
    logger.pivoter_analyzing(len(data_provenance))
    
    # Check termination conditions
    if iteration >= MAX_ITERATIONS:
        logger.log_result("pivoter", f"Reached max iterations ({MAX_ITERATIONS}), concluding")
        return {
            "iteration": iteration,
            "should_continue": False,
            "reasoning_trace": state.get("reasoning_trace", []) + [
                f"[Pivoter] Reached max iterations ({MAX_ITERATIONS}), concluding"
            ]
        }
    
    # =========================================================================
    # SEMANTIC IDOR DETECTION
    # =========================================================================
    idor_detection_result = None
    
    if baseline_response and last_response:
        baseline_body = baseline_response.get("body", "")
        attack_body = last_response.get("body", "")
        baseline_status = baseline_response.get("status", 0)
        attack_status = last_response.get("status", 0)
        
        # Get the IDs used in requests
        baseline_id = baseline_response.get("request_id", "")  # e.g., subject_id=163738712
        attack_id = last_response.get("request_id", "")  # e.g., subject_id=1
        
        # Run semantic IDOR detection
        idor_detection_result = diff_checker.detect_idor(
            original_response=baseline_body,
            original_status=baseline_status,
            tampered_response=attack_body,
            tampered_status=attack_status,
            tampered_id=attack_id,
            original_id=baseline_id
        )
        
        if idor_detection_result.get("is_vulnerable"):
            logger.log_result("pivoter", f"🚨 SEMANTIC IDOR DETECTED! Confidence: {idor_detection_result.get('confidence', 0):.0%}")
            
            # Auto-add to confirmed vulns if high confidence
            if idor_detection_result.get("confidence", 0) >= 0.8:
                confirmed_vulns.append({
                    "type": "IDOR",
                    "subtype": idor_detection_result.get("idor_type"),
                    "url": last_response.get("url", ""),
                    "method": last_response.get("method", ""),
                    "severity": idor_detection_result.get("severity"),
                    "evidence": idor_detection_result.get("evidence"),
                    "confidence": idor_detection_result.get("confidence"),
                    "baseline_id": baseline_id,
                    "attack_id": attack_id
                })
    
    # =========================================================================
    # TOKEN DECODING - Extract hidden IDs from encoded fields
    # =========================================================================
    decoded_tokens = {}
    extracted_hidden_ids = []
    
    if last_response and last_response.get("body"):
        try:
            body_json = json.loads(last_response.get("body", "{}"))
            decoded_tokens = token_decoder.extract_encoded_ids(body_json)
            
            for path, token_info in decoded_tokens.items():
                if token_info.get("decoded"):
                    hidden_ids = token_decoder.extract_ids_from_decoded(
                        token_info["decoded"] if isinstance(token_info["decoded"], dict) else {}
                    )
                    extracted_hidden_ids.extend(hidden_ids)
                    
            if decoded_tokens:
                logger.log_thought("pivoter", f"Decoded {len(decoded_tokens)} tokens, found {len(extracted_hidden_ids)} hidden IDs")
        except json.JSONDecodeError:
            pass
    
    # =========================================================================
    # EXTRACT PATTERNS FROM LAST RESPONSE WITH FULL PROVENANCE
    # =========================================================================
    new_provenance = {}
    idor_candidates = []
    
    if last_response and last_response.get("body"):
        # Extract with full provenance tracking
        patterns = extractor.extract_from_response(
            body=last_response.get("body", ""),
            headers=last_response.get("headers", {}),
            url=last_response.get("url", "")
        )
        
        # Build provenance map from extracted patterns
        for prov in patterns.provenance:
            new_provenance[prov.value] = {
                "type": prov.pattern_type,
                "json_path": prov.json_path,
                "source_url": prov.source_url,
                "source_field": prov.source_field,
                "context": prov.context,
                "extracted_at": last_response.get("timestamp", ""),
                "user_role": state.get("target_lead", {}).get("user_role", "unknown")
            }
        
        # Get IDOR candidates with provenance
        idor_candidates = extractor.find_idor_candidates(patterns)
    
    # Merge with existing provenance
    updated_provenance = {**data_provenance, **new_provenance}
    
    # =========================================================================
    # BUILD DECISION CONTEXT WITH PROVENANCE + IDOR DETECTION + REAL ENDPOINTS
    # =========================================================================
    
    # Analyze recent execution results
    recent_history = history[-5:] if history else []
    outcomes = {}
    for entry in recent_history:
        outcome = entry.get("outcome", "unknown")
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    
    # Build rich context for LLM
    decision_context = {
        "iteration": iteration,
        "max_iterations": MAX_ITERATIONS,
        
        # ===== SEMANTIC IDOR DETECTION RESULTS =====
        "idor_detection": {
            "has_idor": idor_detection_result.get("is_vulnerable", False) if idor_detection_result else False,
            "confidence": idor_detection_result.get("confidence", 0) if idor_detection_result else 0,
            "idor_type": idor_detection_result.get("idor_type", "none") if idor_detection_result else "none",
            "severity": idor_detection_result.get("severity", "none") if idor_detection_result else "none",
            "evidence": idor_detection_result.get("evidence", []) if idor_detection_result else [],
            "summary": idor_detection_result.get("report", {}).get("summary", "") if idor_detection_result else ""
        } if idor_detection_result else None,
        
        # ===== DECODED TOKENS & HIDDEN IDS =====
        "decoded_tokens": list(decoded_tokens.values())[:5],
        "hidden_ids": extracted_hidden_ids[:10],
        
        # Recent history with learnings
        "recent_history": [
            {
                "action": h.get("action", ""),
                "outcome": h.get("outcome", ""),
                "learnings": h.get("learnings", ""),
                "response_status": h.get("response_summary", {}).get("status", 0)
            }
            for h in recent_history
        ],
        "outcome_summary": outcomes,
        
        # IDOR candidates with FULL PROVENANCE
        "idor_candidates": [
            {
                "type": c.get("type"),
                "value": c.get("value"),
                "suggestion": c.get("pivot_suggestion"),
                "provenance": c.get("provenance")  # Full source info
            }
            for c in idor_candidates[:10]  # Limit for context size
        ],
        
        # Data provenance map (most recent entries)
        "data_provenance": dict(list(updated_provenance.items())[-15:]),
        
        # ===== REAL ENDPOINTS - LLM MUST USE THESE =====
        "real_endpoints": [
            {
                "url": e.get("url", ""),
                "method": e.get("method", "GET"),
                "params": e.get("params", []),
                "has_id_param": any("id" in p.lower() for p in e.get("params", []))
            }
            for e in real_endpoints[:20]  # Limit but ensure we have options
        ],
        
        # Request log for replay (last 10)
        "request_log": [
            {
                "id": r.get("id"),
                "method": r.get("method"),
                "url": r.get("url"),
                "timestamp": r.get("timestamp"),
                "status": r.get("response_status")
            }
            for r in request_log[-10:]
        ],
        
        # Last response metadata
        "last_response": {
            "url": last_response.get("url", ""),
            "method": last_response.get("method", ""),
            "status": last_response.get("status", 0),
            "body_size": len(last_response.get("body", "")),
            "has_json": last_response.get("content_type", "").startswith("application/json")
        } if last_response else None,
        
        # Confirmed findings
        "confirmed_vulns": len(confirmed_vulns),
        "pending_steps": len([s for s in attack_plan if s.get("status") == "pending"]),
    }
    
    # Include confirmed vulns summary
    if confirmed_vulns:
        decision_context["vulns_found"] = [
            {
                "type": v.get("type"),
                "url": v.get("url"),
                "severity": v.get("severity")
            }
            for v in confirmed_vulns[:5]
        ]
    
    # =========================================================================
    # LLM DECISION WITH PROVENANCE CONTEXT
    # =========================================================================
    
    logger.log_thought("pivoter", "🧠 Analyzing results with LLM...")
    
    messages = [
        SystemMessage(content=PIVOTER_SYSTEM_PROMPT),
        HumanMessage(content=f"""Analyze these results and decide the next action.

**CRITICAL RULES:**
1. Check `idor_detection` - if `has_idor == true`, this is a CONFIRMED IDOR vulnerability!
2. ONLY use URLs from `real_endpoints` or `request_log` - NO INVENTING URLS!
3. If IDOR confirmed, use decision="report" with should_report=true
4. For horizontal movement, find other endpoints with same parameter type

**IDOR DETECTION RESULT:**
{json.dumps(decision_context.get('idor_detection'), indent=2, default=str) if decision_context.get('idor_detection') else 'No IDOR test performed yet'}

**AVAILABLE REAL ENDPOINTS (you MUST use these):**
{json.dumps(decision_context.get('real_endpoints', []), indent=2, default=str)}

**FULL CONTEXT:**
```json
{json.dumps(decision_context, indent=2, default=str)}
```

Questions to answer:
1. Is IDOR confirmed? (check idor_detection.has_idor)
2. If yes, which other endpoints have the same parameter type? (horizontal movement)
3. What's the next logical action?
4. Are there hidden IDs in decoded tokens to exploit?

Provide decision with clear evidence-based reasoning. DO NOT invent URLs.""")
    ]
    
    try:
        response = await llm.ainvoke(messages)
        logger.log_result("pivoter", "LLM decision received")
        
        # Log full LLM response for debugging panel
        prompt_text = messages[1].content if len(messages) > 1 else ""
        logger.log_llm_response(
            node="pivoter",
            model="claude-3.5-sonnet (attack)",
            prompt=prompt_text,
            response=response.content if response.content else "",
            tokens=response.usage_metadata.get("total_tokens", 0) if hasattr(response, 'usage_metadata') and response.usage_metadata else 0,
            cost=0
        )
    except Exception as e:
        logger.log_error("pivoter", f"LLM invocation failed: {e}")
        raise
    
    # Parse decision
    try:
        response_text = response.content
        # Extract JSON from code blocks
        if "```json" in response_text:
            json_start = response_text.index("```json") + 7
            json_end = response_text.index("```", json_start)
            response_text = response_text[json_start:json_end]
        elif "```" in response_text:
            json_start = response_text.index("```") + 3
            json_end = response_text.index("```", json_start)
            response_text = response_text[json_start:json_end]
        
        response_text = response_text.strip()
        
        # Handle case where LLM returns extra text after JSON
        # Find the first complete JSON object by counting braces
        if response_text.startswith('{'):
            brace_count = 0
            json_end_pos = 0
            for i, char in enumerate(response_text):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_end_pos = i + 1
                        break
            if json_end_pos > 0:
                response_text = response_text[:json_end_pos]
        
        decision = json.loads(response_text)
    except (json.JSONDecodeError, ValueError) as e:
        logger.log_error("pivoter", f"Failed to parse LLM decision: {e}")
        # Fallback decision based on outcomes
        if outcomes.get("data_leak", 0) > 0 or outcomes.get("privilege_bypass", 0) > 0:
            decision = {
                "decision": "report",
                "action": "execute",
                "reasoning": "Critical vulnerabilities found",
                "should_report": True
            }
        elif idor_candidates:
            # Auto-generate replay action from IDOR candidates
            candidate = idor_candidates[0]
            decision = {
                "decision": "pivot",
                "action": "execute",
                "reasoning": f"Found IDOR candidate: {candidate.get('type')} = {candidate.get('value')[:20]}...",
                "next_targets": [{
                    "url": candidate.get("provenance", {}).get("source_url", ""),
                    "method": "GET",
                    "vulnerability_type": "IDOR",
                    "parameter_to_test": candidate.get("type"),
                    "test_value": candidate.get("value")
                }]
            }
        elif outcomes.get("no_finding", 0) > 3:
            decision = {
                "decision": "conclude",
                "action": "execute",
                "reasoning": "Current approach not yielding results"
            }
        else:
            decision = {
                "decision": "continue",
                "action": "execute",
                "reasoning": "More attempts needed"
            }
    
    # =========================================================================
    # PROCESS DECISION
    # =========================================================================
    
    should_continue = decision.get("decision") in ("continue", "pivot", "replay")
    action_type = decision.get("action", "execute")
    
    # Log the decision
    logger.pivoter_decision(
        decision.get("decision", "unknown"),
        decision.get("reasoning", "No reasoning provided")[:100]
    )
    
    # Build replay config if action is replay
    replay_config = None
    if action_type == "replay" and decision.get("replay_config"):
        replay_config = decision["replay_config"]
    
    # =========================================================================
    # VALIDATE NEXT TARGETS - FILTER OUT HALLUCINATED URLS
    # =========================================================================
    # Build set of valid URLs from real_endpoints and request_log
    valid_urls = set()
    
    for ep in real_endpoints:
        url = ep.get("url", "")
        if url:
            # Add both full URL and path
            valid_urls.add(url)
            # Extract path from URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.path:
                valid_urls.add(parsed.path)
    
    for req in request_log:
        url = req.get("url", "")
        if url:
            valid_urls.add(url)
            parsed = urlparse(url)
            if parsed.path:
                valid_urls.add(parsed.path)
    
    # Build new target leads - ONLY from valid URLs
    new_queue: list[TargetLead] = []
    filtered_count = 0
    
    if decision.get("next_targets"):
        for target in decision["next_targets"]:
            target_url = target.get("url", "")
            
            # Check if URL is valid
            is_valid = False
            if target_url:
                parsed_target = urlparse(target_url)
                target_path = parsed_target.path
                
                # Check against valid URLs
                if target_url in valid_urls or target_path in valid_urls:
                    is_valid = True
                else:
                    # Partial match - check if any valid URL contains this path
                    for valid_url in valid_urls:
                        if target_path and target_path in valid_url:
                            is_valid = True
                            break
            
            if is_valid:
                new_queue.append({
                    "endpoint_id": "",
                    "url": target_url,
                    "method": target.get("method", "GET"),
                    "vulnerability_type": target.get("vulnerability_type", "UNKNOWN"),
                    "pivotable_params": [target.get("parameter_to_test")] if target.get("parameter_to_test") else [],
                    "test_value": target.get("test_value"),
                    "value_provenance": target.get("value_provenance"),
                    "confidence_score": decision.get("confidence", 0.5),
                    "source": "pivoter_provenance"
                })
            else:
                filtered_count += 1
                logger.log_thought("pivoter", f"⚠️ Filtered hallucinated URL: {target_url}")
    
    if filtered_count > 0:
        logger.log_result("pivoter", f"Filtered {filtered_count} hallucinated URLs from LLM response")
    
    # If continuing, keep current queue
    if decision.get("decision") == "continue":
        new_queue = state.get("pivot_queue", [])
    
    # =========================================================================
    # HANDLE IDOR CONFIRMATION - AUTO-REPORT
    # =========================================================================
    if idor_detection_result and idor_detection_result.get("is_vulnerable"):
        # Force report if LLM missed it
        if decision.get("decision") != "report":
            logger.log_thought("pivoter", "🚨 Overriding LLM decision - IDOR detected, forcing report")
            decision["decision"] = "report"
            decision["should_report"] = True
    
    # Clear attack plan if pivoting/replaying
    updated_plan = attack_plan if decision.get("decision") == "continue" else []
    
    return {
        "iteration": iteration,
        "should_continue": should_continue or decision.get("decision") == "report",  # Continue if reporting
        "pivot_queue": new_queue,
        "attack_plan": updated_plan,
        "data_provenance": updated_provenance,
        "replay_config": replay_config,
        "action_type": action_type,
        "confirmed_vulns": confirmed_vulns,  # Return updated vulns list
        "idor_detection_result": idor_detection_result,  # Pass detection result
        "decoded_tokens": decoded_tokens,  # Pass decoded tokens for next iteration
        "reasoning_trace": state.get("reasoning_trace", []) + [
            f"[Pivoter] Decision: {decision.get('decision')} ({action_type}) - {decision.get('reasoning', 'No reason')[:100]}"
        ]
    }

    
def should_continue(state: AgentState) -> Literal["continue", "replay", "end"]:
    """
    Conditional edge function for LangGraph
    Determines if the cycle should continue and what action to take
    """
    if not state.get("should_continue", False):
        return "end"
    
    # Check if we should replay instead of normal execution
    if state.get("action_type") == "replay" and state.get("replay_config"):
        return "replay"
    
    return "continue"


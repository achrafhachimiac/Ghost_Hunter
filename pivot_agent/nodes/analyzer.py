"""
Analyzer Node
Analyzes Ghost-Hunter findings and extracts pivotable data
"""

import json
from typing import Any
from langchain_core.messages import SystemMessage, HumanMessage

from ..state import AgentState, ExtractedData, TargetLead
from ..config import get_triage_llm, GHOST_HUNTER_API_URL
from ..tools import get_client, get_extractor
from ..redis_logger import get_agent_logger


ANALYZER_SYSTEM_PROMPT = """You are an expert security researcher analyzing HTTP traffic for vulnerabilities.
Your role is to examine captured requests/responses and identify:

1. **IDOR Candidates**: IDs (numeric, UUID, encoded) that could reference other users' data
2. **Auth Bypass Opportunities**: Weak or missing authorization checks
3. **Data Leakage Patterns**: Sensitive data exposure in responses
4. **Business Logic Flaws**: Race conditions, parameter tampering, workflow bypasses

For each finding, extract:
- The exact parameter/field containing the pivotable value
- The context (what resource it accesses)
- Suggested attack vectors

Output your analysis as JSON with this structure:
{
    "targets": [
        {
            "endpoint": "URL of the endpoint",
            "method": "HTTP method",
            "vulnerability_type": "IDOR|AUTH_BYPASS|DATA_LEAK|BUSINESS_LOGIC",
            "pivotable_params": ["list of parameters to test"],
            "extracted_values": {"param_name": "current_value"},
            "attack_vectors": ["suggested attacks"],
            "confidence": "high|medium|low",
            "reasoning": "why this is vulnerable"
        }
    ],
    "sensitive_data_found": ["list of sensitive data types found"],
    "priority_target": "index of highest priority target"
}
"""


async def analyzer_node(state: AgentState) -> dict[str, Any]:
    """
    Analyzer Node - First step in the pivot cycle
    
    Responsibilities:
    1. Fetch latest findings from Ghost-Hunter
    2. Extract pivotable patterns (IDs, tokens, etc.)
    3. Use LLM to identify attack vectors
    4. Produce target leads for the strategist
    """
    
    # Get logger for live thoughts
    logger = get_agent_logger()
    logger.set_iteration(state.get("iteration", 0))
    
    # Initialize LLM via OpenRouter
    # Use Haiku (triage model) for cheap pattern extraction
    llm = get_triage_llm()
    
    extractor = get_extractor()
    
    # Log start
    logger.analyzer_start(0)  # Will update count after fetch
    
    # Fetch data from Ghost-Hunter
    async with get_client() as client:
        # Get the current target if we have one, otherwise fetch latest findings
        if state.get("target_lead") and state["target_lead"].get("endpoint_id"):
            endpoint_id = state["target_lead"]["endpoint_id"]
            logger.log_thought("analyzer", f"Fetching specific endpoint: {endpoint_id}")
            endpoint = await client.get_endpoint_by_id(endpoint_id)
            triage = await client.get_triage(endpoint_id)
            # Store endpoint directly (not wrapped) + add triage data
            if endpoint:
                endpoint["triage_result"] = triage
            findings_data = [endpoint] if endpoint else []
        else:
            # Fetch latest high-score endpoints
            logger.log_thought("analyzer", "Fetching top endpoints from Ghost-Hunter...")
            endpoints = await client.get_endpoints(status="pending")
            findings = await client.get_findings()
            findings_data = endpoints[:10]  # Top 10
        
        # Also fetch recent HTTP logs for richer context
        logs = await client.get_logs(limit=50)
        if logs:
            logger.log_thought("analyzer", f"Also retrieved {len(logs)} recent requests for context")
        
        # ===================================================================
        # FETCH ALL REAL ENDPOINTS - CRITICAL FOR NO HALLUCINATION!
        # ===================================================================
        all_endpoints = await client.get_endpoints()  # Get ALL endpoints
        real_endpoints = []
        for ep in all_endpoints:
            if isinstance(ep, dict):
                url = ep.get("example_url", "") or ep.get("url", "")
                method = ep.get("method", "GET")
                
                # Extract parameter names from URL
                params = []
                if url:
                    from urllib.parse import urlparse, parse_qs
                    parsed = urlparse(url)
                    query_params = parse_qs(parsed.query)
                    params = list(query_params.keys())
                
                if url:
                    real_endpoints.append({
                        "url": url,
                        "method": method,
                        "params": params,
                        "path": parsed.path if url else "",
                        "host": ep.get("host", ""),
                        "score": ep.get("heuristic_score", 0)
                    })
        
        logger.log_thought("analyzer", f"Loaded {len(real_endpoints)} REAL endpoints (anti-hallucination)")
    
    logger.log_thought("analyzer", f"Retrieved {len(findings_data)} endpoints for analysis")
    
    # Extract patterns from responses
    all_patterns = []
    for item in findings_data:
        if isinstance(item, dict):
            # Get URL - endpoints store in example_url, logs in url
            item_url = item.get("example_url", "") or item.get("url", "")
            
            # Extract from endpoint data
            if "example_response_body" in item:
                patterns = extractor.extract_from_response(
                    body=item.get("example_response_body", ""),
                    headers=item.get("example_response_headers", {}),
                    url=item_url
                )
                idor_candidates = extractor.find_idor_candidates(patterns)
                all_patterns.append({
                    "endpoint": item_url,
                    "method": item.get("method", "GET"),
                    "patterns": patterns.to_dict(),
                    "idor_candidates": idor_candidates,
                    "triage": item.get("triage_result", {}),
                    "score": item.get("heuristic_score", 0),
                    "potential_vulns": item.get("potential_vulns", [])
                })
                
                # Log IDOR candidates found
                if idor_candidates:
                    logger.log_thought("analyzer", 
                        f"Found {len(idor_candidates)} IDOR candidates in {item_url[:50] if item_url else 'unknown'}", 
                        {"candidates": [c["type"] for c in idor_candidates]}
                    )
    
    # Also extract from HTTP requests for additional context (URL patterns, etc.)
    log_patterns = []
    for log in logs[:20]:  # Process top 20 requests
        if isinstance(log, dict):
            # Requests may not have response_body, but we can extract URL patterns
            url = log.get("url", "")
            if url:
                log_patterns.append({
                    "url": url,
                    "method": log.get("method", "GET"),
                    "host": log.get("host", ""),
                    "score": log.get("score", 0),
                    "potential_vulns": log.get("potential_vulns", [])
                })
    
    if log_patterns:
        logger.log_thought("analyzer", f"Extracted context from {len(log_patterns)} HTTP requests")
    
    # Prepare context for LLM analysis
    analysis_context = {
        "findings_count": len(findings_data),
        "extracted_patterns": all_patterns,
        "related_requests": log_patterns[:5],  # Top 5 related requests for context
        "current_iteration": state.get("iteration", 0),
        "previous_attempts": len(state.get("history", []))
    }
    
    # If we have previous history, include learnings
    if state.get("history"):
        recent_history = state["history"][-3:]  # Last 3 attempts
        analysis_context["recent_attempts"] = [
            {
                "action": h.get("action"),
                "outcome": h.get("outcome"),
                "learnings": h.get("learnings")
            }
            for h in recent_history
        ]
    
    # LLM analysis
    logger.log_thought("analyzer", "🧠 Invoking LLM for vulnerability analysis...")
    
    messages = [
        SystemMessage(content=ANALYZER_SYSTEM_PROMPT),
        HumanMessage(content=f"""Analyze these findings for attack opportunities:

```json
{json.dumps(analysis_context, indent=2, default=str)}
```

Focus on:
1. IDOR vulnerabilities (changing IDs to access other users' data)
2. Authorization bypasses
3. Data leakage
4. Business logic flaws

Provide actionable targets with specific attack vectors.""")
    ]
    
    try:
        response = await llm.ainvoke(messages)
        logger.log_result("analyzer", "LLM analysis complete")
        
        # Log full LLM response for debugging panel
        prompt_text = messages[1].content if len(messages) > 1 else ""
        logger.log_llm_response(
            node="analyzer",
            model="claude-3.5-haiku (triage)",
            prompt=prompt_text,
            response=response.content,
            tokens=response.usage_metadata.get("total_tokens", 0) if hasattr(response, 'usage_metadata') and response.usage_metadata else 0,
            cost=0  # Cost calculated elsewhere
        )
    except Exception as e:
        logger.log_error("analyzer", f"LLM invocation failed: {e}")
        raise
    
    # Parse LLM response
    try:
        # Extract JSON from response
        response_text = response.content
        if "```json" in response_text:
            json_start = response_text.index("```json") + 7
            json_end = response_text.index("```", json_start)
            response_text = response_text[json_start:json_end]
        elif "```" in response_text:
            json_start = response_text.index("```") + 3
            json_end = response_text.index("```", json_start)
            response_text = response_text[json_start:json_end]
        
        response_text = response_text.strip()
        
        # Handle extra text after JSON by finding complete JSON object
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
        
        analysis = json.loads(response_text)
        logger.log_thought("analyzer", f"Parsed {len(analysis.get('targets', []))} targets from LLM")
    except (json.JSONDecodeError, ValueError) as e:
        logger.log_error("analyzer", f"Failed to parse LLM response: {e}")
        # Fallback: create basic analysis from extracted patterns
        analysis = {
            "targets": [],
            "sensitive_data_found": [],
            "priority_target": 0
        }
        
        # Auto-generate targets from IDOR candidates
        for pattern_data in all_patterns:
            if pattern_data["idor_candidates"]:
                analysis["targets"].append({
                    "endpoint": pattern_data["endpoint"],
                    "method": pattern_data["method"],
                    "vulnerability_type": "IDOR",
                    "pivotable_params": [c["type"] for c in pattern_data["idor_candidates"]],
                    "extracted_values": {c["type"]: c["value"] for c in pattern_data["idor_candidates"]},
                    "attack_vectors": [c.get("pivot_suggestion", "") for c in pattern_data["idor_candidates"]],
                    "confidence": "medium",
                    "reasoning": "Automatically detected pivotable IDs"
                })
    
    # Build extracted data for state
    extracted_data: ExtractedData = {
        "ids": [],
        "tokens": [],
        "user_data": {},
        "endpoints": [],
        "patterns": {}
    }
    
    for pattern_data in all_patterns:
        patterns = pattern_data.get("patterns", {})
        extracted_data["ids"].extend(patterns.get("uuids", []))
        extracted_data["ids"].extend(patterns.get("numeric_ids", []))
        extracted_data["tokens"].extend(patterns.get("jwts", []))
        extracted_data["endpoints"].append(pattern_data.get("endpoint", ""))
    
    # Dedupe
    extracted_data["ids"] = list(set(extracted_data["ids"]))
    extracted_data["tokens"] = list(set(extracted_data["tokens"]))
    extracted_data["endpoints"] = list(set(extracted_data["endpoints"]))
    
    # Build target leads from analysis
    target_leads: list[TargetLead] = []
    
    # CRITICAL: Start with the original target_lead if it exists
    # This preserves the full URL with query params!
    initial_target = state.get("target_lead", {})
    if initial_target and initial_target.get("url"):
        target_leads.append({
            "endpoint_id": initial_target.get("endpoint_id", ""),
            "url": initial_target.get("url", ""),  # Full URL with query params!
            "base_url": initial_target.get("base_url", ""),
            "query_params": initial_target.get("query_params", {}),  # Original params!
            "method": initial_target.get("method", "GET"),
            "vulnerability_type": initial_target.get("vulnerability_type", "IDOR"),
            "pivotable_params": initial_target.get("pivotable_params", []),
            "confidence_score": initial_target.get("confidence_score", 0.8),
            "source": "initial_target",
            "has_auth": initial_target.get("has_auth", False),
            "body": initial_target.get("body", ""),
            "body_json": initial_target.get("body_json", {}),
        })
        logger.log_thought("analyzer", f"Added initial target: {initial_target.get('url', '')[:60]}...")
    
    # Then add targets from LLM analysis
    for target in analysis.get("targets", []):
        # Skip if this is the same endpoint as initial target
        target_url = target.get("endpoint", "")
        if initial_target and target_url.split("?")[0] == initial_target.get("url", "").split("?")[0]:
            # Merge info but keep initial target's URL with params
            continue
        
        target_leads.append({
            "endpoint_id": "",  # Will be filled by researcher
            "url": target.get("endpoint", ""),
            "method": target.get("method", "GET"),
            "vulnerability_type": target.get("vulnerability_type", "UNKNOWN"),
            "pivotable_params": target.get("pivotable_params", []),
            "confidence_score": 0.8 if target.get("confidence") == "high" else 0.5,
            "source": "analyzer"
        })
    
    # Log results
    logger.analyzer_found_targets(target_leads)
    
    # Update state
    return {
        "extracted_data": extracted_data,
        "pivot_queue": target_leads,
        "real_endpoints": real_endpoints,  # NEW: For pivoter anti-hallucination!
        "reasoning_trace": state.get("reasoning_trace", []) + [
            f"[Analyzer] Found {len(target_leads)} potential targets from {len(findings_data)} findings. Loaded {len(real_endpoints)} real endpoints."
        ]
    }

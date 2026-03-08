"""
Strategist Node
Creates concrete attack plans from enriched targets
"""

import json
from typing import Any
from langchain_core.messages import SystemMessage, HumanMessage

from ..state import AgentState, AttackStep
from ..config import get_attack_llm
from ..redis_logger import get_agent_logger


STRATEGIST_SYSTEM_PROMPT = """You are a tactical security strategist creating attack plans.
Your role is to convert research intelligence into executable attack steps.

For each target, create a detailed attack plan with:
1. **Preconditions**: What state/tokens are needed
2. **Steps**: Exact sequence of HTTP requests with modifications
3. **Success Criteria**: How to detect if the attack worked
4. **Fallback**: What to try if the primary attack fails

Output your strategy as JSON:
{
    "attack_plan": [
        {
            "target_index": 0,
            "priority": 1,
            "steps": [
                {
                    "step_number": 1,
                    "action": "modify_request",
                    "description": "What this step does",
                    "request": {
                        "method": "GET",
                        "url": "full URL with ALL original params, only modifying the tested one",
                        "headers": {"optional": "headers"},
                        "body": "optional body"
                    },
                    "modification": {
                        "type": "parameter|header|body|path",
                        "original": "original value",
                        "modified": "new value",
                        "param_name": "parameter name"
                    },
                    "success_criteria": {
                        "status_code": [200, 201],
                        "response_contains": ["specific string"],
                        "response_differs": true
                    },
                    "stop_on_success": true
                }
            ],
            "estimated_requests": 5,
            "risk_level": "low|medium|high"
        }
    ],
    "execution_order": [0, 1, 2],
    "total_estimated_requests": 15
}

⚠️ CRITICAL - READ CAREFULLY:

1. **USE THE EXACT URL PROVIDED** - Look at the "url" field in each target. 
   It contains the FULL URL with all required query parameters.
   Example: "url": "https://example.com/api/data?subject_type=Patient&subject_id=123&role=main"
   
2. **NEVER INVENT NEW PARAMETERS** - Only use parameters that exist in the original URL.
   If the URL has ?subject_type=X&subject_id=Y&role=Z, your attacks MUST keep those params.
   
3. **FOR IDOR TESTING** - Modify ONLY the ID parameter value:
   - Original: ?subject_type=MasterPatient&subject_id=163738712&role=main
   - Test #1:  ?subject_type=MasterPatient&subject_id=163738713&role=main  (increment)
   - Test #2:  ?subject_type=MasterPatient&subject_id=1&role=main  (low ID)
   - Test #3:  ?subject_type=MasterPatient&subject_id=0&role=main  (boundary)
   
4. **400 BAD REQUEST MEANS WRONG PARAMS** - If you get 400 errors, you're missing required params.

5. Keep plans focused - 3-5 IDOR tests per endpoint is enough.
"""


async def strategist_node(state: AgentState) -> dict[str, Any]:
    """
    Strategist Node - Creates attack plans
    
    Responsibilities:
    1. Prioritize targets by confidence and impact
    2. Create step-by-step attack sequences
    3. Define success criteria for each step
    4. Plan fallback strategies
    """
    
    # Get logger for live thoughts
    logger = get_agent_logger()
    logger.set_iteration(state.get("iteration", 0))
    
    # Use Sonnet (attack model) for strategic reasoning
    llm = get_attack_llm()
    
    # Get targets and research
    targets = state.get("pivot_queue", [])
    knowledge = state.get("knowledge_base", {})
    research_results = knowledge.get("research_results", [])
    extracted_data = state.get("extracted_data", {})
    
    if not targets:
        logger.log_thought("strategist", "No targets to plan attacks for")
        return {
            "attack_plan": [],
            "reasoning_trace": state.get("reasoning_trace", []) + [
                "[Strategist] No targets to plan attacks for"
            ]
        }
    
    logger.strategist_planning(f"{len(targets)} targets")
    
    # Build strategy context
    strategy_context = {
        "targets": [],
        "available_ids": extracted_data.get("ids", [])[:10],  # Limit for context
        "available_tokens": extracted_data.get("tokens", [])[:5],
        "iteration": state.get("iteration", 0),
        "remaining_budget": state.get("max_iterations", 10) - state.get("iteration", 0)
    }
    
    for i, target in enumerate(targets[:5]):  # Limit to top 5 targets
        target_info = {
            "index": i,
            "url": target.get("url", ""),  # Full URL with query params
            "base_url": target.get("base_url", target.get("url", "").split("?")[0]),  # Path only
            "query_params": target.get("query_params", {}),  # Original query params dict
            "method": target.get("method", "GET"),
            "vulnerability_type": target.get("vulnerability_type", ""),
            "pivotable_params": target.get("pivotable_params", []),
            "confidence": target.get("confidence_score", 0.5)
        }
        
        # Add research enrichment if available
        if i < len(research_results):
            research = research_results[i]
            target_info["techniques"] = research.get("relevant_techniques", [])
            target_info["payloads"] = research.get("suggested_payloads", [])[:5]
            target_info["attack_sequence"] = research.get("attack_sequence", [])
        
        strategy_context["targets"].append(target_info)
    
    # Include history for avoiding repeated attempts
    if state.get("history"):
        failed_attempts = [
            h for h in state["history"] 
            if h.get("outcome") == "failed"
        ][-5:]  # Last 5 failures
        
        strategy_context["avoid_patterns"] = [
            {
                "action": h.get("action"),
                "reason": h.get("learnings")
            }
            for h in failed_attempts
        ]
    
    # =========================================================================
    # Build EXPLICIT original request info for the LLM
    # =========================================================================
    original_target = state.get("target_lead", {})
    original_request_info = {
        "original_url": original_target.get("url", ""),
        "original_query_params": original_target.get("query_params", {}),
        "method": original_target.get("method", "GET"),
        "note": "You MUST preserve ALL original query parameters. Only modify the one you're testing!"
    }
    strategy_context["original_request"] = original_request_info
    
    # LLM strategy generation
    logger.log_thought("strategist", "🧠 Creating attack plans with LLM...")
    logger.log_thought("strategist", f"Original URL: {original_target.get('url', 'N/A')[:80]}...")
    logger.log_thought("strategist", f"Query params: {original_target.get('query_params', {})}")
    
    messages = [
        SystemMessage(content=STRATEGIST_SYSTEM_PROMPT),
        HumanMessage(content=f"""Create attack plans for these targets:

```json
{json.dumps(strategy_context, indent=2, default=str)}
```

⚠️ CRITICAL - ORIGINAL REQUEST:
- URL: {original_target.get('url', 'UNKNOWN')}
- Query Params: {json.dumps(original_target.get('query_params', {}), indent=2)}
- You MUST include ALL these query parameters in every request!
- Only modify ONE parameter at a time for testing.

Requirements:
1. Prioritize by confidence and potential impact
2. Use available IDs/tokens where applicable
3. Keep total requests under 20 to avoid rate limiting
4. Include specific, executable request details
5. Avoid patterns that have failed before

Create concrete, executable attack plans.""")
    ]
    
    try:
        response = await llm.ainvoke(messages)
        logger.log_result("strategist", "Attack plans generated")
        
        # Log full LLM response for debugging panel
        prompt_text = messages[1].content if len(messages) > 1 else ""
        logger.log_llm_response(
            node="strategist",
            model="claude-3.5-sonnet (attack)",
            prompt=prompt_text,
            response=response.content if response.content else "",
            tokens=response.usage_metadata.get("total_tokens", 0) if hasattr(response, 'usage_metadata') and response.usage_metadata else 0,
            cost=0
        )
    except Exception as e:
        logger.log_error("strategist", f"LLM invocation failed: {e}")
        raise
    
    # Parse response
    try:
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
        
        strategy = json.loads(response_text)
        logger.log_thought("strategist", f"Created {len(strategy.get('attack_plan', []))} attack plans")
    except (json.JSONDecodeError, ValueError) as e:
        logger.log_error("strategist", f"Failed to parse LLM response: {e}")
        # Fallback: Create basic attack plan
        strategy = {"attack_plan": [], "execution_order": [], "total_estimated_requests": 0}
        
        for i, target in enumerate(targets[:3]):
            url = target.get("url", "")
            method = target.get("method", "GET")
            
            # Auto-generate IDOR test steps
            if target.get("vulnerability_type") == "IDOR":
                ids = extracted_data.get("ids", [])[:3]
                steps = []
                
                for j, test_id in enumerate(ids):
                    steps.append({
                        "step_number": j + 1,
                        "action": "modify_request",
                        "description": f"Test with ID: {test_id}",
                        "request": {
                            "method": method,
                            "url": url,  # Would need to inject ID
                            "headers": {},
                            "body": None
                        },
                        "modification": {
                            "type": "parameter",
                            "original": "unknown",
                            "modified": test_id,
                            "param_name": "id"
                        },
                        "success_criteria": {
                            "status_code": [200],
                            "response_differs": True
                        },
                        "stop_on_success": False
                    })
                
                strategy["attack_plan"].append({
                    "target_index": i,
                    "priority": i + 1,
                    "steps": steps,
                    "estimated_requests": len(steps),
                    "risk_level": "medium"
                })
                strategy["execution_order"].append(i)
                strategy["total_estimated_requests"] += len(steps)
    
    # Convert to AttackStep format
    attack_steps: list[AttackStep] = []
    
    for plan in strategy.get("attack_plan", []):
        target_idx = plan.get("target_index", 0)
        target = targets[target_idx] if target_idx < len(targets) else {}
        
        for step in plan.get("steps", []):
            attack_step: AttackStep = {
                "step_id": f"step_{len(attack_steps)}",
                "action_type": step.get("action", "modify_request"),
                "target_url": step.get("request", {}).get("url", target.get("url", "")),
                "method": step.get("request", {}).get("method", "GET"),
                "modifications": step.get("modification", {}),
                "expected_outcome": step.get("success_criteria", {}),
                "actual_outcome": None,
                "status": "pending"
            }
            attack_steps.append(attack_step)
    
    return {
        "attack_plan": attack_steps,
        "reasoning_trace": state.get("reasoning_trace", []) + [
            f"[Strategist] Created {len(attack_steps)} attack steps for {len(strategy.get('attack_plan', []))} targets"
        ]
    }

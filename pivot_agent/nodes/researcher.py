"""
Researcher Node
Enriches analysis with knowledge base (HackTricks, Nuclei templates, patterns)
"""

import json
from pathlib import Path
from typing import Any
from langchain_core.messages import SystemMessage, HumanMessage

from ..state import AgentState
from ..config import get_triage_llm, KNOWLEDGE_BASE_PATH
from ..redis_logger import get_agent_logger


RESEARCHER_SYSTEM_PROMPT = """You are a security research specialist with access to vulnerability knowledge bases.
Your role is to:

1. **Contextualize Targets**: Match identified targets with known vulnerability patterns
2. **Suggest Payloads**: Recommend specific payloads from the knowledge base
3. **Refine Attack Vectors**: Improve attack strategies based on similar vulnerabilities
4. **Identify Edge Cases**: Find bypass techniques for common protections

Available knowledge sources:
- HackTricks methodology
- Nuclei templates
- Custom patterns for IDOR, auth bypass, business logic
- Payload dictionaries

Output your research as JSON:
{
    "enriched_targets": [
        {
            "original_target": "target reference",
            "relevant_techniques": ["technique names"],
            "suggested_payloads": ["payload1", "payload2"],
            "bypass_methods": ["if auth/WAF present"],
            "reference_vulns": ["similar CVEs or reports"],
            "attack_sequence": ["step1", "step2", "step3"]
        }
    ],
    "knowledge_applied": ["list of KB articles used"],
    "confidence_adjustments": {"target_index": "new_confidence_reason"}
}
"""


class KnowledgeBase:
    """Simple knowledge base accessor for patterns and payloads"""
    
    def __init__(self, base_path: str = KNOWLEDGE_BASE_PATH):
        self.base_path = Path(base_path)
        self._cache = {}
    
    def load_patterns(self, category: str) -> dict[str, Any]:
        """Load patterns for a vulnerability category"""
        if category in self._cache:
            return self._cache[category]
        
        pattern_file = self.base_path / "patterns" / f"{category}.yaml"
        if pattern_file.exists():
            import yaml
            with open(pattern_file) as f:
                self._cache[category] = yaml.safe_load(f)
                return self._cache[category]
        
        return {}
    
    def get_idor_patterns(self) -> dict[str, Any]:
        """Get IDOR-specific patterns and payloads"""
        patterns = self.load_patterns("idor")
        if not patterns:
            # Default IDOR patterns
            patterns = {
                "id_manipulation": [
                    {"type": "increment", "description": "Try ID + 1"},
                    {"type": "decrement", "description": "Try ID - 1"},
                    {"type": "zero", "description": "Try ID = 0"},
                    {"type": "negative", "description": "Try ID = -1"},
                    {"type": "large", "description": "Try very large ID"},
                    {"type": "uuid_variation", "description": "Change UUID bytes"},
                ],
                "bypass_techniques": [
                    "Add .json extension",
                    "Change Accept header",
                    "Use array notation: id[]=1",
                    "HTTP method override",
                    "Case variation in path",
                    "Double URL encoding",
                ],
                "detection_indicators": [
                    "Different user data returned",
                    "200 OK with modified ID",
                    "Response size differs significantly",
                    "New fields appear in response",
                ]
            }
        return patterns
    
    def get_auth_bypass_patterns(self) -> dict[str, Any]:
        """Get authentication bypass patterns"""
        patterns = self.load_patterns("authentication")
        if not patterns:
            patterns = {
                "header_manipulation": [
                    {"header": "X-Original-URL", "value": "/admin"},
                    {"header": "X-Rewrite-URL", "value": "/admin"},
                    {"header": "X-Forwarded-For", "value": "127.0.0.1"},
                    {"header": "X-Custom-IP-Authorization", "value": "127.0.0.1"},
                ],
                "method_override": [
                    "X-HTTP-Method-Override: PUT",
                    "X-HTTP-Method: DELETE",
                    "X-Method-Override: PATCH",
                ],
                "path_traversal": [
                    "/api/v1/admin/../user/1",
                    "/api/v1/user/1/../../admin",
                    "/%2e%2e/admin",
                ],
            }
        return patterns
    
    def get_business_logic_patterns(self) -> dict[str, Any]:
        """Get business logic vulnerability patterns"""
        patterns = self.load_patterns("business_logic")
        if not patterns:
            patterns = {
                "race_conditions": [
                    "Parallel requests for same action",
                    "Time-of-check vs time-of-use",
                    "Double spending/booking",
                ],
                "parameter_tampering": [
                    "Price manipulation",
                    "Quantity to negative",
                    "Role/status change",
                    "Discount code reuse",
                ],
                "workflow_bypass": [
                    "Skip verification steps",
                    "Direct access to final step",
                    "State manipulation",
                ],
            }
        return patterns
    
    def search_nuclei_templates(self, vulnerability_type: str) -> list[dict[str, Any]]:
        """Search for relevant Nuclei templates"""
        templates = []
        nuclei_path = self.base_path / "nuclei-templates"
        
        # Search in relevant directories
        search_dirs = ["http", "dast", "workflows"]
        keywords = vulnerability_type.lower().split("_")
        
        for dir_name in search_dirs:
            dir_path = nuclei_path / dir_name
            if dir_path.exists():
                for template_file in dir_path.rglob("*.yaml"):
                    # Simple keyword matching
                    if any(kw in template_file.name.lower() for kw in keywords):
                        templates.append({
                            "name": template_file.stem,
                            "path": str(template_file.relative_to(nuclei_path)),
                            "category": dir_name
                        })
                        if len(templates) >= 5:  # Limit results
                            break
        
        return templates


async def researcher_node(state: AgentState) -> dict[str, Any]:
    """
    Researcher Node - Enriches targets with knowledge base
    
    Responsibilities:
    1. Load relevant patterns from knowledge base
    2. Match targets with known vulnerability patterns
    3. Suggest specific payloads and techniques
    4. Refine attack strategies
    """
    
    # Get logger for live thoughts
    logger = get_agent_logger()
    logger.set_iteration(state.get("iteration", 0))
    
    # Initialize
    # Use Haiku (triage model) for cheap KB enrichment
    llm = get_triage_llm()
    
    kb = KnowledgeBase()
    
    # Get targets from analyzer
    targets = state.get("pivot_queue", [])
    if not targets:
        logger.log_thought("researcher", "No targets to research")
        return {
            "reasoning_trace": state.get("reasoning_trace", []) + [
                "[Researcher] No targets to research"
            ]
        }
    
    logger.researcher_enriching(f"{len(targets)} targets")
    
    # Load relevant knowledge based on vulnerability types
    knowledge_context = {}
    vuln_types = set(t.get("vulnerability_type", "").upper() for t in targets)
    
    if "IDOR" in vuln_types or any("id" in str(t.get("pivotable_params", [])).lower() for t in targets):
        knowledge_context["idor"] = kb.get_idor_patterns()
        logger.log_thought("researcher", "Loading IDOR patterns from knowledge base")
    
    if "AUTH_BYPASS" in vuln_types or "AUTH" in vuln_types:
        knowledge_context["auth"] = kb.get_auth_bypass_patterns()
        logger.log_thought("researcher", "Loading auth bypass patterns")
    
    if "BUSINESS_LOGIC" in vuln_types:
        knowledge_context["business_logic"] = kb.get_business_logic_patterns()
        logger.log_thought("researcher", "Loading business logic patterns")
    
    # Search for relevant Nuclei templates
    nuclei_templates = []
    for vuln_type in vuln_types:
        templates = kb.search_nuclei_templates(vuln_type)
        nuclei_templates.extend(templates)
    
    if nuclei_templates:
        knowledge_context["nuclei_templates"] = nuclei_templates[:10]
        logger.log_thought("researcher", f"Found {len(nuclei_templates)} relevant Nuclei templates")
    
    # Prepare research context
    research_context = {
        "targets": [
            {
                "index": i,
                "url": t.get("url", ""),
                "method": t.get("method", "GET"),
                "vulnerability_type": t.get("vulnerability_type", ""),
                "pivotable_params": t.get("pivotable_params", []),
                "confidence": t.get("confidence_score", 0.5)
            }
            for i, t in enumerate(targets)
        ],
        "knowledge_base": knowledge_context,
        "previous_findings": state.get("confirmed_vulns", [])
    }
    
    # LLM enrichment
    logger.log_thought("researcher", "🧠 Invoking LLM for target enrichment...")
    
    messages = [
        SystemMessage(content=RESEARCHER_SYSTEM_PROMPT),
        HumanMessage(content=f"""Research these targets and enrich with attack strategies:

```json
{json.dumps(research_context, indent=2, default=str)}
```

For each target:
1. Match with relevant patterns from the knowledge base
2. Suggest specific payloads to try
3. Identify potential bypass techniques
4. Provide a step-by-step attack sequence

Focus on practical, immediately actionable intelligence.""")
    ]
    
    try:
        response = await llm.ainvoke(messages)
        logger.log_result("researcher", "LLM enrichment complete")
        
        # Log full LLM response for debugging panel
        prompt_text = messages[1].content if len(messages) > 1 else ""
        logger.log_llm_response(
            node="researcher",
            model="claude-3.5-haiku (triage)",
            prompt=prompt_text,
            response=response.content if response.content else "",
            tokens=response.usage_metadata.get("total_tokens", 0) if hasattr(response, 'usage_metadata') and response.usage_metadata else 0,
            cost=0
        )
    except Exception as e:
        logger.log_error("researcher", f"LLM invocation failed: {e}")
        raise
    
    # Parse response
    try:
        response_text = response.content if response.content else ""
        
        # Check for empty response
        if not response_text.strip():
            raise ValueError("Empty LLM response")
        
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
        
        if not response_text:
            raise ValueError("No JSON found in response")
        
        research_results = json.loads(response_text)
        logger.log_thought("researcher", f"Enriched {len(research_results.get('enriched_targets', []))} targets")
    except (json.JSONDecodeError, ValueError) as e:
        logger.log_error("researcher", f"Failed to parse LLM response: {e}")
        # Fallback: use knowledge base directly
        research_results = {
            "enriched_targets": [],
            "knowledge_applied": list(knowledge_context.keys()),
            "confidence_adjustments": {}
        }
        
        for i, target in enumerate(targets):
            vuln_type = target.get("vulnerability_type", "").upper()
            enriched = {
                "original_target": i,
                "relevant_techniques": [],
                "suggested_payloads": [],
                "bypass_methods": [],
                "reference_vulns": [],
                "attack_sequence": []
            }
            
            if vuln_type == "IDOR" and "idor" in knowledge_context:
                idor_patterns = knowledge_context["idor"]
                enriched["relevant_techniques"] = [
                    m["type"] for m in idor_patterns.get("id_manipulation", [])
                ]
                enriched["bypass_methods"] = idor_patterns.get("bypass_techniques", [])[:3]
                enriched["attack_sequence"] = [
                    "1. Capture original request with valid ID",
                    "2. Identify ID format (numeric, UUID, etc.)",
                    "3. Generate variations (increment, decrement, etc.)",
                    "4. Send modified requests",
                    "5. Compare responses for data differences"
                ]
            
            research_results["enriched_targets"].append(enriched)
    
    # Update knowledge base in state
    updated_kb = state.get("knowledge_base", {})
    updated_kb.update({
        "patterns": knowledge_context,
        "nuclei_templates": nuclei_templates,
        "research_results": research_results.get("enriched_targets", [])
    })
    
    return {
        "knowledge_base": updated_kb,
        "reasoning_trace": state.get("reasoning_trace", []) + [
            f"[Researcher] Enriched {len(targets)} targets with {len(knowledge_context)} knowledge categories"
        ]
    }

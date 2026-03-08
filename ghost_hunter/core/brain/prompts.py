"""
Ghost-Hunter System Prompts
===========================
Prompts système pour les différentes IA.
Enrichis avec la Knowledge Base (HackTricks, PayloadsAllTheThings).
"""

from typing import Optional, List

TRIAGE_SYSTEM_PROMPT = """You are Ghost-Hunter Triage (Tier 2), an expert security analyst who identifies REAL attack vectors, not just alerts.

## Your Role
1. Filter False Positives - Don't waste time on generic errors
2. Expand Attack Surface - Even if the initial alert is a FP, the request may have valuable parameters

## RULE 1: FALSE POSITIVE DETECTION
Identify common FP patterns:
- Generic 500 errors without SQL-specific messages
- Rate limiting (429) mistaken for vulnerabilities
- Normal input validation errors
- Cookie/session errors

## RULE 2: ATTACK SURFACE EXPANSION (Critical!)
Scan Body + Query Params for sensitive keywords:

| Pattern | Vulnerability | Keywords |
|---------|---------------|----------|
| **IDOR/BOLA** | Access other users' data | user_id, account_id, org_id, patient_id, doctor_id, uuid, profile_ref, owner_id |
| **Mass Assignment** | Privilege escalation | role, is_admin, is_staff, groups, permissions, plan, status, verified |
| **SSRF/Open Redirect** | Internal access | url, callback, webhook, return_to, redirect_uri, next, image_url, file_path |
| **Injection** | SQLi/Command | query, filter, sort, search, cmd, exec, file, path, template |
| **XXE** | XML parsing attack | (XML body detected) |

## Output Format
Respond ONLY with valid JSON:
```json
{
  "interesting": true/false,
  "confidence": 0-100,
  "reason": "Brief explanation",
  "false_positive_reason": "Why initial alert is FP (or null)",
  "suggested_vulns": ["IDOR", "SQLi", ...],
  "attack_surface_hints": [
    "IDOR potential on 'patient_id' - test cross-account access",
    "Mass Assignment on 'status' - test privilege values"
  ],
  "test_phase": "safe/medium/risky",
  "priority": "critical/high/medium/low"
}
```

## Rules
- ALWAYS scan body/params even if main alert is FP
- Pivot: "Not SQLi, BUT might be IDOR"
- attack_surface_hints go directly to Strategist
- Be specific: include the parameter name and suggested test
"""

STRATEGIST_SYSTEM_PROMPT = """<persona>
You are a vulnerability researcher specialized in edge-case parsing bugs, protocol desynchronization, and authorization bypass techniques. You hunt for vulnerabilities that automated scanners miss.
</persona>

<mission>
Analyze the intercepted request and design an exploitation strategy that exploits logic flaws and technical vulnerabilities invisible to WAFs.
</mission>

<analysis_framework>
Before generating payloads, perform internal Chain-of-Thought analysis:
1. **Behavioral Mapping**: How does the backend likely process this input? (Type casting, ORM query, direct DB access?)
2. **Security Impediment**: What defenses are in place? How can they be bypassed using techniques they don't monitor?
3. **Contextual Pivot**: Based on the application domain, what related objects (IDs, roles, resources) could be accessed?
4. **Parser Differential**: How might the WAF parse the request differently from the backend?
</analysis_framework>

<waf_evasion_grammar>
Apply these techniques based on detected WAF:
- **Cloudflare**: Unicode normalization (\\u0027), HPP (id=1&id=2), JSON interop ({"id":1,"id":2}), chunked encoding
- **AWS WAF**: Case variation (SeLeCt), comment injection (SEL/**/ECT), parameter fragmentation
- **Akamai**: Junk data padding, double URL encoding, null byte injection (%00)
- **ModSecurity**: Protocol-level bypass, multipart boundary manipulation, HTTP/2 downgrade
- **Generic**: Type juggling ("123" vs 123 vs [123]), array wrapping, negative values, boundary values
</waf_evasion_grammar>

<output_format>
Respond with JSON only (no markdown). Include your reasoning BEFORE payloads:
{
  "analysis": {
    "behavioral_mapping": "How backend processes input",
    "security_impediment": "Defenses and bypass strategy", 
    "contextual_pivot": "Related attackable objects",
    "parser_differential": "WAF vs backend parsing differences"
  },
  "vuln_class": "IDOR|SQLi|XSS|SSRF|...",
  "tool": "custom",
  "reasoning": "Summary of attack rationale",
  "injection_points": ["param1", "param2"],
  "payloads": [{"payload": "value", "encoding": "none|url|base64|unicode", "technique": "description"}],
  "test_sequence": [{"order": 1, "action": "send_request", "description": "...", "expected_indicators": [...]}],
  "baseline_needed": true,
  "max_requests": 10,
  "delay_between_ms": 1000,
  "success_indicators": ["indicator1", "indicator2"],
  "evasion_techniques": []
}
</output_format>

<rules>
- payloads.payload = INJECTION VALUE only (replaces value at injection_point)
- **CRITICAL: Generate between 15-30 payloads MAXIMUM** - quality over quantity, we have a hard limit of 30 payloads per execution
- **HARD LIMIT: 30 payloads MAX** - exceeding this will cause rate limiting errors
- Generate payloads NOT in standard wordlists - exploit edge cases
- Consider: HPP, JSON interoperability, prototype pollution, type juggling
- For IDOR: test horizontal (other users), vertical (admin), and diagonal (cross-tenant) access
- **CRITICAL: injection_points MUST be body params, query params, or path placeholders ONLY**
- **NEVER use cookie names as injection_points** (cookies like _cfuvid, altid, JSESSIONID are session/tracking - NOT IDOR targets)
- For form-encoded bodies with array notation (e.g., items[][id]=123), use the EXACT field name as injection_point
- Vary payload techniques: type juggling, boundary values, negative IDs, UUID manipulation, encoding variations
</rules>
"""

ANALYSIS_SYSTEM_PROMPT = """You are Ghost-Hunter Analyst, an expert at interpreting security test results.

## Your Role
Analyze the response from a security test and determine if a vulnerability was confirmed.

## Output Format
Respond ONLY with valid JSON:
```json
{
  "vulnerability_confirmed": true/false,
  "confidence": 0-100,
  "vuln_type": "IDOR|SQLi|XSS|...",
  "severity": "critical|high|medium|low|info",
  "evidence": "What proves the vuln",
  "impact": "What an attacker could do",
  "reproduction_steps": ["Step 1", "Step 2"],
  "recommendations": ["Fix 1", "Fix 2"],
  "chain_potential": ["Other vulns this enables"],
  "false_positive_indicators": ["Why it might be FP"]
}
```

## Rules
- Be conservative - require solid evidence
- Consider false positive indicators
- Assess real-world impact
- Suggest verification steps if uncertain
"""


def get_triage_prompt(
    request_data: dict, 
    knowledge_context: Optional[str] = None,
    security_context: Optional[dict] = None
) -> str:
    """Génère le prompt utilisateur pour le triage."""
    body = request_data.get('body')
    body_display = body[:500] if body else "None"
    
    # Extract domain for target context
    url = request_data.get('url', '')
    host = request_data.get('host', '')
    
    # Detect target platform from domain
    target_context = _detect_target_context(host)
    
    base_prompt = f"""Analyze this HTTP request for security testing potential:

**Method:** {request_data.get('method', 'GET')}
**URL:** {request_data.get('url', '')}
**Path:** {request_data.get('path', '')}

**Query Parameters:**
{_format_dict(request_data.get('query_params', {}))}

**Headers:**
{_format_dict(request_data.get('headers', {}), sensitive=True)}

**Body:**
{body_display}"""

    # Add target context (healthcare, fintech, etc.)
    if target_context:
        base_prompt += f"""

**🎯 Target Context:**
{target_context}"""

    # Add heuristic signals with BREAKDOWN
    score_breakdown = request_data.get('score_breakdown', '')
    base_prompt += f"""

**Heuristic Signals:**
- Score: {request_data.get('score', 0)}
- Score Breakdown:
{score_breakdown if score_breakdown else '  (no breakdown available)'}
- Interesting Params: {request_data.get('interesting_params', [])}
- Potential Vulns: {request_data.get('potential_vulns', [])}"""

    # Ajouter le contexte Security Profile si disponible
    if security_context:
        base_prompt += f"""

**🛡️ Target Security Profile:**
- WAF: {security_context.get('waf', 'None detected')} {f"({security_context.get('waf_confidence', 0)}% confidence)" if security_context.get('waf') else ''}
- CDN: {security_context.get('cdn', 'None detected')}
- Anti-Bot: {security_context.get('anti_bot', 'None detected')}
- Rate Limiting: {'Detected' if security_context.get('rate_limiting') else 'Not detected'}
- Backend: {security_context.get('backend', 'Unknown')}
- Frontend: {security_context.get('frontend', 'Unknown')}
- Security Headers: {security_context.get('security_headers_count', 0)}/{security_context.get('security_headers_total', 6)}
- Recommended Evasion: {', '.join(security_context.get('evasion_techniques', [])) or 'None'}"""
    
    # Ajouter le contexte Knowledge si disponible
    if knowledge_context:
        base_prompt += f"\n{knowledge_context}"
    
    base_prompt += "\n\nIs this request worth deeper security testing? Consider the security profile when assessing difficulty."
    
    return base_prompt


def _detect_target_context(host: str) -> str:
    """Load target context from scope.json config."""
    try:
        import json
        from pathlib import Path
        
        # Try multiple paths
        config_paths = [
            Path("config/scope.json"),
            Path(__file__).parent.parent.parent.parent / "config" / "scope.json",
        ]
        
        for config_path in config_paths:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    scope = json.load(f)
                
                target = scope.get('target', {})
                target_name = target.get('name', 'Unknown Target')
                notes = scope.get('notes', '')
                
                # Build context from scope config
                context_lines = [f"- Target Program: {target_name}"]
                
                if notes:
                    context_lines.append(f"- Description: {notes}")
                
                # Auto-detect data sensitivity from keywords in name/notes
                combined = f"{target_name} {notes}".lower()
                
                if any(kw in combined for kw in ['health', 'medical', 'patient', 'doctor', 'pharma', 'hospital', 'clinic', 'santé', 'médic', 'medic', 'appointment', 'rendez-vous']):
                    context_lines.append("- Data Sensitivity: CRITICAL (healthcare/medical data)")
                    context_lines.append("- Regulatory: GDPR, HDS, HIPAA-like")
                    context_lines.append("- Priority Focus: IDOR on patient/doctor IDs, medical data leaks")
                elif any(kw in combined for kw in ['bank', 'payment', 'finance', 'money', 'crypto', 'trading', 'wallet', 'paiement', 'banque']):
                    context_lines.append("- Data Sensitivity: CRITICAL (financial data)")
                    context_lines.append("- Regulatory: PCI-DSS, PSD2, GDPR")
                    context_lines.append("- Priority Focus: IDOR on transactions, payment bypass")
                elif any(kw in combined for kw in ['shop', 'store', 'commerce', 'retail', 'order']):
                    context_lines.append("- Data Sensitivity: HIGH (orders, payment info)")
                    context_lines.append("- Priority Focus: Price manipulation, coupon abuse, order IDOR")
                else:
                    context_lines.append("- Data Sensitivity: MEDIUM-HIGH")
                    context_lines.append("- Priority Focus: IDOR, privilege escalation, data leaks")
                
                return "\n".join(context_lines)
        
        return ""
    except Exception:
        return ""


def get_strategy_prompt(
    request_data: dict, 
    triage_result: dict,
    knowledge_context: Optional[str] = None,
    payloads: Optional[List[str]] = None,
    security_context: Optional[dict] = None
) -> str:
    """Génère le prompt utilisateur pour la stratégie - enrichi avec RAG et XML tags."""
    body = request_data.get('body')
    body_display = body[:1000] if body else "None"
    
    # === SECTION 1: RAG KNOWLEDGE CONTEXT ===
    rag_section = ""
    if knowledge_context:
        rag_section = f"""<knowledge>
{knowledge_context}
</knowledge>
"""
    
    # === SECTION 2: SECURITY PROFILE WITH WAF GRAMMAR ===
    security_section = ""
    if security_context:
        waf = security_context.get('waf', 'None detected')
        waf_conf = security_context.get('waf_confidence', 0)
        cdn = security_context.get('cdn', 'None detected')
        anti_bot = security_context.get('anti_bot', 'None detected')
        rate_limit = security_context.get('rate_limiting', False)
        evasion = security_context.get('evasion_techniques', [])
        
        # WAF-specific attack hints
        waf_hints = ""
        if waf and waf != 'None detected':
            waf_lower = waf.lower()
            if 'cloudflare' in waf_lower:
                waf_hints = "→ Cloudflare: Use Unicode (\\\\u0027), HPP, JSON interop, chunked transfer"
            elif 'aws' in waf_lower:
                waf_hints = "→ AWS WAF: Use case variation, comment injection, param fragmentation"
            elif 'akamai' in waf_lower:
                waf_hints = "→ Akamai: Use junk padding, double encoding, null bytes"
            elif 'imperva' in waf_lower or 'incapsula' in waf_lower:
                waf_hints = "→ Imperva: Use HTTP/2, multipart abuse, protocol confusion"
        
        security_section = f"""<security_profile>
- WAF: {waf} ({waf_conf}% confidence)
- CDN: {cdn}
- Anti-Bot: {anti_bot}
- Rate Limiting: {'⚠️ ACTIVE' if rate_limit else 'Not detected'}
{waf_hints}
</security_profile>
"""
    
    # === SECTION 3: TARGET CONTEXT (domain-specific hints) ===
    target_hints = _get_domain_attack_hints(request_data.get('host', ''), request_data.get('path', ''))
    target_section = ""
    if target_hints:
        target_section = f"""<domain_context>
{target_hints}
</domain_context>
"""
    
    # === SECTION 4: REQUEST DETAILS ===
    base_prompt = f"""{rag_section}{security_section}{target_section}<request>
Method: {request_data.get('method', 'GET')}
Path: {request_data.get('path', '')}
Host: {request_data.get('host', '')}
Content-Type: {request_data.get('content_type', 'N/A')}

Query Parameters: {request_data.get('query_params', {}) or 'None'}

Body:
{body_display}
</request>

<triage_result>
Suggested Vulnerabilities: {triage_result.get('suggested_vulns', [])}
Confidence: {triage_result.get('confidence', 0)}%
Reason: {triage_result.get('reason', '')}
Attack Hints: {triage_result.get('attack_surface_hints', []) or 'Analyze request yourself'}
</triage_result>

<task>
Design an attack plan for: {', '.join(triage_result.get('suggested_vulns', ['general']))}

Focus on edge cases and techniques that bypass standard defenses.
Include your Chain-of-Thought analysis in the "analysis" field before payloads.
</task>"""
    
    return base_prompt


def _get_domain_attack_hints(host: str, path: str) -> str:
    """Generate domain-specific attack hints based on target type."""
    hints = []
    combined = f"{host} {path}".lower()
    
    # Healthcare
    if any(kw in combined for kw in ['health', 'medical', 'patient', 'doctor', 'clinic', 'hospital', 'appointment', 'practitioner']):
        hints.append("Healthcare platform detected:")
        hints.append("- IDOR targets: patient_id, doctor_id, practitioner_id, appointment_id, consultation_id")
        hints.append("- Cross-reference: Can patient access doctor's private notes? Can doctor A see doctor B's patients?")
        hints.append("- Sensitive data: medical records, prescriptions, insurance info")
        hints.append("- Regulatory impact: HIPAA/GDPR violations = critical severity")
    
    # Finance
    elif any(kw in combined for kw in ['bank', 'payment', 'finance', 'transaction', 'wallet', 'transfer', 'account']):
        hints.append("Financial platform detected:")
        hints.append("- IDOR targets: account_id, transaction_id, beneficiary_id, statement_id")
        hints.append("- Race conditions: double-spend, concurrent transfers")
        hints.append("- Amount manipulation: negative values, float precision attacks")
        hints.append("- PCI-DSS scope: card data exposure = critical")
    
    # E-commerce
    elif any(kw in combined for kw in ['shop', 'store', 'cart', 'order', 'product', 'checkout', 'price']):
        hints.append("E-commerce platform detected:")
        hints.append("- IDOR targets: order_id, cart_id, user_address_id, coupon_id")
        hints.append("- Price manipulation: modify quantity/price in cart, coupon stacking")
        hints.append("- Business logic: skip payment step, reuse one-time codes")
    
    # API patterns
    if '/api/' in combined or '/v1/' in combined or '/v2/' in combined:
        hints.append("API endpoint patterns:")
        hints.append("- Test GraphQL introspection if /graphql present")
        hints.append("- Check for mass assignment on PUT/PATCH requests")
        hints.append("- Look for debug/internal endpoints (_debug, _internal, /admin)")
    
    return "\n".join(hints) if hints else ""


def get_analysis_prompt(request_data: dict, response_data: dict, attack_plan: dict) -> str:
    """Génère le prompt utilisateur pour l'analyse."""
    return f"""Analyze this security test result:

**Original Request:**
- Method: {request_data.get('method', 'GET')}
- URL: {request_data.get('url', '')}
- Payload Used: {attack_plan.get('payload_used', 'N/A')}

**Test Type:** {attack_plan.get('vuln_class', 'Unknown')}

**Response:**
- Status Code: {response_data.get('status_code', 'N/A')}
- Response Time: {response_data.get('response_time_ms', 'N/A')}ms
- Body Length: {response_data.get('body_length', 'N/A')} bytes

**Response Body (truncated):**
{response_data.get('body', '')[:1000]}

**Baseline Comparison:**
- Status Changed: {response_data.get('status_changed', False)}
- Body Changed: {response_data.get('body_changed', False)}
- Timing Anomaly: {response_data.get('timing_anomaly', False)}

**Expected Success Indicators:**
{attack_plan.get('success_indicators', ['N/A'])}

Was the vulnerability confirmed?"""


def _format_dict(d: dict, sensitive: bool = False) -> str:
    """Formate un dict pour l'affichage - NO REDACTION."""
    if not d:
        return "None"
    
    lines = []
    for key, value in d.items():
        # Truncate very long values for readability but keep full auth/cookies
        val_str = str(value)
        if len(val_str) > 500 and key.lower() not in ['authorization', 'cookie', 'x-api-key']:
            val_str = val_str[:500] + "..."
        lines.append(f"  - {key}: {val_str}")
    
    return "\n".join(lines)

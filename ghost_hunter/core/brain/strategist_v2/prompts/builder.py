"""
Builder pour les prompts cumulatifs du Strategist V2.

Construit le prompt de Round N en agrégeant le contexte original,
les résultats des rounds précédents et le contexte RAG.
~250 lignes max selon les règles du projet.
"""

from typing import List, Optional
from ..contracts import (
    OriginalContext,
    RoundResult,
    CumulativeKnowledge,
)
from .formatters import (
    format_headers,
    format_body,
    format_test,
    format_list,
    format_encoding_stats,
    format_security_profile,
    format_round_summary,
)


def build_round_n_prompt(
    round_number: int,
    original_context: OriginalContext,
    previous_rounds: List[RoundResult],
    cumulative_knowledge: CumulativeKnowledge,
    rag_context: Optional[str] = None,
    num_payloads: int = 5,
) -> str:
    """
    Construit le prompt cumulatif pour le Round N.
    
    Args:
        round_number: Numéro du round à générer (2+)
        original_context: Contexte original de la requête
        previous_rounds: Résultats des rounds précédents
        cumulative_knowledge: Connaissance agrégée
        rag_context: Contexte RAG (techniques de bypass)
        num_payloads: Nombre de payloads à demander
        
    Returns:
        Prompt complet formaté en markdown
    """
    sections = []
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 1: CONTEXT ORIGINAL
    # ═══════════════════════════════════════════════════════════════
    sections.append(_build_original_context_section(original_context))
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 2: PREVIOUS ROUNDS (si > Round 1)
    # ═══════════════════════════════════════════════════════════════
    if previous_rounds:
        sections.append(_build_previous_rounds_section(previous_rounds))
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 3: RAG CONTEXT
    # ═══════════════════════════════════════════════════════════════
    if rag_context:
        sections.append(_build_rag_section(rag_context))
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 4: CUMULATIVE KNOWLEDGE (Round 2+)
    # ═══════════════════════════════════════════════════════════════
    if round_number > 1:
        sections.append(_build_cumulative_section(
            round_number, cumulative_knowledge
        ))
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 5: TASK
    # ═══════════════════════════════════════════════════════════════
    sections.append(_build_task_section(round_number, num_payloads))
    
    return "\n\n".join(sections)


def _build_original_context_section(ctx: OriginalContext) -> str:
    """Construit la section du contexte original."""
    # Extraire les injection points détectés
    injection_points = _extract_injection_points(ctx)
    
    return f"""# ORIGINAL CONTEXT

## Target Endpoint

| Field | Value |
|-------|-------|
| Method | `{ctx.method}` |
| URL | `{ctx.url}` |
| Vulnerability Class | **{ctx.vuln_class}** |
| Confidence | {ctx.confidence}% |

### 🎯 INJECTION POINTS DETECTED

{_format_injection_points(injection_points)}

### Headers

{format_headers(ctx.headers)}

### Body

{format_body(ctx.body)}

### Triage Assessment

{ctx.triage_reasoning}

### Interesting Parameters

{format_list(ctx.interesting_params)}

### Security Profile

{format_security_profile(ctx.security_profile)}"""


def _extract_injection_points(ctx: OriginalContext) -> dict:
    """
    Extrait tous les points d'injection possibles du contexte.
    Returns: {"url_path": [...], "query_param": [...], "body": [...], "header": [...]}
    """
    import re
    from urllib.parse import urlparse, parse_qs
    
    points = {
        "url_path": [],
        "query_param": [],
        "body": [],
        "header": []
    }
    
    # 1. URL PATH - Extraire les IDs
    parsed = urlparse(ctx.url)
    path_parts = parsed.path.split('/')
    for part in path_parts:
        if not part:
            continue
        # Letter-prefixed account format: u + digits
        if re.match(r'^[uU]\d{6,}$', part):
            points["url_path"].append(part)
        # Numeric IDs (4+ digits)
        elif re.match(r'^\d{4,}$', part):
            points["url_path"].append(part)
        # UUID
        elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', part, re.IGNORECASE):
            points["url_path"].append(part)
        # Short hash/ID (8-32 hex)
        elif re.match(r'^[a-f0-9]{8,32}$', part, re.IGNORECASE) and not re.match(r'^[a-z]+$', part):
            points["url_path"].append(part)
    
    # 2. QUERY PARAMS
    query_params = parse_qs(parsed.query)
    for param in query_params.keys():
        points["query_param"].append(param)
    
    # 3. BODY FIELDS - from interesting_params
    for param in ctx.interesting_params or []:
        if param.startswith("path:"):
            # Already extracted as path ID
            continue
        points["body"].append(param)
    
    # 4. Parse body JSON keys if available
    if ctx.body:
        try:
            import json
            body_json = json.loads(ctx.body)
            if isinstance(body_json, dict):
                for key in body_json.keys():
                    if key not in points["body"]:
                        points["body"].append(key)
        except:
            pass
    
    return points


def _format_injection_points(points: dict) -> str:
    """Formate les injection points pour le prompt."""
    lines = []
    
    if points["url_path"]:
        lines.append("**URL Path IDs (IDOR priority!):**")
        for p in points["url_path"]:
            lines.append(f"- `url_path:{p}` → Try incrementing/decrementing this ID!")
    
    if points["query_param"]:
        lines.append("\n**Query Parameters:**")
        for p in points["query_param"]:
            lines.append(f"- `query_param:{p}`")
    
    if points["body"]:
        lines.append("\n**Body Fields:**")
        for p in points["body"]:
            lines.append(f"- `body:{p}`")
    
    if not any(points.values()):
        return "_No obvious injection points detected - analyze URL and body manually_"
    
    return "\n".join(lines)


def _build_previous_rounds_section(rounds: List[RoundResult]) -> str:
    """Construit la section des rounds précédents."""
    sections = ["# PREVIOUS ROUNDS"]
    
    for round_result in rounds:
        round_num = round_result.round_number
        
        # Plan du round
        sections.append(f"""
## ROUND {round_num} STRATEGY

**Vulnerability Class:** {round_result.plan.vuln_class}
**Reasoning:** {round_result.plan.reasoning}
**Bypass Techniques:** {', '.join(round_result.plan.bypass_techniques) or 'None'}
""")
        
        # Résultats détaillés
        sections.append(f"## ROUND {round_num} RESULTS")
        
        for i, test in enumerate(round_result.tests, 1):
            sections.append(format_test(test, i))
        
        # Summary du round
        sections.append(format_round_summary(
            round_num,
            round_result.blocked_count,
            round_result.passed_count,
            round_result.interesting_count,
            len(round_result.tests)
        ))
    
    return "\n".join(sections)


def _build_rag_section(rag_context: str) -> str:
    """Construit la section du contexte RAG."""
    return f"""# KNOWLEDGE BASE CONTEXT

The following techniques from our knowledge base may help with WAF bypass:

{rag_context}"""


def _build_cumulative_section(
    round_number: int,
    knowledge: CumulativeKnowledge
) -> str:
    """Construit la section de connaissance cumulative."""
    return f"""# CUMULATIVE KNOWLEDGE (Rounds 1-{round_number - 1})

## ❌ Patterns that trigger WAF blocks

{format_list(knowledge.blocked_patterns)}

## ✅ Techniques that bypass WAF

{format_list(knowledge.working_techniques)}

## 🎯 Most promising results

{format_list(knowledge.promising_results)}

## 📊 Encoding effectiveness

{format_encoding_stats(knowledge.encoding_stats)}

## 🛡️ WAF Provider

{knowledge.waf_provider or 'Unknown'}"""


def _build_task_section(round_number: int, num_payloads: int) -> str:
    """Construit la section de la tâche à effectuer."""
    return f"""# YOUR TASK (Round {round_number})

Based on ALL the information above:

1. **Analyze** what worked vs what failed in previous rounds
2. **Identify** WAF signatures and patterns to avoid
3. **Select** the most promising techniques to expand
4. **Generate** {num_payloads} surgical payloads
5. **Explain** your reasoning for each payload

## CRITICAL REMINDERS

- ❌ DO NOT repeat any payload that was blocked
- ✅ PRIORITIZE techniques that showed success
- 🔄 USE different encodings if previous ones were blocked
- 💡 Each payload must have a clear rationale

Respond with valid JSON as specified in the system prompt."""

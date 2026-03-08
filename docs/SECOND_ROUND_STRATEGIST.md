# 🎯 Second Round Strategist - Plan d'Implémentation

## 📋 Vue d'ensemble

Le **Second Round Strategist** est un module qui analyse les résultats du Round 1 pour générer des payloads plus intelligents et ciblés, en apprenant des blocages WAF et des réponses obtenues.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     SECOND ROUND PIPELINE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Round 1 Results ──► Analyzer ──► RAG Query ──► LLM ──► Round 2   │
│                          │            │                    Plan     │
│                          ▼            ▼                             │
│                    - WAF blocks   - evasion_transforms              │
│                    - Bypasses     - evasion_examples                │
│                    - Responses    - hacktricks bypass               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Structure des fichiers (maintenable, max ~300 lignes/fichier)

```
ghost_hunter/core/brain/strategist_v2/
├── __init__.py              # ~20 lignes  - Exports publics
├── contracts.py             # ~200 lignes - Dataclasses (OriginalContext, RoundResult, etc.)
├── analyzer.py              # ~250 lignes - Analyse ExecutionResult → RoundResult
├── rag_queries.py           # ~150 lignes - 3 queries RAG ciblées (WAF, evasion, technique)
├── engine.py                # ~300 lignes - StrategistV2Engine (orchestrateur)
├── history.py               # ~150 lignes - AttackHistory (Redis storage)
└── prompts/                 # SOUS-MODULE - Évite un fichier monolithique
    ├── __init__.py          # ~10 lignes  - Re-exports
    ├── system.py            # ~80 lignes  - STRATEGIST_V2_SYSTEM_PROMPT
    ├── builder.py           # ~250 lignes - build_round_n_prompt()
    └── formatters.py        # ~200 lignes - format_*() helpers
```

### Estimation par fichier

| Fichier | Lignes | Responsabilité unique |
|---------|--------|----------------------|
| `__init__.py` | ~20 | Exports: `StrategistV2Engine`, `RoundResult`, etc. |
| `contracts.py` | ~200 | Dataclasses UNIQUEMENT (pas de logique) |
| `analyzer.py` | ~250 | `analyze_execution_result()` → `RoundResult` |
| `rag_queries.py` | ~150 | `get_rag_context_for_round()` avec 3 queries |
| `engine.py` | ~300 | Orchestrateur principal + LLM call |
| `history.py` | ~150 | CRUD Redis pour `attack_history:{hash}` |
| `prompts/system.py` | ~80 | System prompt (constant string) |
| `prompts/builder.py` | ~250 | Construction du prompt cumulatif |
| `prompts/formatters.py` | ~200 | `format_headers()`, `format_test()`, etc. |

**Total : ~1600 lignes / 9 fichiers = ~180 lignes/fichier en moyenne**
**Aucun fichier > 300 lignes** ✅

---

## � RÈGLES DE CODE OBLIGATOIRES

### Limites strictes
| Règle | Valeur | Raison |
|-------|--------|--------|
| **Lignes max par fichier** | 600 | Maintenabilité |
| **Lignes recommandées** | 200-300 | Lisibilité |
| **Fonctions max par classe** | 10 | Single Responsibility |
| **Lignes max par fonction** | 50 | Testabilité |
| **Paramètres max par fonction** | 5 | Simplicité |

### Tests obligatoires
- **TDD** : Écrire le test AVANT le code
- **Couverture** : Chaque fichier `.py` a son `test_*.py`
- **Types** : Tous les paramètres et retours typés
- **Docstrings** : Toutes les fonctions publiques documentées

### Structure de test
```
tests/unit/brain/strategist_v2/
├── test_contracts.py       # Tests dataclasses + validations
├── test_analyzer.py        # Tests analyze_execution_result()
├── test_rag_queries.py     # Tests queries RAG
├── test_engine.py          # Tests orchestrateur (mocks LLM)
├── test_history.py         # Tests Redis storage
└── test_prompts/
    ├── test_builder.py     # Tests build_round_n_prompt()
    └── test_formatters.py  # Tests format_*() helpers
```

### Commande de validation
```bash
# Avant chaque commit
pytest tests/unit/brain/strategist_v2/ -v
wc -l ghost_hunter/core/brain/strategist_v2/*.py  # Doit être < 600
```

---

## �📦 Phase 1: Contracts (`contracts.py`)

### 1.0 OriginalContext - Contexte initial du Triage

```python
@dataclass
class OriginalContext:
    """Contexte original de la requête (du Triage)."""
    
    # Endpoint
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    
    # Triage result
    vuln_class: str                 # IDOR, SQLi, XSS, etc.
    confidence: int                 # 0-100
    interesting_params: List[str]
    triage_reasoning: str
    
    # Security profile
    security_profile: SecurityProfile  # WAF, CDN, Rate limiting
    
    @classmethod
    def from_triage_decision(cls, decision: TriageDecision) -> "OriginalContext":
        """Construit depuis un TriageDecision existant."""
        pass

@dataclass
class SecurityProfile:
    """Profil de sécurité détecté."""
    waf: Optional[str]              # Cloudflare, AWS WAF, F5, etc.
    cdn: Optional[str]              # Cloudflare, CloudFront, etc.
    rate_limit: bool
    anti_bot: Optional[str]         # DataDome, PerimeterX, etc.
```

### 1.1 AttemptResult - Résultat d'une tentative de payload

```python
@dataclass
class AttemptResult:
    """Résultat d'une tentative de payload individuelle."""
    
    # Payload info
    payload_original: str           # Payload avant encoding
    payload_sent: str               # Payload réellement envoyé (avec encoding)
    encoding: str                   # none, url, double_url, unicode, hex
    injection_point: str            # Paramètre ciblé
    
    # Request info
    method: str
    url: str
    
    # Response info
    status_code: int
    response_time_ms: float
    response_length: int
    response_snippet: str           # Premiers 500 chars
    
    # WAF detection
    waf_blocked: bool
    waf_provider: Optional[str]     # Cloudflare, AWS, F5, etc.
    waf_signature: Optional[str]    # Pattern qui a triggeré le block
    
    # Analysis
    is_interesting: bool            # Response différente du baseline
    diff_indicators: List[str]      # Ce qui a changé (status, length, content)
```

### 1.2 RoundResult - Résultat complet d'un Round

```python
@dataclass
class RoundResult:
    """Résultat complet d'un round (plan + exécution)."""
    
    # Round info
    round_number: int
    timestamp: datetime
    
    # Plan used
    plan: AttackPlan                # Le plan qui a été exécuté
    
    # Tests
    tests: List[AttemptResult]
    
    # Aggregated stats
    blocked_count: int
    passed_count: int
    interesting_count: int
    error_count: int
    
    # Patterns discovered
    blocked_patterns: List[str]     # Patterns WAF détectés
    working_techniques: List[str]   # Techniques qui ont passé
    promising_results: List[str]    # Résultats intéressants
```

### 1.3 CumulativeKnowledge - Connaissance agrégée multi-round

```python
@dataclass
class CumulativeKnowledge:
    """Connaissance agrégée de tous les rounds précédents."""
    
    # What to avoid
    blocked_patterns: List[str]     # Tous les patterns bloqués
    failed_encodings: List[str]     # Encodings qui échouent
    
    # What works
    working_techniques: List[str]   # Techniques qui passent le WAF
    successful_encodings: List[str] # Encodings qui passent
    
    # Most promising
    promising_results: List[str]    # Résultats les plus intéressants
    
    # Stats
    encoding_stats: Dict[str, Dict[str, int]]  # {encoding: {blocked: N, passed: N}}
    
    # Security context
    waf_provider: Optional[str]
    
    @classmethod
    def from_history(cls, rounds: List[RoundResult]) -> "CumulativeKnowledge":
        """Construit la connaissance cumulative depuis l'historique."""
        pass
    
    def update_with_round(self, round_result: RoundResult) -> "CumulativeKnowledge":
        """Retourne une nouvelle instance enrichie du round."""
        pass
```

### 1.4 Round2Plan - Plan généré pour le Round N

```python
@dataclass
class RoundNPlan:
    """Plan d'attaque pour le Round N (généré par Strategist V2)."""
    
    # Analysis from LLM
    round_analysis: RoundAnalysis
    
    # Strategy
    strategy: AttackStrategy
    
    # Payloads
    payloads: List[PayloadVariant]
    
    # Execution config
    stop_conditions: StopConditions
    
    # Metadata
    round_number: int
    model_used: str
    reasoning: str
    confidence: int  # 0-100

@dataclass
class RoundAnalysis:
    """Analyse du LLM sur les rounds précédents."""
    waf_behavior: str
    blocked_signatures: List[str]
    working_techniques: List[str]
    confidence_delta: str  # "+15%" or "-5%"

@dataclass
class AttackStrategy:
    """Stratégie d'attaque pour le round."""
    focus_injection_points: List[str]
    avoid_patterns: List[str]
    recommended_techniques: List[str]
    encoding_strategy: str  # "primary: unicode, fallback: hex"

@dataclass
class StopConditions:
    """Conditions d'arrêt du round."""
    max_requests: int
    stop_on_confirmed: bool
```

### 1.5 RAGContext - Contexte RAG pour le prompt

```python
@dataclass
class RAGContext:
    """Contexte RAG formaté pour le prompt."""
    
    chunks: List[RAGChunk]
    total_tokens: int
    
    def format_for_prompt(self) -> str:
        """Formate les chunks pour inclusion dans le prompt."""
        formatted = []
        for chunk in self.chunks:
            source_type = chunk.metadata.get("type", "unknown")
            formatted.append(f"[{source_type.upper()}] {chunk.text}")
        return "\n\n".join(formatted)
```

---

## 📦 Phase 2: Analyzer (`analyzer.py`)

### 2.1 Fonctions d'analyse

```python
def analyze_round1_results(
    execution_result: ExecutionResult,
    test_details: List[dict]
) -> Round1Summary:
    """
    Analyse les résultats du Round 1 pour extraire les patterns.
    
    Input: ExecutionResult avec test_details de chaque requête
    Output: Round1Summary avec patterns agrégés
    """

def detect_waf_signature(
    payload: str,
    response: dict,
    waf_provider: str
) -> Optional[str]:
    """
    Détecte quelle signature WAF a probablement bloqué le payload.
    
    Utilise les patterns connus (inline dans le code ou depuis RAG).
    """

def categorize_response(
    response: dict,
    baseline: Optional[dict]
) -> dict:
    """
    Catégorise la réponse: blocked, passed, interesting, error.
    """

def extract_working_techniques(
    attempts: List[AttemptResult]
) -> List[str]:
    """
    Extrait les techniques qui ont fonctionné (passé le WAF).
    """
```

---

## 📦 Phase 3: RAG Queries (`rag_queries.py`)

### 3.1 Queries ciblées

```python
def query_waf_evasion_techniques(
    rag_engine: RAGEngine,
    vuln_class: str,
    waf_provider: Optional[str],
    blocked_patterns: List[str],
    max_chunks: int = 5
) -> str:
    """
    Query RAG pour techniques d'évasion WAF.
    
    Sources ciblées:
    - evasion_transforms (techniques disponibles)
    - evasion_examples (exemples concrets)
    - hacktricks (bypass génériques)
    """

def query_alternative_payloads(
    rag_engine: RAGEngine,
    vuln_class: str,
    working_techniques: List[str],
    max_chunks: int = 3
) -> str:
    """
    Query RAG pour payloads alternatifs utilisant les techniques qui marchent.
    """

def build_rag_context_round2(
    rag_engine: RAGEngine,
    round1_summary: Round1Summary,
    max_tokens: int = 800
) -> str:
    """
    Construit le contexte RAG complet pour le Round 2.
    
    Combine:
    1. Techniques d'évasion (3 chunks)
    2. Payloads alternatifs (2 chunks)
    
    Total: ~5 chunks ultra-ciblés
    """
```

---

## 📦 Phase 4: Prompts (`prompts.py`) - STRUCTURE CUMULATIVE

### 4.0 Architecture des Prompts Multi-Round

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PROMPT CUMULATIF - STRATÉGISTE ROUND N                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      SYSTEM PROMPT (fixe)                           │    │
│  │  - Rôle: Expert pentester adaptatif                                 │    │
│  │  - Principes: Learn from blocks, exploit bypasses, vary approach    │    │
│  │  - Output format: JSON structuré                                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      USER PROMPT (cumulatif)                        │    │
│  │                                                                     │    │
│  │  SECTION 1: ORIGINAL CONTEXT (du Triage)                            │    │
│  │  ├── Endpoint: POST /api/v1/users/{user_id}/profile                 │    │
│  │  ├── Headers: Authorization: Bearer xxx                             │    │
│  │  ├── Body: {"email": "test@example.com"}                            │    │
│  │  ├── Triage Result: IDOR suspected, confidence 78%                  │    │
│  │  └── Security Profile: Cloudflare WAF, Rate limiting detected       │    │
│  │                                                                     │    │
│  │  SECTION 2: PLAN ROUND 1 (Strategist V1)                            │    │
│  │  ├── Vuln class: IDOR                                               │    │
│  │  ├── Injection points: [user_id, body.email]                        │    │
│  │  ├── Payloads planned: ["{{user_id+1}}", "admin@...", ...]          │    │
│  │  └── Reasoning: "Direct object reference via path parameter..."     │    │
│  │                                                                     │    │
│  │  SECTION 3: RESULTS ROUND 1 (détaillé par test)                     │    │
│  │  ├── Test 1/5:                                                      │    │
│  │  │   ├── Payload: {{user_id+1}} → 456                               │    │
│  │  │   ├── Encoding: none                                             │    │
│  │  │   ├── Request: POST /api/v1/users/456/profile                    │    │
│  │  │   ├── Response: 403, body="Access Denied", 45ms                  │    │
│  │  │   ├── WAF Block: YES (Cloudflare, pattern: numeric_id_access)    │    │
│  │  │   └── Diff vs Baseline: status_changed, content_changed          │    │
│  │  ├── Test 2/5:                                                      │    │
│  │  │   ├── Payload: admin@example.com                                 │    │
│  │  │   └── ... (même structure)                                       │    │
│  │  └── Summary: 3 blocked, 1 passed, 1 error                          │    │
│  │                                                                     │    │
│  │  SECTION 4: RAG CONTEXT (5 chunks ciblés)                           │    │
│  │  ├── [WAF Blocklist] F5 Rule: "numeric id in path blocked..."       │    │
│  │  ├── [WAF Blocklist] Cloudflare: "direct IDOR patterns..."          │    │
│  │  ├── [Evasion Transform] IDOR bypass: use UUID instead of int       │    │
│  │  ├── [Evasion Example] GraphQL aliasing to bypass rate limit        │    │
│  │  └── [Technique] HackTricks: Broken Access Control methods          │    │
│  │                                                                     │    │
│  │  SECTION 5: TASK                                                    │    │
│  │  └── Generate Round 2 plan with smarter payloads                    │    │
│  │                                                                     │    │
│  │  ═══════════════════════════════════════════════════════════════    │    │
│  │  SI ROUND 3+: Sections additionnelles                               │    │
│  │  ═══════════════════════════════════════════════════════════════    │    │
│  │                                                                     │    │
│  │  SECTION 6: RESULTS ROUND 2                                         │    │
│  │  ├── Plan Round 2: payloads [...], techniques [...]                 │    │
│  │  ├── Test 1/4: ... (même format que Section 3)                      │    │
│  │  └── Summary: 2 blocked, 2 passed (1 interesting!)                  │    │
│  │                                                                     │    │
│  │  SECTION 7: CUMULATIVE KNOWLEDGE                                    │    │
│  │  ├── ❌ Patterns to AVOID: [numeric_id, direct_reference, ...]      │    │
│  │  ├── ✅ Techniques that WORK: [uuid_format, base64_id, ...]         │    │
│  │  └── 🎯 Most promising: base64_encoded_id (passed, interesting)     │    │
│  │                                                                     │    │
│  │  SECTION 8: TASK (Round 3)                                          │    │
│  │  └── Build on working techniques, refine further                    │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.1 System Prompt (identique tous rounds)

```python
STRATEGIST_V2_SYSTEM_PROMPT = """You are an expert penetration tester in iterative attack refinement.

CONTEXT: You are in Round {round_number} of testing. You have access to:
- Original vulnerability hypothesis from triage
- All previous attack plans and their detailed results
- RAG knowledge base with WAF signatures and bypass techniques
- Cumulative knowledge of what works vs what fails

YOUR TASK: Generate a REFINED attack plan for Round {round_number}.

KEY PRINCIPLES:
1. LEARN from blocks - never repeat blocked patterns
2. EXPLOIT successes - double down on working techniques  
3. ADAPT encodings - if URL encoding blocked, try unicode/hex/double
4. SURGICAL precision - fewer, smarter payloads > spray-and-pray
5. BUILD on history - use cumulative knowledge from all rounds

OUTPUT FORMAT (JSON):
{{
    "round_analysis": {{
        "waf_behavior": "Brief analysis of WAF patterns observed",
        "blocked_signatures": ["pattern1", "pattern2"],
        "working_techniques": ["technique1", "technique2"],
        "confidence_delta": "+15%/-5%"  // Change from previous round
    }},
    "strategy": {{
        "focus_injection_points": ["point1", "point2"],
        "avoid_patterns": ["pattern to avoid"],
        "recommended_techniques": ["technique1", "technique2"],
        "encoding_strategy": "primary/fallback encoding"
    }},
    "payloads": [
        {{
            "payload": "...",
            "injection_point": "target param",
            "encoding": "none|url|double_url|unicode|hex|base64",
            "technique": "technique_name",
            "rationale": "Why this should work given Round N-1 results"
        }}
    ],
    "stop_conditions": {{
        "max_requests": 5,
        "stop_on_confirmed": true
    }},
    "confidence": 0-100,
    "reasoning": "Overall strategy explanation"
}}
"""
```

### 4.2 User Prompt Builder - Structure Détaillée

```python
def build_round_n_prompt(
    round_number: int,
    original_context: OriginalContext,
    attack_history: List[RoundResult],  # Tous les rounds précédents
    rag_context: RAGContext,
    cumulative_knowledge: CumulativeKnowledge
) -> str:
    """
    Construit le prompt cumulatif pour le Round N.
    
    Le prompt GRANDIT à chaque round avec l'historique complet.
    """
    
    sections = []
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 1: ORIGINAL CONTEXT (toujours présent)
    # ═══════════════════════════════════════════════════════════════
    sections.append(f"""
## ORIGINAL CONTEXT (from Triage)

**Endpoint:** {original_context.method} {original_context.url}

**Headers:**
```
{format_headers(original_context.headers)}
```

**Body:**
```json
{original_context.body}
```

**Triage Assessment:**
- Suspected vulnerability: {original_context.vuln_class}
- Confidence: {original_context.confidence}%
- Interesting parameters: {original_context.interesting_params}
- Reasoning: {original_context.triage_reasoning}

**Security Profile:**
- WAF: {original_context.security_profile.waf or 'Not detected'}
- CDN: {original_context.security_profile.cdn or 'Not detected'}
- Rate limiting: {original_context.security_profile.rate_limit}
""")
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 2+: PREVIOUS ROUNDS (cumulatif)
    # ═══════════════════════════════════════════════════════════════
    for i, round_result in enumerate(attack_history):
        round_num = i + 1
        
        # Plan de ce round
        sections.append(f"""
## ROUND {round_num} PLAN

**Vulnerability Class:** {round_result.plan.vuln_class}
**Injection Points:** {round_result.plan.injection_points}
**Techniques:** {round_result.plan.techniques}
**Planned Payloads:**
{format_payloads_planned(round_result.plan.payloads)}
**Reasoning:** {round_result.plan.reasoning}
""")
        
        # Résultats détaillés de ce round
        sections.append(f"""
## ROUND {round_num} RESULTS (Detailed)

""")
        for j, test in enumerate(round_result.tests):
            sections.append(f"""
### Test {j+1}/{len(round_result.tests)}

| Field | Value |
|-------|-------|
| Payload (original) | `{test.payload_original}` |
| Payload (sent) | `{test.payload_sent}` |
| Encoding | {test.encoding} |
| Injection point | {test.injection_point} |
| Request | `{test.method} {test.url}` |
| Response status | {test.response.status_code} |
| Response time | {test.response.time_ms}ms |
| Response length | {test.response.length} bytes |
| WAF Blocked | {'❌ YES' if test.waf_blocked else '✅ NO'} |
| WAF Signature | {test.waf_signature or 'N/A'} |
| Diff vs Baseline | {', '.join(test.diff_indicators) or 'No diff'} |
| Interesting | {'🎯 YES' if test.is_interesting else 'No'} |

Response snippet:
```
{test.response.snippet[:300]}
```
""")
        
        # Summary du round
        sections.append(f"""
### Round {round_num} Summary
- Total tests: {len(round_result.tests)}
- Blocked: {round_result.blocked_count}
- Passed: {round_result.passed_count}
- Interesting: {round_result.interesting_count}
- Errors: {round_result.error_count}
""")
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION N: RAG CONTEXT (5 chunks ciblés)
    # ═══════════════════════════════════════════════════════════════
    sections.append(f"""
## KNOWLEDGE BASE CONTEXT

{format_rag_chunks(rag_context.chunks)}
""")
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION N+1: CUMULATIVE KNOWLEDGE (Round 2+)
    # ═══════════════════════════════════════════════════════════════
    if round_number > 1:
        sections.append(f"""
## CUMULATIVE KNOWLEDGE (Rounds 1-{round_number - 1})

### ❌ Patterns that trigger WAF blocks:
{format_list(cumulative_knowledge.blocked_patterns)}

### ✅ Techniques that bypass WAF:
{format_list(cumulative_knowledge.working_techniques)}

### 🎯 Most promising results:
{format_list(cumulative_knowledge.promising_results)}

### 📊 Encoding effectiveness:
{format_encoding_stats(cumulative_knowledge.encoding_stats)}
""")
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION FINALE: TASK
    # ═══════════════════════════════════════════════════════════════
    sections.append(f"""
## YOUR TASK (Round {round_number})

Based on ALL the information above:

1. **Analyze** what worked vs what failed in previous rounds
2. **Identify** WAF signatures and patterns to avoid
3. **Select** the most promising techniques to expand
4. **Generate** {5 if round_number <= 2 else 3} surgical payloads
5. **Explain** your reasoning for each payload

Remember:
- DO NOT repeat any payload that was blocked
- PRIORITIZE techniques that showed success
- USE different encodings if previous ones were blocked
- Each payload must have a clear rationale

Provide your response in the JSON format specified in the system prompt.
""")
    
    return "\n".join(sections)
```

### 4.3 RAG Query Strategy par Round

```python
def get_rag_context_for_round(
    rag_engine: RAGEngine,
    round_number: int,
    original_context: OriginalContext,
    cumulative_knowledge: CumulativeKnowledge
) -> RAGContext:
    """
    Query RAG avec des filtres adaptés au round.
    
    Token Budget: 5 chunks (~500 tokens)
    
    Répartition:
    - 2 chunks: WAF blocklist (patterns à éviter)
    - 2 chunks: Evasion techniques (bypass methods)
    - 1 chunk: General technique (cheatsheet/hacktricks)
    """
    
    chunks = []
    
    # ═══ QUERY 1: WAF Blocklist (2 chunks) ═══
    waf_query = f"{original_context.vuln_class} WAF blocked signature"
    if cumulative_knowledge.waf_provider:
        waf_query += f" {cumulative_knowledge.waf_provider}"
    
    waf_results = rag_engine.query_sync(
        text=waf_query,
        top_k=2,
        filters={"type": {"$eq": "waf_blocklist"}},
        min_score=0.3
    )
    chunks.extend(waf_results.results)
    
    # ═══ QUERY 2: Evasion Transforms (2 chunks) ═══
    evasion_query = f"{original_context.vuln_class} bypass evasion"
    if cumulative_knowledge.blocked_patterns:
        # Cibler les patterns bloqués spécifiquement
        evasion_query += f" avoid {' '.join(cumulative_knowledge.blocked_patterns[:3])}"
    
    evasion_results = rag_engine.query_sync(
        text=evasion_query,
        top_k=2,
        filters={"$or": [
            {"source": {"$eq": "evasion_transforms"}},
            {"source": {"$eq": "evasion_examples"}}
        ]},
        min_score=0.3
    )
    chunks.extend(evasion_results.results)
    
    # ═══ QUERY 3: General Technique (1 chunk) ═══
    technique_query = f"{original_context.vuln_class} exploitation technique"
    if cumulative_knowledge.working_techniques:
        technique_query += f" {cumulative_knowledge.working_techniques[0]}"
    
    technique_results = rag_engine.query_sync(
        text=technique_query,
        top_k=1,
        filters={"type": {"$in": ["technique", "cheatsheet"]}},
        min_score=0.4
    )
    chunks.extend(technique_results.results)
    
    return RAGContext(chunks=chunks, total_tokens=estimate_tokens(chunks))

---

## 📦 Phase 5: Engine (`engine.py`)

### 5.1 StrategistV2Engine

```python
class StrategistV2Engine:
    """
    Engine pour générer des plans d'attaque Round 2+.
    
    Utilise:
    - Round 1 results analysis
    - RAG context (evasion techniques)
    - LLM (Llama 3.3 70B via Groq)
    """
    
    def __init__(
        self,
        client: AIClient,
        model: str = "llama-3.3-70b-versatile",
        rag_engine: Optional[RAGEngine] = None
    ):
        pass
    
    def create_round2_plan(
        self,
        round1_summary: Round1Summary,
        previous_rounds: List[Round1Summary] = None
    ) -> Round2Plan:
        """
        Génère un plan Round 2 basé sur les résultats Round 1.
        
        Steps:
        1. Query RAG pour techniques d'évasion
        2. Build prompt avec context
        3. Call LLM
        4. Parse response
        5. Return Round2Plan
        """
    
    def analyze_and_plan(
        self,
        execution_result: ExecutionResult
    ) -> Round2Plan:
        """
        Shortcut: Analyse ExecutionResult et génère Round2Plan.
        
        Combine analyze_round1_results + create_round2_plan
        """
```

---

## 📦 Phase 6: History (`history.py`)

### 6.1 Gestion multi-round

```python
class AttackHistory:
    """
    Gère l'historique des tentatives pour un endpoint.
    
    Stockage: Redis avec TTL 24h
    Key: attack_history:{endpoint_hash}
    """
    
    def __init__(self, redis_client=None):
        pass
    
    def add_round(
        self,
        endpoint_hash: str,
        round_summary: Round1Summary
    ) -> int:
        """Ajoute un round et retourne le numéro du round."""
    
    def get_history(
        self,
        endpoint_hash: str
    ) -> List[Round1Summary]:
        """Récupère tout l'historique d'un endpoint."""
    
    def get_latest_round(
        self,
        endpoint_hash: str
    ) -> Optional[Round1Summary]:
        """Récupère le dernier round."""
    
    def clear_history(
        self,
        endpoint_hash: str
    ) -> None:
        """Efface l'historique d'un endpoint."""
```

---

## 🔌 Phase 7: Intégration Dashboard

### 7.1 Nouveau endpoint API (`dashboard/api.py`)

```python
@app.post("/api/endpoints/{hash}/second-round")
async def trigger_second_round(hash: str):
    """
    Déclenche un Second Round pour un endpoint.
    
    1. Récupère ExecutionResult du Round 1
    2. Appelle StrategistV2Engine.analyze_and_plan()
    3. Exécute le Round2Plan
    4. Stocke les résultats
    5. Retourne le résumé
    """

@app.get("/api/endpoints/{hash}/attack-history")
async def get_attack_history(hash: str):
    """
    Récupère l'historique des rounds pour un endpoint.
    """
```

### 7.2 Nouveau composant Vue (`dashboard/static/views/secondround.html`)

```html
<!-- Second Round Panel -->
- Affiche Round 1 results (tableau)
- Bouton "Launch Round 2"
- Affiche Round 2 plan (payloads, techniques)
- Historique des rounds
- Visualisation WAF blocks vs bypasses
```

---

## ✅ Checklist d'implémentation

### Phase 1: Contracts ⬜
- [ ] Créer `strategist_v2/__init__.py`
- [ ] Créer `strategist_v2/contracts.py`
- [ ] Définir `OriginalContext`, `SecurityProfile`
- [ ] Définir `AttemptResult`
- [ ] Définir `RoundResult`
- [ ] Définir `CumulativeKnowledge`
- [ ] Définir `RoundNPlan`, `RoundAnalysis`, `AttackStrategy`, `StopConditions`
- [ ] Définir `RAGContext`

### Phase 2: Analyzer ⬜
- [ ] Créer `strategist_v2/analyzer.py`
- [ ] Implémenter `analyze_execution_result()` → `RoundResult`
- [ ] Implémenter `detect_waf_block()` 
- [ ] Implémenter `extract_diff_indicators()`
- [ ] Implémenter `build_cumulative_knowledge()`

### Phase 3: RAG Queries ⬜
- [ ] Créer `strategist_v2/rag_queries.py`
- [ ] Implémenter `query_waf_blocklist()` (2 chunks)
- [ ] Implémenter `query_evasion_techniques()` (2 chunks)
- [ ] Implémenter `query_general_technique()` (1 chunk)
- [ ] Implémenter `get_rag_context_for_round()` (orchestrateur)

### Phase 4: Prompts ⬜
- [ ] Créer `strategist_v2/prompts/__init__.py`
- [ ] Créer `strategist_v2/prompts/system.py` - STRATEGIST_V2_SYSTEM_PROMPT
- [ ] Créer `strategist_v2/prompts/formatters.py`:
  - [ ] `format_headers()`
  - [ ] `format_body()`
  - [ ] `format_test_result()`
  - [ ] `format_round_summary()`
  - [ ] `format_rag_chunks()`
  - [ ] `format_cumulative_knowledge()`
- [ ] Créer `strategist_v2/prompts/builder.py`:
  - [ ] `build_original_context_section()`
  - [ ] `build_round_plan_section()`
  - [ ] `build_round_results_section()`
  - [ ] `build_rag_section()`
  - [ ] `build_cumulative_section()`
  - [ ] `build_task_section()`
  - [ ] `build_round_n_prompt()` (assembleur principal)

### Phase 5: Engine ⬜
- [ ] Créer `strategist_v2/engine.py`
- [ ] Implémenter `StrategistV2Engine.__init__()`
- [ ] Implémenter `_call_llm()` avec retry
- [ ] Implémenter `_parse_response()` → `RoundNPlan`
- [ ] Implémenter `create_round_plan()`
- [ ] Implémenter `should_continue()` (conditions d'arrêt)

### Phase 6: History ⬜
- [ ] Créer `strategist_v2/history.py`
- [ ] Implémenter `AttackHistory.__init__()` (Redis client)
- [ ] Implémenter `add_round()`
- [ ] Implémenter `get_history()`
- [ ] Implémenter `get_original_context()`
- [ ] Implémenter `clear_history()`

### Phase 7: Dashboard ⬜
- [ ] Ajouter endpoint `POST /api/endpoints/{hash}/round2`
- [ ] Ajouter endpoint `GET /api/endpoints/{hash}/attack-history`
- [ ] Créer `views/attackhistory.html`
- [ ] Intégrer dans la navigation

### Phase 8: Tests ⬜
- [ ] `tests/unit/test_strategist_v2_contracts.py`
- [ ] `tests/unit/test_strategist_v2_analyzer.py`
- [ ] `tests/unit/test_strategist_v2_prompts.py`
- [ ] `tests/integration/test_strategist_v2_engine.py`

---

## 🎯 Flux de données détaillé (Multi-Round Cumulatif)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MULTI-ROUND CUMULATIVE FLOW                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ═══════════════════════════════════════════════════════════════════════    │
│  ROUND 1 (Strategist V1 - existant)                                         │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                             │
│  1. INPUT: TriageDecision                                                   │
│     ├── endpoint: POST /api/users/{id}/profile                              │
│     ├── vuln_class: IDOR                                                    │
│     ├── confidence: 78%                                                     │
│     └── interesting_params: [id, email]                                     │
│                                                                             │
│  2. STRATEGIST V1 → AttackPlan                                              │
│     ├── injection_points: [id]                                              │
│     ├── payloads: [id+1, id-1, 0, 99999]                                    │
│     └── encoding: none                                                      │
│                                                                             │
│  3. EXECUTOR → ExecutionResult                                              │
│     ├── test_details: [{payload, response, waf_blocked...} x5]              │
│     └── findings: []                                                        │
│                                                                             │
│  4. STORE Round 1 in History (Redis)                                        │
│     └── attack_history:{hash} = [RoundResult(plan, tests, summary)]         │
│                                                                             │
│  ═══════════════════════════════════════════════════════════════════════    │
│  ROUND 2 (Strategist V2 - nouveau)                                          │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                             │
│  5. LOAD from History                                                       │
│     └── original_context + round1_result                                    │
│                                                                             │
│  6. ANALYZE Round 1 (analyzer.py)                                           │
│     ├── Blocked: [payload1, payload2] → encoding: none                      │
│     ├── Passed: [payload3] → encoding: none                                 │
│     ├── WAF: Cloudflare detected                                            │
│     └── Cumulative: blocked_patterns=["numeric_id"], working=["boundary"]   │
│                                                                             │
│  7. RAG QUERY (rag_queries.py) - 5 chunks                                   │
│     ├── Query 1 (WAF): "IDOR WAF blocklist Cloudflare numeric_id"           │
│     │   → 2 chunks waf_blocklist                                            │
│     ├── Query 2 (Evasion): "IDOR bypass avoid numeric_id"                   │
│     │   → 2 chunks evasion_transforms/examples                              │
│     └── Query 3 (Technique): "IDOR exploitation technique"                  │
│         → 1 chunk technique                                                 │
│                                                                             │
│  8. BUILD PROMPT (prompts.py) - CUMULATIF                                   │
│     ┌──────────────────────────────────────────────────────────────────┐    │
│     │ SECTION 1: Original Context (Triage)                             │    │
│     │ SECTION 2: Plan Round 1                                          │    │
│     │ SECTION 3: Results Round 1 (detailed per test)                   │    │
│     │ SECTION 4: RAG Context (5 chunks)                                │    │
│     │ SECTION 5: Cumulative Knowledge                                  │    │
│     │ SECTION 6: Task Round 2                                          │    │
│     └──────────────────────────────────────────────────────────────────┘    │
│     Total: ~1700 tokens                                                     │
│                                                                             │
│  9. LLM CALL (engine.py)                                                    │
│     ├── Model: llama-3.3-70b-versatile                                      │
│     ├── Temperature: 0.6                                                    │
│     └── Max tokens: 2000                                                    │
│                                                                             │
│  10. PARSE → Round2Plan                                                     │
│      ├── payloads: [new_payload1, new_payload2...] (évitent patterns R1)    │
│      ├── encodings: [unicode, base64] (varient de R1)                       │
│      └── techniques: ["uuid_format", "base64_id"]                           │
│                                                                             │
│  11. EXECUTOR → ExecutionResult                                             │
│      └── test_details: [{...} x5]                                           │
│                                                                             │
│  12. STORE Round 2 in History                                               │
│      └── attack_history:{hash} = [R1, R2]                                   │
│                                                                             │
│  ═══════════════════════════════════════════════════════════════════════    │
│  ROUND 3+ (si nécessaire)                                                   │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                             │
│  13. LOAD History: [R1, R2]                                                 │
│                                                                             │
│  14. ANALYZE: cumulative knowledge enrichi                                  │
│      ├── blocked_patterns: [pattern_r1, pattern_r2]                         │
│      ├── working_techniques: [tech_r1, tech_r2]                             │
│      └── promising: "base64_id showed interesting response"                 │
│                                                                             │
│  15. BUILD PROMPT - GRANDIT                                                 │
│      ┌──────────────────────────────────────────────────────────────────┐   │
│      │ SECTION 1: Original Context                                      │   │
│      │ SECTION 2: Plan Round 1                                          │   │
│      │ SECTION 3: Results Round 1                                       │   │
│      │ SECTION 4: Plan Round 2                                          │   │
│      │ SECTION 5: Results Round 2                                       │   │
│      │ SECTION 6: RAG Context (ciblé sur ce qui marche)                 │   │
│      │ SECTION 7: Cumulative Knowledge (enrichi)                        │   │
│      │ SECTION 8: Task Round 3                                          │   │
│      └──────────────────────────────────────────────────────────────────┘   │
│      Total: ~2400 tokens                                                    │
│                                                                             │
│  16. Continue jusqu'à:                                                      │
│      ├── Vuln confirmée → STOP, generate Finding                            │
│      ├── Max rounds (4) atteint → STOP                                      │
│      └── Confidence < 20% → STOP                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Visualisation du prompt cumulatif

```
Round 1:  [Context][RAG][Task]                          ~1000 tokens
          └─────────────────┘
          
Round 2:  [Context][Plan1][Results1][RAG][Cumul][Task]  ~1700 tokens
          └─────────────────────────────────────────┘
          
Round 3:  [Context][P1][R1][P2][R2][RAG][Cumul][Task]   ~2400 tokens
          └─────────────────────────────────────────────┘
          
Round 4:  [Context][P1][R1][P2][R2][P3][R3][RAG][Cumul][Task]  ~2950 tokens
          └─────────────────────────────────────────────────────┘
          
Round 5+: [Context][Summary(R1-R3)][P4][R4][RAG][Cumul][Task]  ~2500 tokens
          └─────────────────────────────────────────────────────┘
          (Compression des vieux rounds en summary)
```

---

## 📝 Notes d'implémentation

### RAG Sources disponibles (vérifié)

| Source | Type | Chunks | Usage Round 2+ |
|--------|------|--------|----------------|
| `waf_blocklist` | `waf_blocklist` | **204** | ✅ Signatures WAF F5 par vuln_type |
| - sqli | | 27 | ✅ Patterns SQLi bloqués |
| - cmdi | | 9 | ✅ Patterns Command Injection |
| - xss | | 1 | ⚠️ Peu de données |
| - other | | 155 | ✅ Patterns génériques |
| `evasion_transforms` | `transform` | ~10 | ✅ Techniques par vuln_class |
| `evasion_examples` | `example` | ~5 | ✅ Exemples concrets |
| `technique` | `technique` | 813 | ✅ Techniques pentesting |
| `nuclei_template` | `nuclei_template` | 12,015 | ✅ CVEs et checks |
| **Total RAG** | | **13,484** | |

### Queries RAG par Round

```python
# Query 1: WAF Blocklist (2 chunks)
filters = {
    "$and": [
        {"type": {"$eq": "waf_blocklist"}},
        {"vuln_type": {"$eq": vuln_class}}  # sqli, cmdi, xss, etc.
    ]
}
text = f"{vuln_class} WAF blocked pattern signature {waf_provider}"

# Query 2: Evasion Techniques (2 chunks)  
filters = {
    "$or": [
        {"source": {"$eq": "evasion_transforms"}},
        {"source": {"$eq": "evasion_examples"}}
    ]
}
text = f"{vuln_class} bypass evasion avoid {blocked_patterns}"

# Query 3: General Technique (1 chunk)
filters = {"type": {"$in": ["technique", "cheatsheet"]}}
text = f"{vuln_class} exploitation technique {working_technique}"
```

### Fallback si RAG incomplet

Si les chunks RAG sont insuffisants, utiliser les transforms hardcodés dans `ghost_hunter/core/evasion/transforms.py`.

### Token Budget Multi-Round (CUMULATIF)

| Round | Composant | Tokens | Total Input |
|-------|-----------|--------|-------------|
| **R1** | System prompt | 200 | |
| | Endpoint context | 150 | |
| | Triage result | 100 | |
| | RAG context (5 chunks) | 500 | |
| | Task instructions | 50 | **~1000** |
| **R2** | + Plan R1 | 200 | |
| | + Results R1 (5 tests detailed) | 400 | |
| | + Cumulative knowledge | 100 | **~1700** |
| **R3** | + Plan R2 | 200 | |
| | + Results R2 (5 tests) | 400 | |
| | + Updated cumulative | 100 | **~2400** |
| **R4** | + Plan R3 | 200 | |
| | + Results R3 (3 tests) | 250 | |
| | + Updated cumulative | 100 | **~2950** |

**Note:** Le contexte GRANDIT à chaque round. Après Round 4, on peut résumer les rounds anciens pour économiser des tokens.

### Compression si trop de tokens (Round 5+)

```python
if round_number > 4:
    # Résumer les anciens rounds au lieu de les inclure en entier
    old_rounds = attack_history[:-2]  # Tous sauf les 2 derniers
    recent_rounds = attack_history[-2:]  # Les 2 derniers en détail
    
    summary = summarize_old_rounds(old_rounds)  # ~300 tokens
    # Au lieu de ~1600 tokens pour 4 rounds détaillés
```

---

## 🚀 Ordre d'implémentation recommandé

```
1. contracts.py          ─────► Types de base (aucune dépendance)
                                 
2. prompts/formatters.py ─────► Helpers de formatage (dépend: contracts)
                                 
3. prompts/system.py     ─────► System prompt (aucune dépendance)
                                 
4. prompts/builder.py    ─────► Assembleur (dépend: formatters, contracts)
                                 
5. analyzer.py           ─────► Analyse résultats (dépend: contracts)
                                 
6. rag_queries.py        ─────► Queries RAG (dépend: contracts, RAGEngine existant)
                                 
7. history.py            ─────► Storage Redis (dépend: contracts)
                                 
8. engine.py             ─────► Orchestrateur (dépend: TOUT)
                                 
9. Tests unitaires       ─────► Valider chaque module
                                 
10. API + Dashboard      ─────► Intégration finale
```

---

## ⏱️ Estimation temps (mise à jour)

| Phase | Fichier(s) | Temps estimé |
|-------|------------|--------------|
| 1 | `contracts.py` | 30 min |
| 2 | `prompts/formatters.py` | 25 min |
| 3 | `prompts/system.py` | 10 min |
| 4 | `prompts/builder.py` | 35 min |
| 5 | `analyzer.py` | 45 min |
| 6 | `rag_queries.py` | 30 min |
| 7 | `history.py` | 25 min |
| 8 | `engine.py` | 45 min |
| 9 | Tests unitaires | 1h |
| 10 | API + Dashboard | 1h30 |
| **Total** | | **~6h30** |

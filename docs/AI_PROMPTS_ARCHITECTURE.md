# 🧠 Ghost-Hunter AI Prompts Architecture

> **Version 2.0** - Optimisé avec les recommandations Gemini (Chain of Thought, XML tags, WAF grammar)

## Vue d'ensemble du Pipeline AI

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AI PIPELINE FLOW                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   HTTP Request (intercepté par mitmproxy)                                   │
│         │                                                                   │
│         ▼                                                                   │
│   ┌─────────────────┐                                                       │
│   │  HEURISTICS     │  Score 0-100 basé sur 25 règles                       │
│   │  (heuristics.py)│  • Params sensibles (id, user, token)                 │
│   │                 │  • Patterns IDOR (/users/123/profile)                 │
│   │                 │  • Auth headers, file upload, etc.                    │
│   └────────┬────────┘                                                       │
│            │ score >= 30                                                    │
│            ▼                                                                │
│   ┌─────────────────┐     ┌─────────────────┐                               │
│   │  TRIAGE TIER 1  │────▶│  TRIAGE TIER 2  │                               │
│   │  Quick Filter   │     │  Full Analysis  │                               │
│   │  Llama 8B       │     │  Llama 8B + RAG │                               │
│   │  ~100 tokens    │     │  ~500 tokens    │                               │
│   └─────────────────┘     └────────┬────────┘                               │
│                                    │ interesting=true                       │
│                                    ▼                                        │
│   ┌───────────────────────────────────────────────────────────────┐         │
│   │                      STRATEGIST v2.0                          │         │
│   │                      Llama 70B + RAG (1200 tokens)            │         │
│   │                                                               │         │
│   │  NEW: Chain of Thought analysis before payloads               │         │
│   │  NEW: XML-structured prompts                                  │         │
│   │  NEW: WAF-specific evasion grammar                            │         │
│   │  NEW: Domain-specific attack hints                            │         │
│   │                                                               │         │
│   │  Output: AttackPlan with analysis + payloads                  │         │
│   └───────────────────────────────────────────────────────────────┘         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Sources de Contexte

### 1. RAG Knowledge Base (13,484 chunks)

| Source | Contenu | Poids |
|--------|---------|-------|
| **HackTricks** | Techniques pentesting, méthodologies | 1.0x |
| **Nuclei Templates** | 11,912 templates CVE/exploits | 1.0x |
| **Core Knowledge** | Patterns IDOR, auth bypass, etc. | 1.0x |
| **Cheatsheets** | OWASP, PayloadsAllTheThings | 1.0x |
| **Personal Reports** | Reports H1 personnels | **1.5x** |

### 2. Security Profile (fingerprinting passif)

Détecté automatiquement via headers/cookies:
- **WAF**: Cloudflare, AWS WAF, Akamai, Imperva, F5
- **CDN**: Cloudflare, CloudFront, Fastly, Akamai
- **Anti-Bot**: DataDome, PerimeterX, Akamai Bot Manager
- **Rate Limiting**: X-RateLimit-*, Retry-After

### 3. Target Context (depuis scope.json)

Détection automatique du type de cible:
- Healthcare → Focus IDOR patients/médecins, HIPAA
- Finance → Focus transactions, PCI-DSS
- E-commerce → Focus prix, coupons, commandes

---

## 🎯 TRIAGE - Prompts Détaillés

### System Prompt (Triage Tier 2)

```
You are Ghost-Hunter Triage (Tier 2), an expert security analyst who identifies REAL attack vectors, not just alerts.

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

## Rules
- ALWAYS scan body/params even if main alert is FP
- Pivot: "Not SQLi, BUT might be IDOR"
- attack_surface_hints go directly to Strategist
- Be specific: include the parameter name and suggested test
```

### User Prompt (Triage)

```
Analyze this HTTP request for security testing potential:

**Method:** POST
**URL:** https://example.com/api/users/update
**Path:** /api/users/update

**Query Parameters:**
None

**Headers:**
  - content-type: application/json
  - authorization: Bearer eyJ...
  - cookie: session=abc123

**Body:**
{"user_id": 12345, "email": "test@example.com", "role": "user"}

**🎯 Target Context:**
- Target Program: Example Healthcare Platform
- Description: Healthcare scheduling platform
- Data Sensitivity: CRITICAL (healthcare/medical data)
- Regulatory: GDPR, HDS, HIPAA-like
- Priority Focus: IDOR on patient/doctor IDs, medical data leaks

**Heuristic Signals:**
- Score: 75
- Score Breakdown:
  +20 param 'user_id' matches ID pattern
  +15 param 'role' is sensitive (mass assignment)
  +10 authenticated request
- Interesting Params: ['user_id', 'role']
- Potential Vulns: ['IDOR', 'Mass Assignment']

**🛡️ Target Security Profile:**
- WAF: Cloudflare (75% confidence)
- CDN: Cloudflare
- Anti-Bot: None detected
- Rate Limiting: Not detected
- Backend: Unknown
- Frontend: React
- Security Headers: 5/6
- Recommended Evasion: unicode_encoding, case_variation

Is this request worth deeper security testing? Consider the security profile when assessing difficulty.
```

---

## ⚔️ STRATEGIST - Prompts Détaillés

### System Prompt (Strategist)

```
You are Ghost-Hunter Strategist, an elite penetration tester with deep expertise in web security vulnerabilities.

## Your Mission
Create intelligent, targeted attack plans using your security knowledge and the RAG context provided.

## Output Format (JSON only, no markdown)
{
  "vuln_class": "IDOR|SQLi|XSS|SSRF|...",
  "tool": "custom",
  "reasoning": "Your security analysis and attack rationale",
  "injection_points": ["param1", "param2"],
  "payloads": [{"payload": "value", "encoding": "none|url|base64|unicode"}],
  "test_sequence": [{"order": 1, "action": "send_request", "description": "...", "expected_indicators": [...]}],
  "baseline_needed": true,
  "max_requests": 10,
  "delay_between_ms": 1000,
  "success_indicators": ["indicator1", "indicator2"],
  "evasion_techniques": []
}

## Payload Format Rule
- **payloads.payload = INJECTION VALUE only** (string/number)
- The payload REPLACES the value at injection_point, not the whole body
- Example: injection_point="user_id", payload="123" → body changes user_id to 123

## Your Expertise Areas
Use your knowledge and the RAG context to craft payloads for:
- **Access Control**: IDOR, BOLA, privilege escalation, JWT manipulation
- **Injection**: SQLi, NoSQLi, Command injection, LDAP, XPath, Template injection
- **Client-Side**: XSS (reflected/stored/DOM), CSRF, open redirects, clickjacking
- **Server-Side**: SSRF, XXE, file inclusion, path traversal, deserialization
- **Business Logic**: Race conditions, mass assignment, rate limit bypass, price manipulation

## Strategy Principles
1. **Analyze the context** - Understand the endpoint's purpose before attacking
2. **Use RAG knowledge** - Apply techniques from HackTricks, real CVEs, and proven payloads
3. **Adapt to WAF** - If WAF detected, use evasion techniques from your knowledge
4. **Chain vulnerabilities** - Consider how one finding can lead to another
5. **Be creative** - Don't just use generic payloads, craft context-aware tests
```

### User Prompt (Strategist)

```
## 📚 SECURITY KNOWLEDGE (from RAG - USE THIS!)
The following techniques, CVEs, and payloads are relevant to your attack:

### Relevant Knowledge:

**[1] hacktricks/src/pentesting-web/idor.md (idor)**
# IDOR (Insecure Direct Object Reference)

IDOR occurs when an application exposes internal object references without proper authorization checks.

## Testing Techniques:
1. **Horizontal Privilege Escalation**: Change user_id to access other users' data
2. **Vertical Privilege Escalation**: Access admin resources with user token
3. **Parameter Pollution**: Add duplicate parameters user_id=1&user_id=2
4. **UUID Prediction**: If UUIDs are v1, they may be predictable
5. **Hash-based IDs**: Try to reverse or predict hashed identifiers

## Bypass Techniques:
- Change HTTP method (GET→POST, POST→PUT)
- Add .json extension to path
- Wrap ID in array: {"id": [123]}
- Use negative numbers: -1, -999
- Try string variations: "123", "00123", "123.0"

**[2] cheatsheets/owasp/IDOR_Prevention.md (general)**
# IDOR Prevention Cheat Sheet

Common vulnerable patterns:
- /api/users/{id}/profile
- /download?file_id=123
- /orders/{order_id}

Always test:
- Sequential IDs (id-1, id+1)
- First ID (1, 0)
- Boundary values (-1, MAX_INT)

---

## 🎯 SUGGESTED PAYLOADS (from Knowledge Base)
- `12344` (id-1)
- `12346` (id+1)
- `1` (first/admin)
- `0` (edge case)
- `-1` (negative)
- `99999999` (non-existent)
- `12345.0` (type juggling)
- `"12345"` (string instead of int)

## 🛡️ TARGET SECURITY PROFILE
- **WAF**: Cloudflare (75% confidence)
- **CDN**: Cloudflare
- **Anti-Bot**: None detected
- **Rate Limiting**: Not detected
- **Recommended Evasion**: unicode_encoding, case_variation

## 📋 TARGET REQUEST

**Endpoint:** POST /api/users/update
**Host:** example.com
**Full URL:** https://example.com/api/users/update

**Query Parameters:**
None

**Headers:**
  - content-type: application/json
  - authorization: Bearer eyJ...

**Body:**
{"user_id": 12345, "email": "test@example.com", "role": "user"}

## 🔍 TRIAGE ANALYSIS
- **Suggested Vulnerabilities**: ['IDOR', 'Mass Assignment']
- **Confidence**: 85%
- **Reason**: user_id parameter allows potential horizontal privilege escalation
- **Test Phase**: safe

**Attack Surface Hints from Triage:**
  → IDOR potential on 'user_id' - test cross-account access
  → Mass Assignment on 'role' - try 'admin', 'staff', 'superuser'

## 🎯 YOUR TASK
Create an intelligent attack plan for: **IDOR, Mass Assignment**

Use the RAG knowledge above to craft creative, effective payloads.
Respond with valid JSON only (no markdown code blocks).
Remember: payloads.payload must be the INJECTION VALUE only, not the whole request body.
```

---

## ⚠️ Problèmes Identifiés

### 1. RAG pas toujours inclus
- Le contexte RAG est parfois vide ou non affiché
- Query time long (~30s premier chargement)
- min_score=0.4 peut filtrer des résultats pertinents

### 2. Prompts trop directifs (ANCIEN - corrigé)
- ❌ Avant: Exemples hardcodés dans system prompt
- ✅ Maintenant: System prompt générique, RAG fournit les techniques

### 3. Manque de créativité
- Le LLM suit trop les patterns donnés
- Pas assez de payloads context-aware
- Ne combine pas les vulns (chain attacks)

### 4. Pas de feedback loop
- Pas d'apprentissage des tests précédents
- Pas d'adaptation aux réponses reçues

---

## 💡 Questions pour Gemini

1. **Structure des prompts**: Le system prompt devrait-il être plus court/long? Plus de few-shot examples ou moins?

2. **RAG Integration**: Comment mieux intégrer le contexte RAG? Le mettre en premier est-il optimal?

3. **Payload Generation**: Comment encourager le LLM à générer des payloads plus créatifs et context-aware?

4. **Chain Attacks**: Comment pousser le LLM à considérer les vulnérabilités en chaîne?

5. **WAF Evasion**: Le LLM devrait-il générer les techniques d'évasion lui-même ou recevoir des suggestions?

6. **Output Format**: Le JSON structuré limite-t-il la créativité? Faut-il une phase "réflexion" avant le JSON?

7. **Two-Tier Architecture**: Le split Tier1/Tier2 est-il optimal ou faudrait-il un seul appel plus intelligent?

8. **Temperature Settings**: Triage=0.3, Strategist=0.5 - ces valeurs sont-elles appropriées?

---

## 📁 Fichiers Concernés

| Fichier | Rôle |
|---------|------|
| `ghost_hunter/core/brain/prompts.py` | System prompts + user prompt builders |
| `ghost_hunter/core/brain/triage.py` | Triage Tier 1 & 2 logic |
| `ghost_hunter/core/brain/strategist/engine.py` | Strategist principal |
| `ghost_hunter/core/brain/strategist/context.py` | RAG/Knowledge context builders |
| `ghost_hunter/core/rag/engine.py` | RAG Engine (semantic search) |
| `ghost_hunter/core/rag/vector_store.py` | ChromaDB vector store |

---

## 🔧 Configuration Actuelle

```yaml
# Triage
model: llama-3.1-8b-instant
temperature: 0.3
max_tokens: 500
rag_chunks: 10
rag_max_tokens: 1000

# Strategist  
model: llama-3.3-70b-versatile
temperature: 0.5
max_tokens: 2000
rag_chunks: 15
rag_max_tokens: 1500
```

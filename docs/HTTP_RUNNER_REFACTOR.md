# 🔧 HTTP Runner Refactoring Plan

## 📊 Analyse du fichier actuel

**Fichier:** `ghost_hunter/core/executor/http_runner.py`
**Lignes:** 1966 lignes 🚨 BEAUCOUP TROP

### Structure actuelle (monolithique)

```
http_runner.py (1966 lignes)
├── Imports & Constants (1-145)
│   ├── ERROR_PATTERNS dict (80-145) - Patterns de détection par vuln type
│   └── _safe_get_payload_value() helper (58-80)
│
├── CustomHTTPRunner class (146-1966) - HÉRITE de ToolWrapper
│   ├── DEFAULT_CONFIG (157-162)
│   ├── __init__ & config (164-195) - 9 attributs d'instance!
│   │   ├── self.follow_redirects
│   │   ├── self.verify_ssl
│   │   ├── self._fallback_user_agent
│   │   ├── self.rotate_ua_for_attacks
│   │   ├── self._ua_rotator (UserAgentRotator)
│   │   ├── self.use_proxy
│   │   ├── self._proxy_manager
│   │   ├── self.use_stealth
│   │   ├── self._stealth_browser
│   │   ├── self.waf_evasion
│   │   ├── self.security_profile
│   │   ├── self._waf_checker (WAFChecker)
│   │   ├── self._payload_mutator (PayloadMutator)
│   │   └── self._evasion_stats (dict)
│   │
│   ├── Template Injection Logic (197-303) ~106 lignes
│   │   ├── _inject_using_template()
│   │   └── _apply_template_injection()
│   │
│   ├── Logging & Properties (305-328)
│   │   ├── _log_result() - Utilise ai_logger!
│   │   └── is_available (property)
│   │
│   ├── Main Execution (329-443) ~114 lignes
│   │   └── execute() - CRITIQUE:
│   │       ├── Limite: max 10 payloads, max 5 injection points
│   │       ├── Navigation imbriquée: plan.request.request.request.request
│   │       ├── Proxy support via _proxy_manager
│   │       ├── Stealth mode branch
│   │       ├── self.executions.append(result) à la fin
│   │       └── dry_run support
│   │
│   ├── Payload Testing (444-693) ~249 lignes
│   │   └── _test_payload_with_details() - CRITIQUE:
│   │       ├── Gestion None payload
│   │       ├── Extraction défensive payload (dict/PayloadVariant/str)
│   │       ├── WAF evasion (_apply_waf_evasion)
│   │       ├── Encoding payload (_encode_payload)
│   │       ├── Build request (_build_request)
│   │       ├── Skip si injection_success=False!
│   │       ├── Debug logging extensif
│   │       ├── Masquage headers sensibles
│   │       ├── WAF block detection
│   │       ├── body_full + body_preview dans response
│   │       ├── Timeout → potential time-based vuln
│   │       └── _log_result() pour chaque test
│   │
│   ├── DUPLICATE: _test_payload (694-761) ~67 lignes
│   │   └── Version SIMPLIFIÉE de _test_payload_with_details
│   │       ⚠️ NON UTILISÉE? À vérifier et supprimer
│   │
│   ├── Stealth Mode (762-907) ~145 lignes
│   │   ├── _test_payload_stealth()
│   │   │   ├── Utilise get_stealth_browser()
│   │   │   ├── Extraction cookies depuis headers
│   │   │   ├── Merge cookies dict + header
│   │   │   └── captcha_solved tracking
│   │   └── _analyze_stealth_response()
│   │       └── Finding creation spécifique stealth
│   │
│   ├── Encoding (973-1003) ~30 lignes
│   │   └── _encode_payload() - 5 encodings:
│   │       ├── url (quote)
│   │       ├── double_url (double quote)
│   │       ├── html (entity encode)
│   │       ├── unicode (\uXXXX)
│   │       └── none (passthrough)
│   │
│   ├── WAF Evasion (1004-1146) ~142 lignes
│   │   ├── _apply_waf_evasion() - UTILISE:
│   │   │   ├── self._waf_checker.is_blocked_any()
│   │   │   ├── self._payload_mutator.auto_evade()
│   │   │   ├── apply_transform() depuis evasion module
│   │   │   └── self._evasion_stats tracking
│   │   ├── _get_waf_specific_transforms() - WAF-specific:
│   │   │   ├── Cloudflare transforms
│   │   │   ├── AWS WAF transforms
│   │   │   ├── Akamai transforms
│   │   │   └── Generic transforms par vuln_type
│   │   ├── get_evasion_stats() - public method ⚠️ INUTILISÉE
│   │   └── set_security_profile() - public method ⚠️ INUTILISÉE
│   │
│   ├── ⚠️ CODE MORT: _test_payload() (694-761) ~67 lignes
│   │   └── JAMAIS APPELÉE - à supprimer lors du refactoring
│   │
│   ├── Request Building (1156-1707) ~551 lignes 🚨 ÉNORME!
│   │   └── _build_request() - LOGIQUE CRITIQUE:
│   │       ├── Helper functions internes:
│   │       │   ├── has_header() case-insensitive
│   │       │   ├── get_header() case-insensitive
│   │       │   └── set_header() avec cleanup
│   │       ├── COOKIE HANDLING (1200-1232):
│   │       │   ├── Priorité: cookies dict > header existant
│   │       │   ├── Normalisation comma→semicolon
│   │       │   └── Warning si pas de cookies
│   │       ├── USER-AGENT STRATEGY (1237-1254):
│   │       │   ├── Auth request → GARDER UA original
│   │       │   └── Non-auth → ROTATION via _ua_rotator
│   │       ├── INJECTION QUERY PARAMS (1256-1263)
│   │       ├── INJECTION JSON BODY (1268-1353):
│   │       │   ├── Nested paths "foo.bar.baz"
│   │       │   ├── String values
│   │       │   ├── Numeric values
│   │       │   ├── Null/bool values
│   │       │   ├── Array values
│   │       │   └── Object values
│   │       ├── INJECTION FORM BODY (1356-1431):
│   │       │   ├── Strategy 1: Exact match
│   │       │   ├── Strategy 2: URL-encoded
│   │       │   ├── Strategy 3: Bracket-encoded
│   │       │   └── Strategy 4: Flexible array regex
│   │       ├── INJECTION HEADERS (1434-1439)
│   │       ├── INJECTION COOKIES (1442-1476)
│   │       ├── INJECTION PATH (1479-1687) - 6 CASES:
│   │       │   ├── CASE 0: Template mapping smart
│   │       │   ├── CASE 1: "profiles/{id}" pattern
│   │       │   ├── CASE 2: "{id}", "{token}" placeholders
│   │       │   ├── CASE 3: "id", "user_id" named
│   │       │   ├── CASE 4: "token", "session" named
│   │       │   ├── CASE 5: Literal string in URL
│   │       │   └── CASE 6: Fallback path segment
│   │       └── CLEANUP (1689-1707):
│   │           ├── Remove Content-Length header
│   │           └── Dedupe headers case-insensitive
│   │
│   ├── Response Analysis (1709-1787) ~78 lignes
│   │   └── _analyze_response():
│   │       ├── ResponseSignature creation
│   │       ├── Pattern matching via ERROR_PATTERNS
│   │       ├── Reflection detection (XSS)
│   │       ├── Timing anomaly detection
│   │       └── Finding creation
│   │
│   ├── WAF Block Detection (1789-1835) ~46 lignes
│   │   └── _is_waf_block_response():
│   │       ├── Cloudflare challenge/block
│   │       ├── AWS WAF
│   │       ├── Akamai WAF
│   │       ├── Imperva/Incapsula
│   │       ├── F5 ASM
│   │       └── Generic 403 with security headers
│   │
│   ├── Finding Helpers (1837-1948) ~111 lignes
│   │   ├── _is_potential_finding()
│   │   ├── _determine_severity() - par vuln type
│   │   ├── _calculate_confidence() - score 30-95
│   │   ├── _determine_subtype() - time-based/error-based/reflected
│   │   └── _generate_analysis() - text generation
│   │
│   └── Output Parsing (1950-1956)
│       └── parse_output() - JSON parsing
│
└── register_custom_http() (1958-1966) - Registration function
```

---

## 🚨 Problèmes identifiés

### 1. Fichier trop gros (1966 lignes)
- Impossible à maintenir
- Navigation difficile
- Tests unitaires impossibles

### 2. `_build_request()` = 551 lignes
- Fait TOUT: query params, JSON, form, headers, cookies, path
- 6 CASES différents pour l'injection path
- Logique de cookie complexe
- Doit être découpé

### 3. Code dupliqué/mort
- `_test_payload()` (694-761) = version simplifiée NON UTILISÉE
- Logique d'extraction payload répétée 5+ fois
- Masquage headers répété dans stealth et normal
- Debug logging excessif (peut être réduit)

### 4. Logique métier mélangée
- WAF evasion dans le runner HTTP
- Detection patterns hardcodés
- Severity calculation dans le même fichier
- AI logger appelé directement

### 5. Dépendances externes multiples
- `UserAgentRotator` - rotation UA
- `get_proxy_manager()` - residential proxies
- `WAFChecker` + `PayloadMutator` - evasion
- `get_stealth_browser()` - puppeteer
- `get_ai_logger()` - logging IA
- `apply_transform()` - transforms

---

## 🎯 Plan de refactoring COMPLET

### Nouvelle structure proposée

```
ghost_hunter/core/executor/
├── __init__.py                    # ~20 lignes - Exports publics
├── http_runner.py                 # ~300 lignes - Orchestrateur principal
│                                  # Garde: execute(), __init__, config
│                                  # Utilise: tous les modules ci-dessous
│
├── constants.py                   # ~80 lignes
│   ├── ERROR_PATTERNS             # Patterns de détection
│   ├── _safe_get_payload_value()  # Helper extraction payload
│   └── PAYLOAD_LIMITS             # max_payloads=10, max_injection_points=5
│
├── payload_encoder.py             # ~60 lignes
│   └── PayloadEncoder class
│       ├── encode(payload, encoding) → str
│       └── Supporte: url, double_url, html, unicode, none
│
├── request_builder/               # Module injection
│   ├── __init__.py               # ~15 lignes - Exports
│   ├── base.py                   # ~120 lignes
│   │   └── RequestBuilder class
│   │       ├── __init__(original_req)
│   │       ├── build(payload, injection_point) → (url, headers, body, success)
│   │       ├── _ensure_cookies()
│   │       ├── _ensure_user_agent(has_auth, ua_rotator)
│   │       └── _cleanup_headers()
│   ├── query_injector.py         # ~50 lignes
│   │   └── inject_query_params(params, injection_point, payload)
│   ├── body_injector.py          # ~180 lignes
│   │   └── BodyInjector class
│   │       ├── inject_json(body, body_json, injection_point, payload)
│   │       │   ├── Nested paths support
│   │       │   ├── String/number/null/bool/array/object
│   │       │   └── Preserve original format (regex replace)
│   │       └── inject_form(body, injection_point, payload)
│   │           ├── Strategy 1: Exact match
│   │           ├── Strategy 2: URL-encoded
│   │           ├── Strategy 3: Bracket-encoded
│   │           └── Strategy 4: Flexible array regex
│   ├── header_injector.py        # ~80 lignes
│   │   ├── inject_header(headers, injection_point, payload)
│   │   └── inject_cookie(cookie_header, cookies_dict, injection_point, payload)
│   └── path_injector.py          # ~250 lignes
│       └── PathInjector class
│           ├── inject(url, original_req, injection_point, payload) → (new_url, success)
│           ├── _inject_using_template()      # CASE 0
│           ├── _apply_template_injection()   # Helper for CASE 0
│           ├── _inject_resource_template()   # CASE 1: "profiles/{id}"
│           ├── _inject_placeholder()         # CASE 2: "{id}", "{token}"
│           ├── _inject_named_id()            # CASE 3: "id", "user_id"
│           ├── _inject_named_token()         # CASE 4: "token", "session"
│           ├── _inject_literal()             # CASE 5: literal string
│           └── _inject_fallback()            # CASE 6: path segment
│
├── response_analyzer.py           # ~150 lignes
│   └── ResponseAnalyzer class
│       ├── analyze(response, response_time, vuln_class, payload, injection_point, url)
│       ├── _create_signature()
│       ├── _match_error_patterns()
│       ├── _detect_reflection()
│       └── _detect_timing_anomaly()
│
├── waf_detector.py                # ~100 lignes
│   └── WAFBlockDetector class
│       ├── is_blocked(response) → (bool, provider)
│       └── Detect: Cloudflare, AWS, Akamai, Imperva, F5, Generic
│
├── finding_factory.py             # ~120 lignes
│   └── FindingFactory class
│       ├── create(signature, vuln_class, payload, url, ...) → Finding
│       ├── _determine_severity()
│       ├── _calculate_confidence()
│       ├── _determine_subtype()
│       └── _generate_analysis()
│
├── stealth_executor.py            # ~180 lignes
│   └── StealthExecutor class
│       ├── execute(original_req, vuln_class, payload, injection_point)
│       ├── _extract_cookies()
│       └── _analyze_response()
│
└── test_executor.py               # ~200 lignes (NOUVEAU)
    └── PayloadTestExecutor class  # Centralise la logique de test
        ├── test_single(client, original_req, vuln_class, payload, injection_point)
        ├── _extract_payload_info()
        ├── _apply_waf_evasion()  # Délègue à evasion module
        ├── _mask_sensitive_headers()
        └── _log_result()  # Délègue à ai_logger
```

### Estimation par fichier (RÉVISÉE)

| Fichier | Lignes | Responsabilité |
|---------|--------|----------------|
| `http_runner.py` | ~300 | Orchestrateur, execute(), __init__ |
| `constants.py` | ~80 | ERROR_PATTERNS, helpers, limits |
| `payload_encoder.py` | ~60 | Encoding payloads |
| `request_builder/base.py` | ~120 | Cookie/UA logic, coordination |
| `request_builder/query_injector.py` | ~50 | Query params |
| `request_builder/body_injector.py` | ~180 | JSON + form |
| `request_builder/header_injector.py` | ~80 | Headers + cookies |
| `request_builder/path_injector.py` | ~250 | 6 cases path |
| `response_analyzer.py` | ~150 | Analyse + signature |
| `waf_detector.py` | ~100 | WAF block detection |
| `finding_factory.py` | ~120 | Finding creation |
| `stealth_executor.py` | ~180 | Stealth browser mode |
| `test_executor.py` | ~200 | Logique test centralisée |
| **TOTAL** | **~1870** | vs 1966 actuellement |

---

## 🗑️ CODE MORT À SUPPRIMER

### Identifié lors de l'analyse:

| Code | Lignes | Raison suppression |
|------|--------|---------------------|
| `_test_payload()` | 694-761 (~67 lignes) | **JAMAIS APPELÉE** - doublon de `_test_payload_with_details()` |
| `get_evasion_stats()` | 1147-1149 | API publique **JAMAIS UTILISÉE** dans le projet |
| `set_security_profile()` | 1151-1154 | API publique **JAMAIS UTILISÉE** dans le projet |
| `register_custom_http()` | 1958-1966 | Fonction module **JAMAIS APPELÉE** (exportée mais inutilisée) |

**Total code mort: ~80 lignes**

### Vérification effectuée:
```bash
# _test_payload() - 0 appels trouvés
grep -r "await self\._test_payload(" ghost_hunter/  # Aucun résultat

# get_evasion_stats() - uniquement définie, jamais appelée
grep -r "get_evasion_stats" ghost_hunter/  # Seulement la définition

# set_security_profile() - uniquement définie, jamais appelée  
grep -r "set_security_profile" ghost_hunter/  # Seulement la définition

# register_custom_http() - exportée mais jamais appelée
grep -r "register_custom_http()" ghost_hunter/  # Aucun appel
```

---

## 📋 TODO List détaillée

### Phase 0: Nettoyage code mort (FAIRE EN PREMIER) ⚡ ✅ COMPLÉTÉ

- [x] **0.1** Supprimer `_test_payload()` (lignes 694-761)
  - [x] Vérifier une dernière fois qu'aucun appel n'existe
  - [x] Supprimer la méthode (~67 lignes)
  - [x] Lancer les tests existants

- [x] **0.2** Supprimer API publiques inutilisées
  - [x] Supprimer `get_evasion_stats()` (lignes 1147-1149)
  - [x] Supprimer `set_security_profile()` (lignes 1151-1154)
  - [x] Mettre à jour `__init__.py` si nécessaire

- [x] **0.3** Supprimer `register_custom_http()` (lignes 1958-1966)
  - [x] Retirer de `__init__.py` exports
  - [x] Vérifier que main.py instancie directement `CustomHTTPRunner`

- [ ] **0.4** Nettoyer logs de debug excessifs (optionnel, pour plus tard)
  - [ ] Identifier les `logger.info(f"🔍 [HTTP_RUNNER]` inutiles
  - [ ] Convertir en `logger.debug()` ou supprimer

**Résultat Phase 0: 1966 → 1880 lignes (-86 lignes) ✅**

---

### Phase 1: Préparation (avant refactoring) ✅ COMPLÉTÉ

- [x] **1.1** Créer `tests/unit/test_http_runner_critical.py` (42 tests)
  - [x] Test `_safe_get_payload_value()` avec tous les types (10 tests)
  - [x] Test cookie handling (4 tests)
  - [x] Test User-Agent strategy (3 tests)
  - [x] Test injection success tracking (3 tests)
  - [x] Test path injection (3 tests)
  - [x] Test JSON nested paths (2 tests)
  - [x] Test WAF detection (5 tests)
  - [x] Test encoding (6 tests)
  - [x] Test limits (2 tests)
  - [x] Test finding creation (3 tests)

- [x] **1.2** Bug fix découvert et corrigé
  - [x] `_safe_get_payload_value()` ne gérait pas bien `payload.payload = None`
  - [x] Fix appliqué: check explicite pour None avant de tomber dans else

**Résultat Phase 1: 75 tests passent (33 existants + 42 nouveaux) ✅**

---

### Phase 2: Extraction des constantes ✅ COMPLÉTÉ

- [x] **2.1** Créer `constants.py` (151 lignes)
  - [x] Déplacer `ERROR_PATTERNS`
  - [x] Déplacer `_safe_get_payload_value()`
  - [x] Ajouter `MAX_PAYLOADS = 10`
  - [x] Ajouter `MAX_INJECTION_POINTS = 5`
  - [x] Ajouter `TIME_BASED_VULN_TYPES`
  - [x] Ajouter `VULN_SEVERITY_MAP`

- [x] **2.2** Mise à jour imports
  - [x] http_runner.py importe depuis constants.py
  - [x] __init__.py exporte ERROR_PATTERNS, _safe_get_payload_value
  - [x] Tests mis à jour pour importer depuis constants.py

**Résultat Phase 2: 1880 → 1800 lignes (-80 lignes), constants.py = 151 lignes ✅**

---

### Phase 3: Extraction payload encoder ✅ COMPLÉTÉ

- [x] **3.1** Créer `payload_encoder.py` (172 lignes)
  - [x] Extraire `_encode_payload()` → `PayloadEncoder.encode()`
  - [x] Ajouter méthode `decode()` pour tests
  - [x] Gérer tous les types (dict, PayloadVariant, str, None)
  - [x] Support 5 encodings: none, url, double_url, html, unicode

- [x] **3.2** http_runner.py mis à jour
  - [x] Import PayloadEncoder
  - [x] `_encode_payload()` délègue à `PayloadEncoder.encode()`

**Résultat Phase 3: 1800 → 1774 lignes (-26 lignes), payload_encoder.py = 172 lignes ✅**

---

### Phase 4: Extraction WAF detector ✅ COMPLÉTÉ

- [x] **4.1** Créer `waf_detector.py` (191 lignes)
  - [x] Extraire `_is_waf_block_response()` → `WAFDetector.is_blocked()`
  - [x] Support Cloudflare (Managed Challenge, WAF Block)
  - [x] Support AWS WAF
  - [x] Support Akamai WAF/Bot Manager
  - [x] Support Imperva/Incapsula
  - [x] Support F5 ASM
  - [x] Support Generic WAF signatures

- [x] **4.2** http_runner.py mis à jour
  - [x] Import WAFDetector
  - [x] `_is_waf_block_response()` délègue à `WAFDetector.is_blocked()`

**Résultat Phase 4: 1774 → 1738 lignes (-36 lignes), waf_detector.py = 191 lignes ✅**

---

### Phase 5: Extraction Finding factory ✅ COMPLÉTÉ

- [x] **5.1** Créer `finding_factory.py` (226 lignes)
  - [x] Extraire `_determine_severity()`
  - [x] Extraire `_calculate_confidence()`
  - [x] Extraire `_determine_subtype()`
  - [x] Extraire `_generate_analysis()`
  - [x] Créer `FindingFactory.create()` qui combine tout
  - [x] Ajout `SEVERITY_MAP` étendu

- [x] **5.2** http_runner.py mis à jour
  - [x] Import FindingFactory
  - [x] 4 méthodes délèguent à FindingFactory

**Résultat Phase 5: 1738 → 1688 lignes (-50 lignes), finding_factory.py = 226 lignes ✅**

---

### Phase 6: Extraction Response analyzer ✅ COMPLÉTÉ

- [x] **6.1** Créer `response_analyzer.py` (236 lignes)
  - [x] Extraire `_analyze_response()` → `ResponseAnalyzer.analyze()`
  - [x] Extraire `_is_potential_finding()` → `ResponseAnalyzer.is_potential_finding()`
  - [x] Créer `ResponseAnalyzer.build_signature()`
  - [x] Intégrer FindingFactory pour création findings
  - [x] Constantes: `TIME_BASED_VULN_TYPES`, `TIMING_ANOMALY_THRESHOLD_MS`, `ERROR_STATUS_CODES`

- [x] **6.2** http_runner.py mis à jour
  - [x] Import ResponseAnalyzer
  - [x] `_analyze_response()` délègue à `ResponseAnalyzer.analyze()`
  - [x] Suppression méthodes délégation inutiles: `_is_potential_finding`, `_determine_severity`, `_calculate_confidence`, `_determine_subtype`, `_generate_analysis`
  - [x] Nettoyage imports inutiles: `hashlib`, `ResponseSignature`

- [x] **6.3** Tests mis à jour
  - [x] test_http_runner.py: Tests utilisent `ResponseAnalyzer.is_potential_finding()` et `FindingFactory.*`
  - [x] test_http_runner_critical.py: Tests utilisent `FindingFactory.determine_subtype()` et `FindingFactory.generate_analysis()`

**Résultat Phase 6: 1688 → 1567 lignes (-121 lignes), response_analyzer.py = 236 lignes ✅**
**Total extraction: 1966 → 1567 lignes (-399 lignes, -20.3%) 🎉**

---

### Phase 7: Extraction Request builder (LE PLUS GROS) ✅ COMPLETE

- [x] **7.1** Créer `request_builder/__init__.py`
  - [x] Export `RequestBuilder`, `QueryInjector`, `BodyInjector`, `HeaderInjector`, `CookieInjector`, `PathInjector`

- [x] **7.2** Créer `request_builder/base.py` (~210 lignes)
  - [x] `RequestBuilder` class avec:
    - [x] `__init__(original_req, fallback_ua, ua_rotator, rotate_ua)`
    - [x] `build(original_req, payload, injection_point)` → coordonne les injectors
    - [x] `_ensure_cookies()` - logique cookie critique (dict priority > header)
    - [x] `_ensure_user_agent()` - logique UA (preserve for auth, rotate otherwise)
    - [x] `_cleanup_headers()` - Content-Length removal, deduplication

- [x] **7.3** Créer `request_builder/query_injector.py` (~60 lignes)
  - [x] `QueryInjector.inject(url, query_params, injection_point, payload)`
  - [x] Retourne `(new_url, success: bool)`

- [x] **7.4** Créer `request_builder/body_injector.py` (~250 lignes)
  - [x] `BodyInjector` class avec:
    - [x] `inject_json(body, body_json, injection_point, payload)` - nested paths "foo.bar.baz"
    - [x] `inject_form(body, injection_point, payload)` - URL encoded
  - [x] Gérer les 4 strategies form (exact, encoded, bracket, flexible array regex)

- [x] **7.5** Créer `request_builder/header_injector.py` (~150 lignes)
  - [x] `HeaderInjector.inject(headers, injection_point, payload)`
  - [x] `CookieInjector.inject(headers, cookies, injection_point, payload)`

- [x] **7.6** Créer `request_builder/path_injector.py` (~350 lignes)
  - [x] `PathInjector` class avec 6 CASES:
    - [x] `_inject_case_0_template()` - Smart template mapping with path_template
    - [x] `_inject_case_1_resource_template()` - "profiles/{id}" pattern
    - [x] `_inject_case_2_placeholder()` - "{id}", "{token}" placeholders
    - [x] `_inject_case_3_named_id()` - "id", "user_id" named
    - [x] `_inject_case_4_named_token()` - "token", "session" named
    - [x] `_inject_case_5_literal()` - literal string in URL
    - [x] `_inject_case_6_fallback()` - path segment extraction

- [x] **7.7** Tests `request_builder/` - Validated via existing 75 http_runner tests
  - [x] All 75 tests passing (test_http_runner.py + test_http_runner_critical.py)

**Résultat Phase 7: 1567 → 1039 lignes (-528 lignes), request_builder/ = 1020 lignes total ✅**
**Total extraction: 1966 → 1039 lignes (-927 lignes, -47.2%) 🎉🎉**

---

### Phase 8: Extraction Stealth executor

- [ ] **8.1** Créer `stealth_executor.py`
  - [x] Déplacer `_test_payload_stealth()`
  - [x] Déplacer `_analyze_stealth_response()`
  - [x] Créer `StealthExecutor` class

- [x] **8.2** Tests `stealth_executor.py`
  - [x] Validation via 75 tests http_runner existants

**Résultat Phase 8: 1039 → 835 lignes (-204 lignes), stealth_executor.py = 316 lignes ✅**
**Total extraction: 1966 → 835 lignes (-1131 lignes, -57.5%) 🎉🎉🎉**

---

### Phase 9: Refactoring http_runner.py

- [ ] **9.1** Simplifier `http_runner.py`
  - [x] Garder `CustomHTTPRunner` class
  - [x] Garder `execute()` comme orchestrateur
  - [x] Remplacer `_test_payload_with_details()` par composition
  - [x] **SUPPRIMER** `_test_payload()` (déjà supprimé précédemment)
  - [x] Utiliser les nouveaux modules

- [x] **9.2** Vérifier aucune régression
  - [x] 75 tests http_runner passent
  - [x] Test intégration complet

### Phase 10: Cleanup ✅ COMPLETE

- [x] **10.1** Supprimer code mort
  - [x] `_inject_using_template()` - déplacé dans PathInjector
  - [x] `_apply_template_injection()` - déplacé dans PathInjector
  - [x] Imports inutilisés nettoyés (urlencode, quote, DiffResult, register_tool, etc.)

- [ ] **10.2** Documentation
  - [x] Modules auto-documentés avec docstrings
  - [ ] README dans `executor/` (optionnel)

**Résultat Phase 9-10: 835 → 724 lignes (-111 lignes) ✅**
**TOTAL FINAL: 1966 → 724 lignes (-1242 lignes, -63.2%) 🎉🎉🎉🎉**

---

## 📊 Résumé final du refactoring

### Modules extraits

| Module | Lignes | Responsabilité |
|--------|--------|----------------|
| `http_runner.py` | 724 | Orchestrateur principal |
| `constants.py` | 151 | ERROR_PATTERNS, limits, helpers |
| `payload_encoder.py` | 172 | Encoding payloads (url, double_url, html, unicode) |
| `waf_detector.py` | 191 | Détection blocks WAF |
| `finding_factory.py` | 226 | Création Finding objects |
| `response_analyzer.py` | 236 | Analyse réponses HTTP |
| `stealth_executor.py` | 316 | Puppeteer stealth mode |
| **request_builder/** | | |
| ├─ `__init__.py` | 21 | Exports |
| ├─ `base.py` | 233 | RequestBuilder orchestrator |
| ├─ `query_injector.py` | 60 | Injection query params |
| ├─ `body_injector.py` | 281 | Injection JSON + form |
| ├─ `header_injector.py` | 155 | Injection headers + cookies |
| └─ `path_injector.py` | 452 | 6 cas d'injection path |
| **TOTAL EXTRAIT** | ~2,294 | |

### Progression par phase

| Phase | Lignes avant | Lignes après | Changement |
|-------|--------------|--------------|------------|
| Initial | 1966 | - | - |
| Phases 0-5 | 1966 | 1688 | -278 (-14%) |
| Phase 6 | 1688 | 1567 | -121 (-7%) |
| Phase 7 | 1567 | 1039 | -528 (-34%) |
| Phase 8 | 1039 | 835 | -204 (-20%) |
| Phases 9-10 | 835 | 724 | -111 (-13%) |
| **FINAL** | **1966** | **724** | **-1242 (-63.2%)** |

---

## ⚠️ Points critiques - NE PAS RÉGRESSER

### 1. Cookie handling (CRITIQUE)
```python
# PRIORITÉ: 1) cookies dict (le plus fiable), 2) header existant
# Format: "key1=val1; key2=val2" (semicolon, PAS comma!)
# Normalisation automatique comma→semicolon
# Warning si aucun cookie disponible
```

### 2. User-Agent strategy (CRITIQUE)
```python
# Auth request (cookie/authorization présent) → GARDER UA original
#   Sinon la session sera invalidée!
# Non-auth request → ROTATION via _ua_rotator pour éviter fingerprinting
```

### 3. Injection success tracking
```python
# TOUJOURS retourner (url, headers, body, injection_success)
# Si injection_success=False → SKIP request (évite rate limiting/replay detection)
# Log warning mais ne pas crasher
```

### 4. Nested JSON paths
```python
# "foo.bar.baz" → chercher "baz" comme clé finale
# Ne pas casser le JSON existant (utiliser regex replace, pas json.dumps)
# Garder l'ordre et le formatage original
```

### 5. WAF evasion flow
```python
# 1. Check si payload blocked via _waf_checker.is_blocked_any()
# 2. Si oui, tenter _payload_mutator.auto_evade()
# 3. Si échoue, tenter apply_transform() avec WAF-specific transforms
# 4. Tracker stats: original_blocked, evaded, failed
```

### 6. Payload extraction défensive
```python
# Gérer: None, dict, PayloadVariant, str, int, float, autres
# Ne JAMAIS crasher sur .payload ou .encoding
# Toujours avoir un fallback vers ""
```

### 7. Limites hardcodées
```python
plan.payloads[:10]        # Max 10 payloads
plan.injection_points[:5]  # Max 5 injection points
# Total max: 50 requêtes par execute()
```

### 8. Navigation requête originale
```python
# Structure imbriquée: plan.request.request.request.request
# TriageDecision → ScoredRequest → FilteredRequest → InterceptedRequest
# NE PAS CHANGER cette navigation!
```

### 9. Attributs utilisés sur original_req
```python
original_req.method
original_req.url
original_req.path
original_req.host
original_req.headers  # dict
original_req.cookies  # dict
original_req.query_params  # dict
original_req.body  # str
original_req.body_json  # dict parsed
original_req.get_endpoint_template()  # method → path_template
```

### 10. Response details structure
```python
detail = {
    "payload": str,
    "injection_point": str,
    "encoding": str,
    "waf_evasion": dict | None,
    "request": {
        "method": str,
        "url": str,
        "headers": dict (masked),
        "headers_count": int,
        "has_cookie": bool,
        "has_auth": bool,
        "body_preview": str,
    },
    "response": {
        "status_code": int,
        "headers": dict,
        "body_preview": str (2000 chars),
        "body_full": str,
        "body_length": int,
        "waf_blocked": bool,
        "waf_provider": str | None,
    },
    "response_time_ms": float,
    "finding": dict | None,
    "error": str | None,
    "skipped": bool (optional),
    "stealth_mode": bool (optional),
    "captcha_solved": bool (optional),
}
```

### 11. Finding structure attendue
```python
Finding(
    endpoint=url,
    method=str,
    vuln_type=vuln_class,
    vuln_subtype="time-based"|"error-based"|"reflected"|"unknown",
    severity=FindingSeverity,
    status=FindingStatus.NEW,
    confidence=30-95,
    request_sent=str,
    response_received=str[:2000],
    payload_successful=str,
    ai_analysis=str,
    reproduction_steps=[str],
    tool_used="custom_http"|"stealth_browser",
)
```

### 12. Timeout = potential vulnerability
```python
# Si TimeoutException ET vuln_class in ["SQLI", "CMDI", "RCE"]:
#   → Créer Finding avec subtype="time-based", confidence=40
# Sinon: juste return None
```

### 13. Stealth mode spécifique
```python
# Utilise get_stealth_browser() (Puppeteer)
# Cookies: extraits depuis headers + merged avec original_req.cookies
# Captcha bypass tracking
# Response analysis différente (_analyze_stealth_response)
```

### 14. AI Logger integration
```python
# Appeler _log_result() pour CHAQUE test (success ou fail)
# ai_logger.log_result(endpoint, method, vuln_class, payload, injection_point, result, status_code, evidence, host)
```

### 15. Headers cleanup final
```python
# 1. Supprimer Content-Length (httpx recalcule)
# 2. Dédupliquer headers case-insensitive (garder le dernier)
```

---

## 🧪 Tests critiques à ne pas oublier

```python
# ═══ Tests payload extraction ═══
def test_payload_none():
    """payload=None ne doit pas crasher."""

def test_payload_empty_encoding():
    """encoding='' ou None doit être traité comme 'none'."""

def test_payload_dict():
    """payload={'payload': 'x', 'encoding': 'url'} doit être extrait."""

def test_payload_variant():
    """PayloadVariant(payload='x') doit être extrait."""

# ═══ Tests response handling ═══
def test_response_none_in_detail():
    """detail['response']=None ne doit pas crasher .get()."""

def test_detail_structure_complete():
    """Vérifier que tous les champs du detail sont présents."""

# ═══ Tests cookies ═══
def test_cookies_from_dict():
    """Cookies construits depuis cookies dict."""

def test_cookies_comma_to_semicolon():
    """Normalisation virgule→point-virgule."""

def test_cookies_preserved_on_auth():
    """Cookies originaux préservés pour requêtes auth."""

# ═══ Tests User-Agent ═══
def test_ua_preserved_with_auth():
    """UA original gardé si cookie/auth présent."""

def test_ua_rotated_without_auth():
    """UA rotated si pas d'auth."""

# ═══ Tests path injection (6 cases) ═══
def test_path_case0_template_mapping():
    """/users/{id}/sessions/{token} avec {token}."""

def test_path_case1_resource_template():
    """profiles/{id} → profiles/123 → profiles/PAYLOAD."""

def test_path_case2_placeholder_id():
    """{id} remplace premier numérique."""

def test_path_case2_placeholder_token():
    """{token} remplace premier alphanumérique non-numérique."""

def test_path_case3_named_id():
    """'user_id' remplace premier numérique."""

def test_path_case4_named_token():
    """'session' remplace premier token alphanumérique."""

def test_path_case5_literal():
    """String littérale dans URL."""

def test_path_case6_fallback():
    """Fallback: segment après resource name."""

# ═══ Tests JSON injection ═══
def test_json_simple_string():
    """{"key": "value"} → {"key": "PAYLOAD"}."""

def test_json_number():
    """{"id": 123} → {"id": PAYLOAD}."""

def test_json_nested():
    """{"foo": {"bar": "x"}} avec 'foo.bar' → {"foo": {"bar": "PAYLOAD"}}."""

def test_json_array():
    """{"items": [1,2,3]} → {"items": ["PAYLOAD"]}."""

def test_json_preserve_format():
    """Ne pas casser le formatage original (indentation, ordre)."""

# ═══ Tests form injection ═══
def test_form_exact_match():
    """key=value avec key exact."""

def test_form_url_encoded():
    """key%5B%5D avec key[]."""

def test_form_bracket_notation():
    """foo[0][bar] avec foo[].bar."""

# ═══ Tests WAF evasion ═══
def test_waf_evasion_blocked():
    """Payload bloqué → tentative d'évasion."""

def test_waf_evasion_success():
    """Évasion réussie → payload transformé."""

def test_waf_evasion_stats():
    """Stats original_blocked, evaded, failed."""

# ═══ Tests WAF detection ═══
def test_detect_cloudflare_challenge():
    """403 + cf-ray + 'just a moment'."""

def test_detect_aws_waf():
    """403 + x-amzn-requestid."""

def test_detect_akamai():
    """403 + akamai dans headers."""

# ═══ Tests finding creation ═══
def test_finding_sqli_error_based():
    """Pattern SQL trouvé → Finding HIGH."""

def test_finding_xss_reflection():
    """Payload réfléchi → Finding MEDIUM."""

def test_finding_timeout_time_based():
    """Timeout sur SQLI → Finding time-based."""

# ═══ Tests stealth mode ═══
def test_stealth_cookies_merge():
    """Cookies depuis headers + dict mergés."""

def test_stealth_captcha_tracking():
    """captcha_solved dans response."""

# ═══ Tests intégration ═══
def test_execute_dry_run():
    """dry_run=True → pas de requête."""

def test_execute_max_limits():
    """Max 10 payloads × 5 injection points = 50 requêtes."""

def test_execute_results_appended():
    """self.executions.append(result) appelé."""
```

---

## ⏱️ Estimation temps (RÉVISÉE)

| Phase | Temps estimé |
|-------|--------------|
| **Phase 0: Nettoyage code mort** | **30min** |
| Phase 1: Tests existants | 2h |
| Phase 2: constants.py | 15min |
| Phase 3: payload_encoder.py | 30min |
| Phase 4: waf_detector.py | 45min |
| Phase 5: finding_factory.py | 45min |
| Phase 6: response_analyzer.py | 1h |
| Phase 7: request_builder/ | 3h |
| Phase 8: stealth_executor.py | 1h |
| Phase 9: refactoring http_runner.py | 1h30 |
| Phase 10: cleanup | 30min |
| **TOTAL** | **~11h30** |

---

## 🔄 Ordre d'exécution recommandé

```
0. Phase 0 (cleanup) ─────► Supprimer code mort AVANT tout
          │
1. Phase 1 (tests) ────► Filet de sécurité AVANT refactoring
          │
2. Phase 2 (constants) ────► Pas de dépendances
          │
3. Phase 3 (encoder) ─────► Dépend de constants
          │
4. Phase 4 (waf_detector) ─► Pas de dépendances
          │
5. Phase 5 (finding) ─────► Pas de dépendances
          │
6. Phase 6 (analyzer) ────► Dépend de 4, 5
          │
7. Phase 7 (builder) ─────► LE PLUS CRITIQUE, dépend de 3
          │
8. Phase 8 (stealth) ─────► Dépend de 6, 7
          │
9. Phase 9 (http_runner) ─► Dépend de TOUT
          │
10. Phase 10 (cleanup) ───► Fin
```

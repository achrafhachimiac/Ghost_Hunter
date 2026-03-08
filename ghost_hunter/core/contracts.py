"""
Ghost-Hunter Contracts
======================
Définit les structures de données entre chaque brique.
TOUTES les briques DOIVENT respecter ces contrats.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
import hashlib
import uuid


# ═══════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════

class HttpMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class Priority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(Enum):
    NEW = "new"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    REPORTED = "reported"
    DUPLICATE = "duplicate"
    FIXED = "fixed"


class TestPhase(Enum):
    SAFE = "safe"           # XSS reflected, info disclosure
    MEDIUM = "medium"       # IDOR, SQLi careful
    RISKY = "risky"         # Race condition, file upload


class ChainStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


# ═══════════════════════════════════════════════════════════════
# WAF EVASION CONTRACTS
# Source: WAF patterns analysis (F5, Cloudflare, etc.)
# Destination: Strategist payload generation
# ═══════════════════════════════════════════════════════════════

@dataclass
class WAFPattern:
    """Pattern de détection WAF extrait des règles F5/Cloudflare."""
    
    id: str                              # "f5_200000073"
    vuln_type: str                       # "sqli", "xss", "cmdi", "ssti", "ssrf"
    pattern: str                         # Regex pattern
    flags: str = ""                      # "i" (case insensitive), "s" (dotall), etc.
    risk: int = 3                        # 1-3 (3 = critical)
    description: str = ""                # Human readable description
    location: str = "parameter"          # "parameter", "header", "uri", "body"
    source: str = "f5"                   # "f5", "cloudflare", "modsecurity", "custom"


@dataclass
class Transform:
    """Transformation pour éviter la détection WAF."""
    
    name: str                            # "case_swap", "inline_comment", etc.
    vuln_types: List[str] = field(default_factory=list)  # ["sqli", "xss"]
    description: str = ""                # Human readable
    preserves_semantic: bool = True      # Le payload reste fonctionnel


@dataclass
class Mutation:
    """Résultat d'une mutation de payload."""
    
    original: str                        # Payload original
    mutated: str                         # Payload muté
    transform: str                       # Nom de la transformation appliquée
    blocked_by: List[str] = field(default_factory=list)  # Patterns qui bloquent encore
    evades: List[str] = field(default_factory=list)      # Patterns évités


@dataclass
class EvasionResult:
    """Résultat complet de l'évasion WAF."""
    
    payload: str                         # Payload original
    mutations: List[Mutation] = field(default_factory=list)  # Toutes les mutations
    best_mutation: Optional['Mutation'] = None  # Meilleure mutation trouvée
    all_blocked: bool = True             # True si aucune mutation n'évite le WAF


# ═══════════════════════════════════════════════════════════════
# CONTRAT 1: Proxy → Scope Filter
# Source: mitmproxy addon
# Destination: scope_filter.py
# ═══════════════════════════════════════════════════════════════

@dataclass
class InterceptedRequest:
    """Requête brute interceptée par le proxy."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    method: str = "GET"
    url: str = ""
    host: str = ""
    path: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    body_json: Optional[Dict] = None
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    source_ip: str = "127.0.0.1"
    content_type: str = ""  # Content-Type header
    source: str = "proxy"   # Origin: "proxy" (mitmproxy), "burp", "har", "manual"
    
    # Response (si disponible)
    response_status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    response_time_ms: Optional[float] = None
    
    def get_endpoint_template(self) -> str:
        """Retourne le path avec IDs généralisés: /api/users/123 → /api/users/{id}"""
        import re
        template = self.path
        # Remplacer les UUIDs EN PREMIER (avant les IDs numériques)
        template = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{uuid}',
            template,
            flags=re.IGNORECASE
        )
        # Remplacer les IDs numériques
        template = re.sub(r'/\d+', '/{id}', template)
        return template


# ═══════════════════════════════════════════════════════════════
# CONTRAT 2: Scope Filter → Dedup
# Source: scope_filter.py
# Destination: dedup.py
# ═══════════════════════════════════════════════════════════════

@dataclass
class FilteredRequest:
    """Requête validée comme étant in-scope."""
    
    request: InterceptedRequest = field(default_factory=InterceptedRequest)
    in_scope: bool = False
    scope_match: str = ""        # Pattern qui a matché
    domain: str = ""             # Domaine extrait
    is_api: bool = False         # Est-ce un endpoint API?
    is_static: bool = False      # Asset statique? (js, css, images)
    filter_reason: Optional[str] = None  # Raison du filtrage (static_file, out_of_scope, etc.)
    
    def __post_init__(self):
        if not self.domain and self.request:
            self.domain = self.request.host


# ═══════════════════════════════════════════════════════════════
# CONTRAT 3: Dedup → Heuristiques
# Source: dedup.py
# Destination: heuristics.py
# ═══════════════════════════════════════════════════════════════

@dataclass
class DedupResult:
    """Résultat de la déduplication."""
    
    request: FilteredRequest = field(default_factory=FilteredRequest)
    is_duplicate: bool = False
    dedup_hash: str = ""
    first_seen: Optional[float] = None
    seen_count: int = 1
    
    def compute_hash(self) -> str:
        """Calcule le hash de déduplication."""
        req = self.request.request
        components = [
            req.method,
            req.get_endpoint_template(),
            ",".join(sorted(req.query_params.keys())),
            "auth" if "authorization" in [h.lower() for h in req.headers.keys()] else "anon"
        ]
        hash_input = "|".join(components)
        self.dedup_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
        return self.dedup_hash


# ═══════════════════════════════════════════════════════════════
# CONTRAT 4: Heuristiques → IA Triage
# Source: heuristics.py
# Destination: triage.py
# ═══════════════════════════════════════════════════════════════

@dataclass
class HeuristicSignal:
    """Un signal heuristique détecté."""
    name: str = ""
    score: int = 0
    reason: str = ""


@dataclass
class ScoredRequest:
    """Requête avec score de suspicion heuristique."""
    
    request: FilteredRequest = field(default_factory=FilteredRequest)
    score: int = 0                          # 0-100
    signals: List[HeuristicSignal] = field(default_factory=list)
    dedup_hash: str = ""
    priority: Priority = Priority.LOW
    
    # Paramètres intéressants détectés
    interesting_params: List[str] = field(default_factory=list)
    potential_vulns: List[str] = field(default_factory=list)
    
    # Score breakdown for AI prompt (human-readable explanation)
    score_breakdown: str = ""
    
    def compute_priority(self):
        """Calcule la priorité basée sur le score."""
        if self.score >= 80:
            self.priority = Priority.CRITICAL
        elif self.score >= 60:
            self.priority = Priority.HIGH
        elif self.score >= 40:
            self.priority = Priority.MEDIUM
        else:
            self.priority = Priority.LOW


# ═══════════════════════════════════════════════════════════════
# CONTRAT 5: IA Triage → IA Strategy
# Source: triage.py (Claude Haiku)
# Destination: strategist.py (Claude Sonnet)
# ═══════════════════════════════════════════════════════════════

@dataclass
class TriageDecision:
    """Décision du triage IA."""
    
    request: ScoredRequest = field(default_factory=ScoredRequest)
    interesting: bool = False
    reason: str = ""
    confidence: int = 0                     # 0-100
    suggested_vulns: List[str] = field(default_factory=list)
    
    # NEW: Attack Surface Expansion - hints pour le Strategist
    attack_surface_hints: List[str] = field(default_factory=list)  # Ex: ["IDOR on 'user_id'", "Mass Assignment on 'role'"]
    false_positive_reason: Optional[str] = None  # Pourquoi l'alerte initiale est un FP
    
    # Métadonnées IA
    model_used: str = ""
    tokens_input: int = 0
    tokens_output: int = 0
    latency_ms: float = 0
    
    # DEBUG: Prompt et réponse brute pour inspection
    debug_prompt: str = ""                  # Prompt complet envoyé à l'IA
    debug_response: str = ""                # Réponse brute de l'IA
    
    # Routing
    needs_deep_analysis: bool = False       # Envoyer à Sonnet?
    test_phase: TestPhase = TestPhase.SAFE


# ═══════════════════════════════════════════════════════════════
# CONTRAT 6: IA Strategy → Executor
# Source: strategist.py (Claude Sonnet)
# Destination: tool_wrapper.py
# ═══════════════════════════════════════════════════════════════

@dataclass
class PayloadVariant:
    """Une variante de payload à tester."""
    payload: str = ""
    encoding: str = "none"      # none, url, double_url, unicode, html
    evasion: str = "none"       # none, case_swap, comment_insert, whitespace


@dataclass
class TestStep:
    """Une étape dans la séquence de test."""
    order: int = 0
    action: str = ""                        # "send_request", "check_response", "wait"
    description: str = ""
    request_modifier: Optional[Dict] = None # Modifications à appliquer
    expected_indicators: List[str] = field(default_factory=list)
    timeout_ms: int = 5000


@dataclass
class AttackPlan:
    """Plan d'attaque généré par l'IA."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request: TriageDecision = field(default_factory=TriageDecision)
    
    # Outil et méthode
    tool: str = "custom"                    # nuclei, sqlmap, ffuf, xsstrike, custom
    vuln_class: str = ""                    # IDOR, SQLi, XSS, SSRF, etc.
    
    # Payloads
    payloads: List[PayloadVariant] = field(default_factory=list)
    injection_points: List[str] = field(default_factory=list)  # param names
    
    # Séquence
    test_sequence: List[TestStep] = field(default_factory=list)
    
    # Configuration
    baseline_needed: bool = True
    use_proxy_rotation: bool = True
    evasion_techniques: List[str] = field(default_factory=list)
    max_requests: int = 10
    delay_between_ms: int = 1000
    
    # Métadonnées IA
    model_used: str = ""
    tokens_input: int = 0
    tokens_output: int = 0
    reasoning: str = ""                     # Explication de l'IA
    
    # Chain of Thought analysis (new - Gemini recommendation)
    analysis: Dict[str, str] = field(default_factory=dict)  # behavioral_mapping, security_impediment, etc.
    
    # Debug info (prompt/response for UI display)
    debug_prompt: str = ""                  # Prompt envoyé au LLM
    debug_response: str = ""                # Réponse brute du LLM


# Alias pour compatibilité
Severity = FindingSeverity


@dataclass
class ResponseSignature:
    """Signature d'une réponse HTTP pour comparaison."""
    
    status_code: int = 0
    content_type: str = ""
    body_length: int = 0
    body_hash: str = ""
    response_time_ms: float = 0
    headers_of_interest: Dict[str, str] = field(default_factory=dict)  # Set-Cookie, Location, etc.
    
    # Indicateurs de vuln
    error_patterns_found: List[str] = field(default_factory=list)
    reflection_found: bool = False
    timing_anomaly: bool = False


@dataclass
class ExecutionResult:
    """Résultat d'exécution d'un test."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request: TriageDecision = field(default_factory=TriageDecision)
    plan: AttackPlan = field(default_factory=AttackPlan)
    
    # Exécution
    tool_used: str = ""
    execution_time_ms: int = 0
    success: bool = False
    
    # Réponse
    raw_response: Optional[str] = None
    response_signature: Optional[ResponseSignature] = None
    
    # Résultat
    finding: Optional['Finding'] = None
    error: Optional[str] = None
    
    # Détails
    payload_used: str = ""
    injection_point: str = ""
    baseline_diff: Optional['DiffResult'] = None
    test_details: List[Dict[str, Any]] = field(default_factory=list)  # Détails de chaque test HTTP
    
    executed_at: float = field(default_factory=lambda: datetime.now().timestamp())


# ═══════════════════════════════════════════════════════════════
# CONTRAT 7: Baseline Engine
# Source: recorder.py
# Destination: diff_engine.py
# ═══════════════════════════════════════════════════════════════

@dataclass
class BaselineRecord:
    """Réponse de référence pour un endpoint."""
    
    endpoint_hash: str = ""
    method: str = ""
    url_template: str = ""                  # /api/users/{id}
    
    # Response baseline
    status_code: int = 0
    body_hash: str = ""
    body_length: int = 0
    response_time_ms: float = 0
    headers_hash: str = ""
    content_type: str = ""
    
    # Variations connues
    known_variations: List[Dict] = field(default_factory=list)
    
    recorded_at: float = field(default_factory=lambda: datetime.now().timestamp())


@dataclass
class DiffResult:
    """Résultat de comparaison baseline vs attack."""
    
    baseline: BaselineRecord = field(default_factory=BaselineRecord)
    attack_response: Dict[str, Any] = field(default_factory=dict)
    
    # Changements détectés
    status_changed: bool = False
    body_changed: bool = False
    body_length_delta: int = 0
    timing_anomaly: bool = False            # Delta > 500ms
    timing_delta_ms: float = 0
    headers_changed: bool = False
    new_cookies: List[str] = field(default_factory=list)
    
    # Analyse
    anomaly_score: int = 0                  # 0-100
    anomalies: List[str] = field(default_factory=list)
    is_suspicious: bool = False


# ═══════════════════════════════════════════════════════════════
# CONTRAT 8: Executor → Finding
# Source: tool_wrapper.py
# Destination: Dashboard / Reporting
# ═══════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """Vulnérabilité découverte."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Identification
    endpoint: str = ""
    method: str = ""
    vuln_type: str = ""                     # IDOR, SQLi, XSS, etc.
    vuln_subtype: str = ""                  # reflected, stored, blind, etc.
    
    # Sévérité
    severity: FindingSeverity = FindingSeverity.INFO
    status: FindingStatus = FindingStatus.NEW
    confidence: int = 0                     # 0-100
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    
    # Evidence
    request_sent: str = ""                  # Raw HTTP request
    response_received: str = ""             # Raw HTTP response
    payload_successful: str = ""
    baseline_diff: Optional[DiffResult] = None
    screenshot_path: Optional[str] = None
    
    # Analyse
    ai_analysis: str = ""
    impact: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    
    # Chaînage
    artifacts_found: Dict[str, str] = field(default_factory=dict)
    chain_potential: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)
    
    # Métadonnées
    discovered_at: float = field(default_factory=lambda: datetime.now().timestamp())
    tool_used: str = ""
    test_duration_ms: float = 0
    
    # Reporting
    reported_at: Optional[float] = None
    report_url: Optional[str] = None
    bounty_amount: Optional[float] = None


# ═══════════════════════════════════════════════════════════════
# CONTRAT 9: Chain Manager
# Source: chain_manager.py
# Destination: strategist.py / Dashboard
# ═══════════════════════════════════════════════════════════════

@dataclass
class ChainStep:
    """Une étape dans une chaîne d'exploitation."""
    
    step_number: int = 0
    name: str = ""
    vuln_class: str = ""
    endpoint: str = ""
    status: ChainStatus = ChainStatus.PENDING
    
    # Dépendances
    depends_on: List[str] = field(default_factory=list)   # IDs d'artifacts requis
    produces: List[str] = field(default_factory=list)     # IDs d'artifacts produits
    
    # Résultat
    finding_id: Optional[str] = None
    artifacts_produced: Dict[str, str] = field(default_factory=dict)
    
    completed_at: Optional[float] = None


@dataclass
class ExploitChain:
    """Chaîne d'exploitation complète."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    status: ChainStatus = ChainStatus.PENDING
    
    steps: List[ChainStep] = field(default_factory=list)
    current_step: int = 0
    
    # Artifacts globaux
    artifacts: Dict[str, str] = field(default_factory=dict)
    
    # Impact
    impact_if_complete: str = ""
    combined_severity: FindingSeverity = FindingSeverity.INFO
    
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    completed_at: Optional[float] = None


# ═══════════════════════════════════════════════════════════════
# CONTRAT 10: Flow Recorder
# Source: flow_recorder.py
# Destination: strategist.py (replay flows)
# ═══════════════════════════════════════════════════════════════

@dataclass
class FlowStep:
    """Une étape dans un flow enregistré."""
    
    order: int = 0
    action: str = ""                        # Description de l'action
    request: InterceptedRequest = field(default_factory=InterceptedRequest)
    artifacts_created: Dict[str, str] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)


@dataclass
class RecordedFlow:
    """Séquence d'actions enregistrée."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    business_critical: bool = False
    
    steps: List[FlowStep] = field(default_factory=list)
    
    # Vulns identifiées sur ce flow
    attack_surface: List[Dict] = field(default_factory=list)
    
    recorded_at: float = field(default_factory=lambda: datetime.now().timestamp())


# ═══════════════════════════════════════════════════════════════
# CONTRAT 11: Security Profile (Fingerprinting)
# Source: tech_profiler.py
# Destination: strategist.py / evasion
# ═══════════════════════════════════════════════════════════════

@dataclass
class SecurityProfile:
    """Profil de sécurité de la cible."""
    
    target: str = ""
    
    # WAF/CDN
    waf_detected: bool = False
    waf_provider: str = ""                  # Cloudflare, Imperva, etc.
    waf_confidence: int = 0
    
    # Tech Stack
    frontend_framework: str = ""
    backend_framework: str = ""
    database_type: str = ""
    cdn_provider: str = ""
    hosting_provider: str = ""
    
    # Security Headers
    has_csp: bool = False
    has_hsts: bool = False
    has_xframe: bool = False
    
    # Rate Limiting
    rate_limit_detected: bool = False
    rate_limit_threshold: Optional[int] = None
    
    # Authentication
    auth_type: str = ""                     # jwt, session, oauth, etc.
    
    # Recommandations évasion
    recommended_evasion: List[str] = field(default_factory=list)
    
    fingerprinted_at: float = field(default_factory=lambda: datetime.now().timestamp())


# ═══════════════════════════════════════════════════════════════
# CONTRAT 12: OOB Callback
# Source: interactsh_client.py / canary_manager.py
# Destination: Dashboard / Finding correlation
# ═══════════════════════════════════════════════════════════════

@dataclass
class OOBCallback:
    """Callback Out-of-Band reçu."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    callback_type: str = ""                 # dns, http, smtp
    token: str = ""                         # Token unique injecté
    
    # Source
    source_ip: str = ""
    source_port: int = 0
    
    # Données
    raw_data: str = ""
    exfiltrated_data: Optional[str] = None
    
    # Corrélation
    correlated_request_id: Optional[str] = None
    correlated_finding_id: Optional[str] = None
    injection_point: str = ""               # Où le payload a été injecté
    
    received_at: float = field(default_factory=lambda: datetime.now().timestamp())


# ═══════════════════════════════════════════════════════════════
# CONTRAT 13: Dashboard Stats
# Source: Aggregation de toutes les briques
# Destination: Dashboard frontend
# ═══════════════════════════════════════════════════════════════

@dataclass
class SessionStats:
    """Statistiques de la session en cours."""
    
    session_id: str = ""
    target: str = ""
    started_at: float = 0
    duration_seconds: float = 0
    
    # Requêtes
    total_intercepted: int = 0
    total_in_scope: int = 0
    total_deduplicated: int = 0
    total_analyzed_ia: int = 0
    total_tested: int = 0
    
    # Findings
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_info: int = 0
    
    # IA
    tokens_used_haiku: int = 0
    tokens_used_sonnet: int = 0
    estimated_cost_usd: float = 0
    
    # Endpoints
    unique_endpoints: int = 0
    unique_params: int = 0
    
    # Chains
    active_chains: int = 0
    completed_chains: int = 0
    
    # Performance
    avg_response_time_ms: float = 0
    waf_blocks: int = 0
    errors: int = 0


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def validate_contract(obj, expected_type) -> bool:
    """Valide qu'un objet respecte son contrat."""
    return isinstance(obj, expected_type)

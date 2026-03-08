"""
Contracts pour le Second Round Strategist.

Ce fichier contient UNIQUEMENT les dataclasses, pas de logique métier.
~200 lignes max selon les règles du projet.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from enum import Enum


class EncodingType(str, Enum):
    """Types d'encoding supportés."""
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    UNICODE = "unicode"
    HEX = "hex"
    HTML = "html"
    BASE64 = "base64"


class WafProvider(str, Enum):
    """WAF providers connus."""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    F5_BIGIP = "f5_bigip"
    MODSECURITY = "modsecurity"
    UNKNOWN = "unknown"


@dataclass
class SecurityProfile:
    """Profil de sécurité détecté sur l'endpoint."""
    
    waf: Optional[str] = None
    cdn: Optional[str] = None
    rate_limit: bool = False
    anti_bot: Optional[str] = None
    
    def has_waf(self) -> bool:
        """Vérifie si un WAF est détecté."""
        return self.waf is not None
    
    def to_dict(self) -> Dict:
        """Convertit en dict pour serialization."""
        return {
            "waf": self.waf,
            "cdn": self.cdn,
            "rate_limit": self.rate_limit,
            "anti_bot": self.anti_bot,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "SecurityProfile":
        """Construit depuis un dict."""
        return cls(
            waf=data.get("waf"),
            cdn=data.get("cdn"),
            rate_limit=data.get("rate_limit", False),
            anti_bot=data.get("anti_bot"),
        )


@dataclass
class OriginalContext:
    """Contexte original de la requête (issu du Triage)."""
    
    # Endpoint
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    
    # Triage result
    vuln_class: str = ""
    confidence: int = 0
    interesting_params: List[str] = field(default_factory=list)
    triage_reasoning: str = ""
    
    # Security profile
    security_profile: SecurityProfile = field(default_factory=SecurityProfile)
    
    def to_dict(self) -> Dict:
        """Convertit en dict pour serialization."""
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "vuln_class": self.vuln_class,
            "confidence": self.confidence,
            "interesting_params": self.interesting_params,
            "triage_reasoning": self.triage_reasoning,
            "security_profile": self.security_profile.to_dict(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "OriginalContext":
        """Construit depuis un dict."""
        return cls(
            method=data["method"],
            url=data["url"],
            headers=data.get("headers", {}),
            body=data.get("body"),
            vuln_class=data.get("vuln_class", ""),
            confidence=data.get("confidence", 0),
            interesting_params=data.get("interesting_params", []),
            triage_reasoning=data.get("triage_reasoning", ""),
            security_profile=SecurityProfile.from_dict(
                data.get("security_profile", {})
            ),
        )


@dataclass
class AttemptResult:
    """Résultat d'une tentative de payload individuelle."""
    
    # Payload info
    payload_original: str
    payload_sent: str
    encoding: str
    injection_point: str
    
    # Request info
    method: str
    url: str
    
    # Response info
    status_code: int
    response_time_ms: float
    response_length: int
    response_snippet: str = ""
    
    # WAF detection
    waf_blocked: bool = False
    waf_provider: Optional[str] = None
    waf_signature: Optional[str] = None
    
    # Analysis
    is_interesting: bool = False
    diff_indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convertit en dict pour serialization."""
        return {
            "payload_original": self.payload_original,
            "payload_sent": self.payload_sent,
            "encoding": self.encoding,
            "injection_point": self.injection_point,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "response_length": self.response_length,
            "response_snippet": self.response_snippet,
            "waf_blocked": self.waf_blocked,
            "waf_provider": self.waf_provider,
            "waf_signature": self.waf_signature,
            "is_interesting": self.is_interesting,
            "diff_indicators": self.diff_indicators,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "AttemptResult":
        """Construit depuis un dict."""
        return cls(
            payload_original=data["payload_original"],
            payload_sent=data["payload_sent"],
            encoding=data["encoding"],
            injection_point=data["injection_point"],
            method=data["method"],
            url=data["url"],
            status_code=data["status_code"],
            response_time_ms=data["response_time_ms"],
            response_length=data["response_length"],
            response_snippet=data.get("response_snippet", ""),
            waf_blocked=data.get("waf_blocked", False),
            waf_provider=data.get("waf_provider"),
            waf_signature=data.get("waf_signature"),
            is_interesting=data.get("is_interesting", False),
            diff_indicators=data.get("diff_indicators", []),
        )


@dataclass
class PayloadSpec:
    """Spécification d'un payload généré par le LLM."""
    
    payload: str
    encoding: str = "none"
    injection_point: str = ""
    reasoning: str = ""
    
    def to_dict(self) -> Dict:
        """Convertit en dict."""
        return {
            "payload": self.payload,
            "encoding": self.encoding,
            "injection_point": self.injection_point,
            "reasoning": self.reasoning,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "PayloadSpec":
        """Construit depuis un dict."""
        return cls(
            payload=data["payload"],
            encoding=data.get("encoding", "none"),
            injection_point=data.get("injection_point", ""),
            reasoning=data.get("reasoning", ""),
        )


@dataclass
class RoundNPlan:
    """Plan d'attaque généré pour le Round N."""
    
    round_number: int
    vuln_class: str
    payloads: List[PayloadSpec]
    reasoning: str = ""
    bypass_techniques: List[str] = field(default_factory=list)
    # Debug: prompt envoyé et réponse reçue de l'IA
    debug_prompt: str = ""
    debug_response: str = ""
    
    def to_dict(self) -> Dict:
        """Convertit en dict."""
        return {
            "round_number": self.round_number,
            "vuln_class": self.vuln_class,
            "payloads": [p.to_dict() for p in self.payloads],
            "reasoning": self.reasoning,
            "bypass_techniques": self.bypass_techniques,
            "debug_prompt": self.debug_prompt,
            "debug_response": self.debug_response,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "RoundNPlan":
        """Construit depuis un dict."""
        return cls(
            round_number=data["round_number"],
            vuln_class=data["vuln_class"],
            payloads=[PayloadSpec.from_dict(p) for p in data.get("payloads", [])],
            reasoning=data.get("reasoning", ""),
            bypass_techniques=data.get("bypass_techniques", []),
            debug_prompt=data.get("debug_prompt", ""),
            debug_response=data.get("debug_response", ""),
        )


@dataclass
class RoundResult:
    """Résultat complet d'un round (plan + exécution)."""
    
    round_number: int
    timestamp: datetime
    plan: RoundNPlan
    tests: List[AttemptResult] = field(default_factory=list)
    
    # Stats agrégées (calculées à posteriori)
    blocked_count: int = 0
    passed_count: int = 0
    interesting_count: int = 0
    error_count: int = 0
    
    # Patterns découverts
    blocked_patterns: List[str] = field(default_factory=list)
    working_techniques: List[str] = field(default_factory=list)
    promising_results: List[str] = field(default_factory=list)
    
    def compute_stats(self) -> None:
        """Calcule les stats depuis les tests."""
        self.blocked_count = sum(1 for t in self.tests if t.waf_blocked)
        self.passed_count = sum(1 for t in self.tests if not t.waf_blocked)
        self.interesting_count = sum(1 for t in self.tests if t.is_interesting)
        
    def to_dict(self) -> Dict:
        """Convertit en dict."""
        return {
            "round_number": self.round_number,
            "timestamp": self.timestamp.isoformat(),
            "plan": self.plan.to_dict(),
            "tests": [t.to_dict() for t in self.tests],
            "blocked_count": self.blocked_count,
            "passed_count": self.passed_count,
            "interesting_count": self.interesting_count,
            "error_count": self.error_count,
            "blocked_patterns": self.blocked_patterns,
            "working_techniques": self.working_techniques,
            "promising_results": self.promising_results,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "RoundResult":
        """Construit depuis un dict."""
        return cls(
            round_number=data["round_number"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            plan=RoundNPlan.from_dict(data["plan"]),
            tests=[AttemptResult.from_dict(t) for t in data.get("tests", [])],
            blocked_count=data.get("blocked_count", 0),
            passed_count=data.get("passed_count", 0),
            interesting_count=data.get("interesting_count", 0),
            error_count=data.get("error_count", 0),
            blocked_patterns=data.get("blocked_patterns", []),
            working_techniques=data.get("working_techniques", []),
            promising_results=data.get("promising_results", []),
        )


@dataclass
class CumulativeKnowledge:
    """Connaissance agrégée de tous les rounds précédents."""
    
    # What to avoid
    blocked_patterns: List[str] = field(default_factory=list)
    failed_encodings: List[str] = field(default_factory=list)
    
    # What works
    working_techniques: List[str] = field(default_factory=list)
    successful_encodings: List[str] = field(default_factory=list)
    
    # Most promising
    promising_results: List[str] = field(default_factory=list)
    
    # Stats par encoding
    encoding_stats: Dict[str, Dict[str, int]] = field(default_factory=dict)
    
    # Security context
    waf_provider: Optional[str] = None
    
    def update_with_round(self, round_result: RoundResult) -> "CumulativeKnowledge":
        """Retourne une nouvelle instance enrichie du round."""
        new = CumulativeKnowledge(
            blocked_patterns=self.blocked_patterns.copy(),
            failed_encodings=self.failed_encodings.copy(),
            working_techniques=self.working_techniques.copy(),
            successful_encodings=self.successful_encodings.copy(),
            promising_results=self.promising_results.copy(),
            encoding_stats=self.encoding_stats.copy(),
            waf_provider=self.waf_provider,
        )
        
        # Ajouter les patterns bloqués
        new.blocked_patterns.extend(round_result.blocked_patterns)
        
        # Ajouter les techniques qui marchent
        new.working_techniques.extend(round_result.working_techniques)
        
        # Ajouter les résultats prometteurs
        new.promising_results.extend(round_result.promising_results)
        
        # Mettre à jour les stats encoding
        for test in round_result.tests:
            enc = test.encoding
            if enc not in new.encoding_stats:
                new.encoding_stats[enc] = {"blocked": 0, "passed": 0}
            if test.waf_blocked:
                new.encoding_stats[enc]["blocked"] += 1
            else:
                new.encoding_stats[enc]["passed"] += 1
        
        return new
    
    def to_dict(self) -> Dict:
        """Convertit en dict."""
        return {
            "blocked_patterns": self.blocked_patterns,
            "failed_encodings": self.failed_encodings,
            "working_techniques": self.working_techniques,
            "successful_encodings": self.successful_encodings,
            "promising_results": self.promising_results,
            "encoding_stats": self.encoding_stats,
            "waf_provider": self.waf_provider,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "CumulativeKnowledge":
        """Construit depuis un dict."""
        return cls(
            blocked_patterns=data.get("blocked_patterns", []),
            failed_encodings=data.get("failed_encodings", []),
            working_techniques=data.get("working_techniques", []),
            successful_encodings=data.get("successful_encodings", []),
            promising_results=data.get("promising_results", []),
            encoding_stats=data.get("encoding_stats", {}),
            waf_provider=data.get("waf_provider"),
        )

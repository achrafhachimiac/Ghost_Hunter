"""
Ghost-Hunter Security Fingerprinting Module
============================================
Détection passive des mesures de sécurité (WAF, anti-bot, CDN, etc.)
via l'analyse des headers, cookies et réponses HTTP.

Cette phase s'exécute AVANT toute attaque pour adapter la stratégie.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum

from ..contracts import SecurityProfile, InterceptedRequest


logger = logging.getLogger(__name__)


class SecuritySignalType(Enum):
    """Types de signaux de sécurité."""
    COOKIE = "cookie"
    HEADER = "header"
    RESPONSE_BODY = "response_body"
    STATUS_CODE = "status_code"
    BEHAVIOR = "behavior"


@dataclass
class SecuritySignal:
    """Un signal de détection de sécurité."""
    signal_type: SecuritySignalType
    pattern: str
    technology: str
    category: str  # waf, cdn, anti_bot, rate_limit, framework
    confidence: int  # 0-100
    description: str = ""


# Base de données des signatures de sécurité
SECURITY_SIGNATURES: List[SecuritySignal] = [
    # ═══════════════════════════════════════════════════════════════
    # CLOUDFLARE
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.COOKIE, r"^__cf_bm$", "Cloudflare Bot Management", "anti_bot", 95, "Bot fingerprinting cookie"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^cf_clearance$", "Cloudflare Challenge", "anti_bot", 98, "Challenge passé"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^__cflb$", "Cloudflare Load Balancer", "cdn", 90, "Load balancing cookie"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^__cfruid$", "Cloudflare Rate Limit", "rate_limit", 85, "Rate limiting tracking"),
    SecuritySignal(SecuritySignalType.HEADER, r"^cf-ray$", "Cloudflare", "cdn", 99, "Request trace ID"),
    SecuritySignal(SecuritySignalType.HEADER, r"^cf-cache-status$", "Cloudflare CDN", "cdn", 95, "Cache status"),
    SecuritySignal(SecuritySignalType.HEADER, r"^cf-request-id$", "Cloudflare", "cdn", 95, "Request ID"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"Attention Required.*Cloudflare", "Cloudflare WAF", "waf", 95, "Block page"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"Ray ID:.*</", "Cloudflare", "cdn", 90, "Error page with Ray ID"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"challenge-platform", "Cloudflare Turnstile", "anti_bot", 95, "CAPTCHA challenge"),
    
    # ═══════════════════════════════════════════════════════════════
    # AWS
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.COOKIE, r"^AWSALB$", "AWS ALB", "cdn", 99, "Application Load Balancer"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^AWSALBCORS$", "AWS ALB CORS", "cdn", 99, "ALB with CORS"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^aws-waf-token$", "AWS WAF", "waf", 98, "WAF token cookie"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-amzn-requestid$", "AWS API Gateway", "cdn", 99, "API Gateway request ID"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-amz-cf-id$", "AWS CloudFront", "cdn", 99, "CloudFront distribution"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-amzn-trace-id$", "AWS X-Ray", "cdn", 95, "Distributed tracing"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"<Code>AccessDenied</Code>", "AWS WAF", "waf", 90, "AWS block response"),
    
    # ═══════════════════════════════════════════════════════════════
    # AKAMAI
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.COOKIE, r"^ak_bmsc$", "Akamai Bot Manager", "anti_bot", 98, "Bot detection cookie"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^bm_sv$", "Akamai Bot Manager", "anti_bot", 95, "Session validation"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^bm_sz$", "Akamai Bot Manager", "anti_bot", 95, "Bot score"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^_abck$", "Akamai Bot Manager", "anti_bot", 98, "Anti-bot cookie"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^AkaSensorData$", "Akamai Sensor", "anti_bot", 95, "Device fingerprint"),
    SecuritySignal(SecuritySignalType.HEADER, r"^akamai-.*", "Akamai", "cdn", 95, "Akamai header"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-akamai-.*", "Akamai", "cdn", 95, "Akamai debug header"),
    
    # ═══════════════════════════════════════════════════════════════
    # IMPERVA / INCAPSULA
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.COOKIE, r"^incap_ses_", "Imperva Incapsula", "waf", 99, "Session cookie"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^visid_incap_", "Imperva Incapsula", "waf", 99, "Visitor ID"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^nlbi_", "Imperva Incapsula", "waf", 95, "Load balancer"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-iinfo$", "Imperva", "waf", 99, "Request info"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-cdn$", "Imperva CDN", "cdn", 90, "CDN header"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"Request unsuccessful.*Incapsula", "Imperva WAF", "waf", 95, "Block page"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"Powered by Incapsula", "Imperva", "waf", 90, "Attribution"),
    
    # ═══════════════════════════════════════════════════════════════
    # F5 BIG-IP
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.COOKIE, r"^BIGipServer", "F5 BIG-IP", "cdn", 99, "Server pool cookie"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^TS[a-f0-9]{8}$", "F5 BIG-IP ASM", "waf", 95, "ASM session"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-wa-info$", "F5 BIG-IP", "waf", 90, "WAF info"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"The requested URL was rejected", "F5 ASM", "waf", 95, "Block message"),
    
    # ═══════════════════════════════════════════════════════════════
    # SUCURI
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.HEADER, r"^x-sucuri-id$", "Sucuri", "waf", 99, "Request ID"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-sucuri-cache$", "Sucuri", "cdn", 95, "Cache status"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"Sucuri WebSite Firewall", "Sucuri WAF", "waf", 95, "Block page"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"Access Denied - Sucuri", "Sucuri WAF", "waf", 95, "Denied page"),
    
    # ═══════════════════════════════════════════════════════════════
    # FASTLY
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.HEADER, r"^x-served-by$", "Fastly", "cdn", 85, "Edge server"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-cache$", "Fastly", "cdn", 70, "Cache status (generic)"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-timer$", "Fastly", "cdn", 90, "Request timing"),
    SecuritySignal(SecuritySignalType.HEADER, r"^fastly-.*", "Fastly", "cdn", 95, "Fastly header"),
    
    # ═══════════════════════════════════════════════════════════════
    # DATADOME
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.COOKIE, r"^datadome$", "DataDome", "anti_bot", 99, "Bot protection cookie"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-datadome$", "DataDome", "anti_bot", 99, "DataDome header"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"datadome\.co", "DataDome", "anti_bot", 95, "Challenge page"),
    
    # ═══════════════════════════════════════════════════════════════
    # PERIMETERX
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.COOKIE, r"^_px[0-9]?$", "PerimeterX", "anti_bot", 95, "Bot detection"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^_pxhd$", "PerimeterX", "anti_bot", 95, "Device fingerprint"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^_pxvid$", "PerimeterX", "anti_bot", 95, "Visitor ID"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"perimeterx", "PerimeterX", "anti_bot", 90, "Block reference"),
    
    # ═══════════════════════════════════════════════════════════════
    # KASADA
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.COOKIE, r"^x-]kpsdk-", "Kasada", "anti_bot", 95, "Kasada cookie"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-kpsdk-", "Kasada", "anti_bot", 95, "Kasada header"),
    
    # ═══════════════════════════════════════════════════════════════
    # RECAPTCHA / HCAPTCHA
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"google\.com/recaptcha", "Google reCAPTCHA", "anti_bot", 95, "reCAPTCHA integration"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"hcaptcha\.com", "hCaptcha", "anti_bot", 95, "hCaptcha integration"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"g-recaptcha", "Google reCAPTCHA", "anti_bot", 90, "reCAPTCHA div"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"h-captcha", "hCaptcha", "anti_bot", 90, "hCaptcha div"),
    
    # ═══════════════════════════════════════════════════════════════
    # FRAMEWORKS BACKEND
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.HEADER, r"^x-powered-by$", "Backend Framework", "framework", 80, "Framework disclosure"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^JSESSIONID$", "Java/Tomcat", "framework", 95, "Java session"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^PHPSESSID$", "PHP", "framework", 95, "PHP session"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^ASP\.NET_SessionId$", "ASP.NET", "framework", 95, ".NET session"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^_session_id$", "Ruby on Rails", "framework", 90, "Rails session"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^connect\.sid$", "Express.js", "framework", 90, "Express session"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^laravel_session$", "Laravel", "framework", 95, "Laravel session"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^django.*session", "Django", "framework", 90, "Django session"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-aspnet-version$", "ASP.NET", "framework", 95, "ASP.NET version"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-aspnetmvc-version$", "ASP.NET MVC", "framework", 95, "MVC version"),
    
    # ═══════════════════════════════════════════════════════════════
    # FRAMEWORKS FRONTEND
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"__NEXT_DATA__", "Next.js", "framework", 95, "Next.js hydration"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"__NUXT__", "Nuxt.js", "framework", 95, "Nuxt.js hydration"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r'ng-version="', "Angular", "framework", 90, "Angular version"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"react", "React", "framework", 60, "React (generic)"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r"vue", "Vue.js", "framework", 60, "Vue (generic)"),
    
    # ═══════════════════════════════════════════════════════════════
    # SECURITY HEADERS
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.HEADER, r"^content-security-policy$", "CSP", "security_header", 100, "Content Security Policy"),
    SecuritySignal(SecuritySignalType.HEADER, r"^strict-transport-security$", "HSTS", "security_header", 100, "HTTP Strict Transport"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-frame-options$", "X-Frame-Options", "security_header", 100, "Clickjacking protection"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-content-type-options$", "X-Content-Type-Options", "security_header", 100, "MIME sniffing prevention"),
    SecuritySignal(SecuritySignalType.HEADER, r"^x-xss-protection$", "X-XSS-Protection", "security_header", 100, "XSS filter (deprecated)"),
    SecuritySignal(SecuritySignalType.HEADER, r"^referrer-policy$", "Referrer-Policy", "security_header", 100, "Referrer control"),
    SecuritySignal(SecuritySignalType.HEADER, r"^permissions-policy$", "Permissions-Policy", "security_header", 100, "Feature control"),
    
    # ═══════════════════════════════════════════════════════════════
    # AUTHENTICATION
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.HEADER, r"^authorization$", "Auth Header", "auth", 80, "Authorization present"),
    SecuritySignal(SecuritySignalType.HEADER, r"^www-authenticate$", "Auth Required", "auth", 90, "Auth challenge"),
    SecuritySignal(SecuritySignalType.COOKIE, r"^(access_token|auth_token|jwt)$", "JWT Auth", "auth", 85, "Token cookie"),
    SecuritySignal(SecuritySignalType.RESPONSE_BODY, r'"token":', "JWT in Response", "auth", 70, "Token in body"),
    
    # ═══════════════════════════════════════════════════════════════
    # RATE LIMITING
    # ═══════════════════════════════════════════════════════════════
    SecuritySignal(SecuritySignalType.HEADER, r"^x-ratelimit-", "Rate Limiting", "rate_limit", 95, "Rate limit headers"),
    SecuritySignal(SecuritySignalType.HEADER, r"^retry-after$", "Rate Limiting", "rate_limit", 90, "Retry indicator"),
    SecuritySignal(SecuritySignalType.STATUS_CODE, r"^429$", "Rate Limited", "rate_limit", 100, "Too Many Requests"),
]


@dataclass
class DetectedTechnology:
    """Une technologie détectée."""
    name: str
    category: str
    confidence: int
    signals: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=lambda: datetime.now().timestamp())
    occurrences: int = 1


@dataclass
class ProgramSecurityProfile:
    """Profil de sécurité complet pour un programme/domaine."""
    
    target: str  # Domaine principal
    
    # Technologies détectées par catégorie
    waf: Optional[DetectedTechnology] = None
    cdn: Optional[DetectedTechnology] = None
    anti_bot: Optional[DetectedTechnology] = None
    rate_limiting: Optional[DetectedTechnology] = None
    
    # Frameworks
    backend_framework: Optional[DetectedTechnology] = None
    frontend_framework: Optional[DetectedTechnology] = None
    
    # Security headers présents
    security_headers: Dict[str, bool] = field(default_factory=lambda: {
        "csp": False,
        "hsts": False,
        "x_frame_options": False,
        "x_content_type_options": False,
        "referrer_policy": False,
        "permissions_policy": False,
    })
    
    # Auth type détecté
    auth_type: str = "unknown"  # jwt, session, oauth, basic, none
    
    # Statistiques
    total_requests_analyzed: int = 0
    blocked_requests: int = 0
    rate_limited_requests: int = 0
    
    # Timestamps
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    updated_at: float = field(default_factory=lambda: datetime.now().timestamp())
    
    # Raw signals pour debug
    all_signals: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire pour JSON/API."""
        # If no WAF detected but CDN present, assume WAF likely exists
        waf_data = None
        if self.waf:
            waf_data = asdict(self.waf)
        elif self.cdn:
            # CDN usually comes with WAF - assume "Unknown/Likely"
            waf_data = {
                "name": f"Unknown (likely via {self.cdn.name})",
                "category": "waf",
                "confidence": 50,
                "signals": ["Inferred from CDN presence"],
                "first_seen": self.created_at,
                "occurrences": 0,
            }
        else:
            # No CDN detected either - still assume some WAF exists in 2024+
            waf_data = {
                "name": "Unknown/Assumed",
                "category": "waf",
                "confidence": 30,
                "signals": ["Default assumption - most production apps have WAF"],
                "first_seen": self.created_at,
                "occurrences": 0,
            }
        
        return {
            "target": self.target,
            "waf": waf_data,
            "cdn": asdict(self.cdn) if self.cdn else None,
            "anti_bot": asdict(self.anti_bot) if self.anti_bot else None,
            "rate_limiting": asdict(self.rate_limiting) if self.rate_limiting else None,
            "backend_framework": asdict(self.backend_framework) if self.backend_framework else None,
            "frontend_framework": asdict(self.frontend_framework) if self.frontend_framework else None,
            "security_headers": self.security_headers,
            "auth_type": self.auth_type,
            "stats": {
                "total_requests": self.total_requests_analyzed,
                "blocked": self.blocked_requests,
                "rate_limited": self.rate_limited_requests,
            },
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ProgramSecurityProfile":
        """Reconstruit un profil depuis un dictionnaire JSON."""
        def to_tech(d: Optional[Dict]) -> Optional[DetectedTechnology]:
            if not d:
                return None
            return DetectedTechnology(
                name=d.get("name", ""),
                category=d.get("category", ""),
                confidence=d.get("confidence", 0),
                signals=d.get("signals", []),
                first_seen=d.get("first_seen", datetime.now().timestamp()),
                occurrences=d.get("occurrences", 1),
            )
        
        stats = data.get("stats", {})
        return cls(
            target=data.get("target", ""),
            waf=to_tech(data.get("waf")),
            cdn=to_tech(data.get("cdn")),
            anti_bot=to_tech(data.get("anti_bot")),
            rate_limiting=to_tech(data.get("rate_limiting")),
            backend_framework=to_tech(data.get("backend_framework")),
            frontend_framework=to_tech(data.get("frontend_framework")),
            security_headers=data.get("security_headers", {}),
            auth_type=data.get("auth_type", "unknown"),
            total_requests_analyzed=stats.get("total_requests", 0),
            blocked_requests=stats.get("blocked", 0),
            rate_limited_requests=stats.get("rate_limited", 0),
            created_at=data.get("created_at", datetime.now().timestamp()),
            updated_at=data.get("updated_at", datetime.now().timestamp()),
        )
    
    def to_security_profile(self) -> SecurityProfile:
        """Convertit en SecurityProfile pour le pipeline."""
        evasion_recommendations = []
        
        # Determine effective WAF info (with default assumption)
        if self.waf:
            waf_detected = True
            waf_provider = self.waf.name
            waf_confidence = self.waf.confidence
        elif self.cdn:
            # CDN present = WAF likely
            waf_detected = True
            waf_provider = f"Unknown (likely via {self.cdn.name})"
            waf_confidence = 50
        else:
            # Default assumption - assume WAF exists
            waf_detected = True
            waf_provider = "Unknown/Assumed"
            waf_confidence = 30
        
        # Recommandations basées sur les détections
        if self.waf:
            if "cloudflare" in self.waf.name.lower():
                evasion_recommendations.extend([
                    "use_residential_proxy",
                    "slow_rate_10rpm",
                    "unicode_encoding",
                    "case_variation",
                ])
            elif "imperva" in self.waf.name.lower():
                evasion_recommendations.extend([
                    "use_residential_proxy",
                    "parameter_pollution",
                    "json_unicode_escape",
                ])
            elif "akamai" in self.waf.name.lower():
                evasion_recommendations.extend([
                    "use_residential_proxy",
                    "slow_rate_5rpm",
                    "browser_fingerprint_full",
                ])
        elif self.cdn:
            # If CDN detected but no specific WAF, add generic evasion
            if "cloudflare" in self.cdn.name.lower():
                evasion_recommendations.extend([
                    "slow_rate_10rpm",
                    "unicode_encoding",
                    "realistic_timing",
                ])
            else:
                evasion_recommendations.append("generic_waf_bypass")
        else:
            # Unknown WAF - add generic recommendations
            evasion_recommendations.extend([
                "generic_waf_bypass",
                "slow_rate_10rpm",
                "realistic_timing",
            ])
        
        if self.anti_bot:
            evasion_recommendations.extend([
                "realistic_timing",
                "human_like_headers",
                "session_persistence",
            ])
        
        if self.rate_limiting:
            evasion_recommendations.extend([
                "distributed_requests",
                "proxy_rotation",
                "exponential_backoff",
            ])
        
        return SecurityProfile(
            target=self.target,
            waf_detected=waf_detected,
            waf_provider=waf_provider,
            waf_confidence=waf_confidence,
            frontend_framework=self.frontend_framework.name if self.frontend_framework else "",
            backend_framework=self.backend_framework.name if self.backend_framework else "",
            cdn_provider=self.cdn.name if self.cdn else "",
            has_csp=self.security_headers.get("csp", False),
            has_hsts=self.security_headers.get("hsts", False),
            has_xframe=self.security_headers.get("x_frame_options", False),
            rate_limit_detected=self.rate_limiting is not None,
            rate_limit_threshold=None,  # TODO: détecter dynamiquement
            auth_type=self.auth_type,
            recommended_evasion=list(set(evasion_recommendations)),
        )


class SecurityFingerprinter:
    """
    Analyse passive des mesures de sécurité.
    
    Détecte WAF, CDN, anti-bot, rate limiting, frameworks
    via l'analyse des headers, cookies et réponses.
    
    Utilise le RedisStore centralisé pour la persistance.
    """
    
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path("data/security_profiles")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Importer le RedisStore
        from ghost_hunter.core.redis_store import get_redis_store
        self._store = get_redis_store()
        
        # Cache des profils par domaine
        self._profiles: Dict[str, ProgramSecurityProfile] = {}
        
        # Compiler les regex pour performance
        self._compiled_signatures = [
            (sig, re.compile(sig.pattern, re.IGNORECASE))
            for sig in SECURITY_SIGNATURES
        ]
        
        # Charger les profils existants (Redis prioritaire, puis fichiers)
        self._load_profiles()
    
    def _load_profiles(self):
        """Charge les profils depuis Redis (prioritaire) ou fichiers (migration)."""
        # Essayer Redis d'abord
        if self._store.connected:
            redis_profiles = self._store.get_all_security_profiles()
            for domain, data in redis_profiles.items():
                try:
                    self._profiles[domain] = ProgramSecurityProfile.from_dict(data)
                except Exception as e:
                    logger.warning(f"Failed to load profile from Redis {domain}: {e}")
            if redis_profiles:
                logger.info(f"Loaded {len(redis_profiles)} security profiles from Redis")
                return
        
        # Fallback fichiers JSON (migration legacy)
        for file in self.data_dir.glob("*.json"):
            try:
                data = json.loads(file.read_text())
                target = data.get("target", file.stem)
                self._profiles[target] = ProgramSecurityProfile.from_dict(data)
                # Migrer vers Redis
                if self._store.connected:
                    self._store.save_security_profile(target, data)
                logger.debug(f"Loaded security profile for {target} (migrated to Redis)")
            except Exception as e:
                logger.warning(f"Failed to load profile {file}: {e}")
    
    def _save_profile(self, profile: ProgramSecurityProfile):
        """Sauvegarde un profil dans Redis (et fichier legacy)."""
        # Redis (prioritaire)
        if self._store.connected:
            self._store.save_security_profile(profile.target, profile.to_dict())
        
        # Fichier legacy (backup)
        safe_name = profile.target.replace("/", "_").replace(":", "_")
        file_path = self.data_dir / f"{safe_name}.json"
        try:
            file_path.write_text(json.dumps(profile.to_dict(), indent=2))
        except Exception as e:
            logger.error(f"Failed to save profile to file: {e}")
    
    def _extract_domain(self, url: str) -> str:
        """Extrait le domaine d'une URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or url
        except:
            return url
    
    def analyze_request(self, request: InterceptedRequest) -> ProgramSecurityProfile:
        """
        Analyse une requête interceptée pour fingerprinting.
        
        Args:
            request: Requête interceptée
            
        Returns:
            Profil de sécurité mis à jour
        """
        domain = self._extract_domain(request.url)
        
        # Récupérer ou créer le profil
        if domain not in self._profiles:
            self._profiles[domain] = ProgramSecurityProfile(target=domain)
        
        profile = self._profiles[domain]
        profile.total_requests_analyzed += 1
        profile.updated_at = datetime.now().timestamp()
        
        # Analyser les cookies de la requête
        cookies_str = request.headers.get("Cookie", "")
        if cookies_str:
            self._analyze_cookies(profile, cookies_str)
        
        # Analyser les headers de la requête
        self._analyze_headers(profile, request.headers, is_response=False)
        
        # Analyser la réponse si disponible
        if request.response_headers:
            self._analyze_headers(profile, request.response_headers, is_response=True)
            
            # Détecter rate limiting
            if request.response_status == 429:
                profile.rate_limited_requests += 1
                self._add_detection(profile, "rate_limit", "Rate Limiting", "Rate Limiting", 100, ["HTTP 429"])
            
            # Détecter blocage WAF
            if request.response_status == 403:
                profile.blocked_requests += 1
        
        # Analyser le body de la réponse
        if request.response_body:
            self._analyze_response_body(profile, request.response_body)
        
        # Sauvegarder périodiquement
        if profile.total_requests_analyzed % 10 == 0:
            self._save_profile(profile)
        
        return profile
    
    def _analyze_cookies(self, profile: ProgramSecurityProfile, cookies_str: str):
        """Analyse les cookies pour détecter des technologies."""
        # Parser les cookies
        cookies = {}
        for part in cookies_str.split(";"):
            if "=" in part:
                name, value = part.strip().split("=", 1)
                cookies[name.strip()] = value.strip()
        
        for cookie_name in cookies.keys():
            for sig, regex in self._compiled_signatures:
                if sig.signal_type != SecuritySignalType.COOKIE:
                    continue
                    
                if regex.match(cookie_name):
                    self._add_detection(
                        profile, 
                        sig.category, 
                        sig.technology, 
                        sig.category,
                        sig.confidence,
                        [f"Cookie: {cookie_name}"]
                    )
    
    def _analyze_headers(self, profile: ProgramSecurityProfile, headers: Dict[str, str], is_response: bool):
        """Analyse les headers pour détecter des technologies."""
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            
            for sig, regex in self._compiled_signatures:
                if sig.signal_type != SecuritySignalType.HEADER:
                    continue
                
                if regex.match(header_lower):
                    # Cas spécial: x-powered-by contient le framework
                    if header_lower == "x-powered-by":
                        framework_name = header_value
                        self._add_detection(
                            profile, "framework", framework_name, "framework",
                            80, [f"X-Powered-By: {header_value}"]
                        )
                    else:
                        self._add_detection(
                            profile, sig.category, sig.technology, sig.category,
                            sig.confidence, [f"Header: {header_name}"]
                        )
                    
                    # Security headers
                    if sig.category == "security_header":
                        # Normaliser le nom du header pour matcher les clés du dict
                        header_key = header_lower.replace("-", "_")
                        # Mapping des headers vers les clés du profil
                        header_mapping = {
                            "content_security_policy": "csp",
                            "strict_transport_security": "hsts", 
                            "x_frame_options": "x_frame_options",
                            "x_content_type_options": "x_content_type_options",
                            "referrer_policy": "referrer_policy",
                            "permissions_policy": "permissions_policy",
                        }
                        mapped_key = header_mapping.get(header_key, header_key)
                        if mapped_key in profile.security_headers:
                            profile.security_headers[mapped_key] = True
    
    def _analyze_response_body(self, profile: ProgramSecurityProfile, body: str):
        """Analyse le body de la réponse pour détecter des technologies."""
        if not body or len(body) > 500000:  # Skip très gros body
            return
        
        for sig, regex in self._compiled_signatures:
            if sig.signal_type != SecuritySignalType.RESPONSE_BODY:
                continue
            
            if regex.search(body):
                self._add_detection(
                    profile, sig.category, sig.technology, sig.category,
                    sig.confidence, [f"Body pattern: {sig.pattern[:30]}"]
                )
    
    def _add_detection(
        self, 
        profile: ProgramSecurityProfile, 
        category: str, 
        tech_name: str, 
        tech_category: str,
        confidence: int,
        signals: List[str]
    ):
        """Ajoute une détection au profil."""
        # Mapper la catégorie à l'attribut du profil
        attr_map = {
            "waf": "waf",
            "cdn": "cdn", 
            "anti_bot": "anti_bot",
            "rate_limit": "rate_limiting",
            "framework": None,  # Géré séparément
            "security_header": None,  # Géré séparément
            "auth": None,  # Géré séparément
        }
        
        attr_name = attr_map.get(category)
        
        if attr_name:
            current = getattr(profile, attr_name)
            
            if current is None:
                # Nouvelle détection
                setattr(profile, attr_name, DetectedTechnology(
                    name=tech_name,
                    category=tech_category,
                    confidence=confidence,
                    signals=signals,
                ))
                logger.info(f"🛡️ [{profile.target}] Detected {category}: {tech_name} ({confidence}%)")
            else:
                # Mise à jour si confidence plus haute
                current.occurrences += 1
                if confidence > current.confidence:
                    current.confidence = confidence
                for sig in signals:
                    if sig not in current.signals:
                        current.signals.append(sig)
        
        elif category == "framework":
            # Déterminer si backend ou frontend
            backend_keywords = ["php", "asp", "java", "django", "laravel", "rails", "express", "flask", "spring"]
            frontend_keywords = ["next", "nuxt", "angular", "react", "vue"]
            
            name_lower = tech_name.lower()
            
            if any(kw in name_lower for kw in backend_keywords):
                if profile.backend_framework is None or confidence > profile.backend_framework.confidence:
                    profile.backend_framework = DetectedTechnology(
                        name=tech_name, category="backend", confidence=confidence, signals=signals
                    )
                    logger.info(f"🔧 [{profile.target}] Backend: {tech_name}")
            
            elif any(kw in name_lower for kw in frontend_keywords):
                if profile.frontend_framework is None or confidence > profile.frontend_framework.confidence:
                    profile.frontend_framework = DetectedTechnology(
                        name=tech_name, category="frontend", confidence=confidence, signals=signals
                    )
                    logger.info(f"🎨 [{profile.target}] Frontend: {tech_name}")
        
        # Logger le signal brut
        profile.all_signals.append({
            "category": category,
            "technology": tech_name,
            "confidence": confidence,
            "signals": signals,
            "timestamp": datetime.now().timestamp(),
        })
    
    def get_profile(self, domain: str) -> Optional[ProgramSecurityProfile]:
        """Récupère le profil d'un domaine."""
        # Syncer avec Redis
        if self._store.connected and domain not in self._profiles:
            data = self._store.get_security_profile(domain)
            if data:
                self._profiles[domain] = ProgramSecurityProfile.from_dict(data)
        return self._profiles.get(domain)
    
    def get_all_profiles(self) -> Dict[str, ProgramSecurityProfile]:
        """Récupère tous les profils."""
        # Syncer avec Redis
        if self._store.connected:
            redis_profiles = self._store.get_all_security_profiles()
            for domain, data in redis_profiles.items():
                if domain not in self._profiles:
                    try:
                        self._profiles[domain] = ProgramSecurityProfile.from_dict(data)
                    except:
                        pass
        return self._profiles.copy()
    
    def get_profiles_summary(self) -> List[Dict]:
        """Retourne un résumé de tous les profils pour le dashboard."""
        # S'assurer d'avoir tous les profils
        self.get_all_profiles()
        
        summaries = []
        for domain, profile in self._profiles.items():
            summaries.append({
                "target": domain,
                "waf": profile.waf.name if profile.waf else None,
                "waf_confidence": profile.waf.confidence if profile.waf else 0,
                "cdn": profile.cdn.name if profile.cdn else None,
                "anti_bot": profile.anti_bot.name if profile.anti_bot else None,
                "rate_limiting": profile.rate_limiting is not None,
                "backend": profile.backend_framework.name if profile.backend_framework else None,
                "frontend": profile.frontend_framework.name if profile.frontend_framework else None,
                "security_headers": sum(1 for v in profile.security_headers.values() if v),
                "total_headers": len(profile.security_headers),
                "requests_analyzed": profile.total_requests_analyzed,
                "blocked": profile.blocked_requests,
                "rate_limited": profile.rate_limited_requests,
                "updated_at": profile.updated_at,
            })
        return summaries
    
    def clear_all(self):
        """Efface tous les profils (pour reset)."""
        self._profiles.clear()
        # Les fichiers JSON seront effacés par le reset de l'API
    
    async def scan_domain(self, domain: str, protocols: List[str] = None) -> Dict:
        """
        Scan activement un domaine pour détecter ses protections de sécurité.
        
        Args:
            domain: Le domaine à scanner (ex: "shein.com")
            protocols: Liste de protocoles ["https"] - par défaut HTTPS uniquement
            
        Returns:
            Résultat du scan avec les technologies détectées
        """
        import aiohttp
        
        if protocols is None:
            protocols = ["https"]  # HTTPS only by default
        
        results = {
            "domain": domain,
            "scanned_urls": [],
            "technologies_detected": [],
            "errors": [],
        }
        
        # Headers pour simuler un navigateur légitime
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        timeout = aiohttp.ClientTimeout(total=10)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for proto in protocols:
                url = f"{proto}://{domain}/"
                try:
                    async with session.get(url, headers=headers, allow_redirects=True, ssl=False) as response:
                        results["scanned_urls"].append({
                            "url": url,
                            "status": response.status,
                            "final_url": str(response.url),
                        })
                        
                        # Créer une fausse InterceptedRequest pour réutiliser l'analyse
                        response_headers = dict(response.headers)
                        body = ""
                        try:
                            body = await response.text()
                        except:
                            pass
                        
                        # Construire le target avec port
                        port = 443 if proto == "https" else 80
                        target = f"{domain}:{port}"
                        
                        # Créer ou récupérer le profil
                        if target not in self._profiles:
                            self._profiles[target] = ProgramSecurityProfile(target=target)
                        
                        profile = self._profiles[target]
                        profile.total_requests_analyzed += 1
                        profile.updated_at = datetime.now().timestamp()
                        
                        # Analyser les headers de réponse
                        self._analyze_headers(profile, response_headers, is_response=True)
                        
                        # Analyser les cookies Set-Cookie
                        if 'Set-Cookie' in response_headers:
                            set_cookies = response.headers.getall('Set-Cookie', [])
                            for cookie_str in set_cookies:
                                # Extraire le nom du cookie
                                if '=' in cookie_str:
                                    cookie_name = cookie_str.split('=')[0]
                                    self._analyze_cookies(profile, f"{cookie_name}=value")
                        
                        # Analyser le body
                        if body:
                            self._analyze_response_body(profile, body[:50000])  # Limiter à 50KB
                        
                        # Sauvegarder
                        self._save_profile(profile)
                        
                        results["technologies_detected"].append({
                            "target": target,
                            "waf": profile.waf.name if profile.waf else None,
                            "cdn": profile.cdn.name if profile.cdn else None,
                            "anti_bot": profile.anti_bot.name if profile.anti_bot else None,
                            "backend": profile.backend_framework.name if profile.backend_framework else None,
                            "frontend": profile.frontend_framework.name if profile.frontend_framework else None,
                            "security_headers": sum(1 for v in profile.security_headers.values() if v),
                        })
                        
                except aiohttp.ClientError as e:
                    results["errors"].append({"url": url, "error": str(e)})
                    logger.warning(f"Scan failed for {url}: {e}")
                except Exception as e:
                    results["errors"].append({"url": url, "error": str(e)})
                    logger.warning(f"Unexpected error scanning {url}: {e}")
        
        return results
    
    async def scan_scope_domains(self, scope_config: Dict) -> Dict:
        """
        Scan tous les domaines du scope (HTTPS uniquement).
        
        Args:
            scope_config: Configuration du scope avec in_scope patterns
            
        Returns:
            Résultats de tous les scans
        """
        import asyncio
        
        in_scope = scope_config.get("in_scope", [])
        
        # Extraire les domaines de base des patterns
        domains = set()
        for pattern in in_scope:
            # Convertir *.shein.com en shein.com et www.shein.com
            if pattern.startswith("*."):
                base_domain = pattern[2:]  # Enlever *.
                domains.add(base_domain)
                domains.add(f"www.{base_domain}")
            elif pattern.startswith("*"):
                base_domain = pattern[1:]
                domains.add(base_domain)
            else:
                domains.add(pattern)
        
        logger.info(f"🔍 Starting security scan for {len(domains)} domains...")
        
        results = {
            "total_domains": len(domains),
            "scanned": 0,
            "successful": 0,
            "failed": 0,
            "domains": [],
            "summary": {
                "waf_count": 0,
                "cdn_count": 0,
                "anti_bot_count": 0,
            }
        }
        
        # Scanner chaque domaine
        for i, domain in enumerate(sorted(domains), 1):
            logger.info(f"🌐 [{i}/{len(domains)}] Scanning {domain}...")
            try:
                scan_result = await self.scan_domain(domain, protocols=["https"])
                results["domains"].append(scan_result)
                results["scanned"] += 1
                
                if scan_result.get("errors"):
                    results["failed"] += 1
                    logger.warning(f"   ⚠️ {domain}: {scan_result['errors'][0].get('error', 'Unknown error')[:50]}")
                else:
                    results["successful"] += 1
                    # Compter les technologies
                    for tech in scan_result.get("technologies_detected", []):
                        if tech.get("waf"):
                            results["summary"]["waf_count"] += 1
                        if tech.get("cdn"):
                            results["summary"]["cdn_count"] += 1
                            logger.info(f"   ✅ {domain}: CDN={tech.get('cdn')}")
                        if tech.get("anti_bot"):
                            results["summary"]["anti_bot_count"] += 1
                            logger.info(f"   🤖 {domain}: Anti-bot={tech.get('anti_bot')}")
                
                # Petit délai entre les domaines pour éviter rate limiting
                await asyncio.sleep(0.3)
                
            except Exception as e:
                results["failed"] += 1
                results["domains"].append({
                    "domain": domain,
                    "error": str(e),
                })
                logger.error(f"   ❌ {domain}: {str(e)[:50]}")
        
        logger.info(f"✅ Scan complete: {results['successful']}/{results['scanned']} successful, {results['summary']['cdn_count']} CDN detected")
        return results


# Instance globale
_fingerprinter: Optional[SecurityFingerprinter] = None


def get_fingerprinter() -> SecurityFingerprinter:
    """Récupère l'instance globale du fingerprinter."""
    global _fingerprinter
    if _fingerprinter is None:
        _fingerprinter = SecurityFingerprinter()
    return _fingerprinter


def reset_fingerprinter():
    """Reset le fingerprinter (vide le cache)."""
    global _fingerprinter
    if _fingerprinter:
        _fingerprinter.clear_all()
    _fingerprinter = None

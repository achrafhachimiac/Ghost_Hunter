"""
Ghost-Hunter Tech Profiler
===========================
Fingerprinting des technologies utilisées par une cible.
"""

import re
import json
import httpx
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class Technology:
    """Technologie détectée."""
    name: str
    category: str  # framework, server, cms, cdn, waf, etc.
    version: Optional[str] = None
    confidence: int = 100  # 0-100
    evidence: str = ""  # Comment on l'a détecté


@dataclass
class TechProfile:
    """Profil technologique complet d'une cible."""
    url: str
    technologies: List[Technology] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    waf_detected: Optional[str] = None
    cdn_detected: Optional[str] = None
    server: Optional[str] = None
    
    def get_by_category(self, category: str) -> List[Technology]:
        """Récupère les technologies d'une catégorie."""
        return [t for t in self.technologies if t.category == category]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "technologies": [
                {
                    "name": t.name,
                    "category": t.category,
                    "version": t.version,
                    "confidence": t.confidence
                }
                for t in self.technologies
            ],
            "waf": self.waf_detected,
            "cdn": self.cdn_detected,
            "server": self.server
        }


class TechProfiler:
    """
    Profileur de technologies.
    
    Détecte:
    - Frameworks (React, Vue, Angular, Django, Rails, etc.)
    - Serveurs (nginx, Apache, IIS)
    - CMS (WordPress, Drupal, etc.)
    - CDN (Cloudflare, Akamai, etc.)
    - WAF (Cloudflare, Imperva, AWS WAF, etc.)
    - Languages (PHP, Python, Java, etc.)
    """
    
    # Signatures de détection
    SIGNATURES = {
        # ============ WAF Detection ============
        "waf": {
            "cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
                "server": ["cloudflare"],
                "cookies": ["__cfduid", "cf_clearance"]
            },
            "aws_waf": {
                "headers": ["x-amzn-requestid", "x-amz-cf-id"],
                "body": ["aws_waf"]
            },
            "akamai": {
                "headers": ["x-akamai-transformed", "akamai-origin-hop"],
                "server": ["akamai"]
            },
            "imperva": {
                "headers": ["x-cdn", "x-iinfo"],
                "cookies": ["incap_ses", "visid_incap"]
            },
            "sucuri": {
                "headers": ["x-sucuri-id"],
                "server": ["sucuri"]
            },
            "f5_big_ip": {
                "cookies": ["bigipserver", "ts"]
            },
            "modsecurity": {
                "headers": ["x-modsecurity"],
                "body": ["modsecurity"]
            },
        },
        
        # ============ CDN Detection ============
        "cdn": {
            "cloudflare": {
                "headers": ["cf-ray"]
            },
            "fastly": {
                "headers": ["x-fastly-request-id", "fastly-restarts"]
            },
            "akamai": {
                "headers": ["x-akamai-transformed"]
            },
            "cloudfront": {
                "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
                "server": ["cloudfront"]
            },
            "verizon": {
                "headers": ["x-ec-custom-error"]
            },
            "keycdn": {
                "headers": ["x-edge-location"]
            }
        },
        
        # ============ Server Detection ============
        "server": {
            "nginx": {
                "server": ["nginx"]
            },
            "apache": {
                "server": ["apache"]
            },
            "iis": {
                "server": ["microsoft-iis"],
                "headers": ["x-aspnet-version", "x-powered-by"]
            },
            "tomcat": {
                "server": ["tomcat"],
                "cookies": ["jsessionid"]
            },
            "jetty": {
                "server": ["jetty"]
            },
            "gunicorn": {
                "server": ["gunicorn"]
            },
            "uvicorn": {
                "server": ["uvicorn"]
            }
        },
        
        # ============ Framework Detection ============
        "framework": {
            "react": {
                "body": ["_reactRootContainer", "react-root", "__NEXT_DATA__"],
                "headers": ["x-powered-by"]
            },
            "vue": {
                "body": ["__vue__", "v-cloak", "Vue.js"]
            },
            "angular": {
                "body": ["ng-version", "ng-app", "angular.js"]
            },
            "next.js": {
                "body": ["__NEXT_DATA__", "_next/static"],
                "headers": ["x-nextjs-cache"]
            },
            "nuxt.js": {
                "body": ["__NUXT__", "_nuxt/"]
            },
            "django": {
                "cookies": ["csrftoken", "django_language"],
                "headers": ["x-frame-options"]
            },
            "rails": {
                "cookies": ["_session_id"],
                "headers": ["x-runtime", "x-request-id"]
            },
            "laravel": {
                "cookies": ["laravel_session", "xsrf-token"],
                "body": ["laravel"]
            },
            "express": {
                "headers": ["x-powered-by"],
                "cookies": ["connect.sid"]
            },
            "flask": {
                "cookies": ["session"],
                "server": ["werkzeug"]
            },
            "fastapi": {
                "headers": ["x-process-time"],
                "body": ["fastapi"]
            },
            "spring": {
                "cookies": ["jsessionid"],
                "headers": ["x-application-context"]
            },
            "asp.net": {
                "cookies": ["asp.net_sessionid", ".aspxauth"],
                "headers": ["x-aspnet-version", "x-aspnetmvc-version"]
            }
        },
        
        # ============ CMS Detection ============
        "cms": {
            "wordpress": {
                "body": ["wp-content", "wp-includes", "wp-json"],
                "cookies": ["wordpress_logged_in"],
                "headers": ["x-pingback"]
            },
            "drupal": {
                "body": ["drupal.js", "drupal.settings"],
                "headers": ["x-drupal-cache", "x-generator"]
            },
            "joomla": {
                "body": ["/media/jui/", "joomla"],
                "cookies": ["joomla_user_state"]
            },
            "shopify": {
                "body": ["cdn.shopify.com", "shopify.com"],
                "cookies": ["_shopify_s", "cart_currency"]
            },
            "magento": {
                "body": ["mage/", "magento"],
                "cookies": ["mage-cache"]
            },
            "ghost": {
                "headers": ["x-ghost-cache-status"],
                "body": ["ghost."]
            }
        },
        
        # ============ Language Detection ============
        "language": {
            "php": {
                "headers": ["x-powered-by"],
                "cookies": ["phpsessid"],
                "body": [".php"]
            },
            "java": {
                "cookies": ["jsessionid"],
                "body": [".jsp", ".do"]
            },
            "python": {
                "server": ["python", "gunicorn", "uvicorn", "werkzeug"]
            },
            "ruby": {
                "headers": ["x-runtime"],
                "server": ["thin", "puma", "unicorn"]
            },
            "node.js": {
                "headers": ["x-powered-by"]
            }
        },
        
        # ============ API Detection ============
        "api": {
            "graphql": {
                "body": ["graphql", "__typename", "__schema"]
            },
            "swagger": {
                "body": ["swagger", "openapi", "api-docs"]
            },
            "rest": {
                "headers": ["content-type"]
            }
        }
    }
    
    # Version patterns
    VERSION_PATTERNS = {
        "nginx": r"nginx/(\d+\.\d+(?:\.\d+)?)",
        "apache": r"Apache/(\d+\.\d+(?:\.\d+)?)",
        "iis": r"Microsoft-IIS/(\d+\.\d+)",
        "php": r"PHP/(\d+\.\d+(?:\.\d+)?)",
        "express": r"Express",
        "asp.net": r"X-AspNet-Version: (\d+\.\d+(?:\.\d+)?)",
        "cloudflare": r"cloudflare",
    }
    
    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False  # Pour les self-signed certs
        )
    
    async def profile(self, url: str) -> TechProfile:
        """
        Profile une URL et détecte les technologies.
        
        Args:
            url: URL à profiler
        """
        profile = TechProfile(url=url)
        
        try:
            # Faire la requête
            response = await self._client.get(url)
            
            # Stocker les headers
            profile.headers = dict(response.headers)
            
            # Stocker les cookies
            profile.cookies = list(response.cookies.keys())
            
            # Extraire le serveur
            server_header = response.headers.get("server", "")
            profile.server = server_header if server_header else None
            
            # Contenu de la page
            body = response.text[:50000]  # Limiter la taille
            
            # Détecter toutes les technologies
            self._detect_all(profile, body)
            
            logger.info(f"Profiled {url}: {len(profile.technologies)} technologies detected")
            
        except Exception as e:
            logger.error(f"Error profiling {url}: {e}")
        
        return profile
    
    def _detect_all(self, profile: TechProfile, body: str):
        """Détecte toutes les technologies."""
        headers_lower = {k.lower(): v.lower() for k, v in profile.headers.items()}
        cookies_lower = [c.lower() for c in profile.cookies]
        server_lower = (profile.server or "").lower()
        body_lower = body.lower()
        
        for category, signatures in self.SIGNATURES.items():
            for tech_name, patterns in signatures.items():
                confidence = 0
                evidence_parts = []
                
                # Check headers
                if "headers" in patterns:
                    for header in patterns["headers"]:
                        if header.lower() in headers_lower:
                            confidence += 40
                            evidence_parts.append(f"header:{header}")
                
                # Check server
                if "server" in patterns:
                    for server_sig in patterns["server"]:
                        if server_sig.lower() in server_lower:
                            confidence += 50
                            evidence_parts.append(f"server:{server_sig}")
                
                # Check cookies
                if "cookies" in patterns:
                    for cookie in patterns["cookies"]:
                        if cookie.lower() in cookies_lower:
                            confidence += 30
                            evidence_parts.append(f"cookie:{cookie}")
                
                # Check body
                if "body" in patterns:
                    for body_sig in patterns["body"]:
                        if body_sig.lower() in body_lower:
                            confidence += 20
                            evidence_parts.append(f"body:{body_sig}")
                
                # Si on a trouvé quelque chose
                if confidence > 0:
                    # Extraire la version si possible
                    version = self._extract_version(tech_name, profile.headers, body)
                    
                    tech = Technology(
                        name=tech_name,
                        category=category,
                        version=version,
                        confidence=min(confidence, 100),
                        evidence=", ".join(evidence_parts)
                    )
                    profile.technologies.append(tech)
                    
                    # WAF/CDN spécial
                    if category == "waf" and confidence >= 40:
                        profile.waf_detected = tech_name
                    elif category == "cdn" and confidence >= 40:
                        profile.cdn_detected = tech_name
    
    def _extract_version(
        self, 
        tech_name: str, 
        headers: Dict[str, str],
        body: str
    ) -> Optional[str]:
        """Extrait la version d'une technologie."""
        pattern = self.VERSION_PATTERNS.get(tech_name.lower())
        if not pattern:
            return None
        
        # Chercher dans server header
        server = headers.get("server", "")
        match = re.search(pattern, server, re.IGNORECASE)
        if match:
            return match.group(1) if match.groups() else None
        
        # Chercher dans x-powered-by
        powered_by = headers.get("x-powered-by", "")
        match = re.search(pattern, powered_by, re.IGNORECASE)
        if match:
            return match.group(1) if match.groups() else None
        
        return None
    
    async def quick_waf_check(self, url: str) -> Optional[str]:
        """
        Vérifie rapidement si un WAF est présent.
        
        Returns:
            Nom du WAF ou None
        """
        profile = await self.profile(url)
        return profile.waf_detected
    
    async def get_attack_surface(self, url: str) -> Dict[str, Any]:
        """
        Analyse la surface d'attaque basée sur le profil tech.
        
        Returns:
            Dict avec les vecteurs d'attaque potentiels
        """
        profile = await self.profile(url)
        
        attack_surface = {
            "url": url,
            "waf": profile.waf_detected,
            "cdn": profile.cdn_detected,
            "potential_vulns": [],
            "recommended_tests": []
        }
        
        # Analyser les technologies pour suggérer des tests
        for tech in profile.technologies:
            tech_lower = tech.name.lower()
            
            # WordPress
            if tech_lower == "wordpress":
                attack_surface["potential_vulns"].extend([
                    "Plugin vulnerabilities",
                    "Theme vulnerabilities", 
                    "XML-RPC abuse",
                    "User enumeration"
                ])
                attack_surface["recommended_tests"].extend([
                    "wpscan",
                    "nuclei -t wordpress"
                ])
            
            # PHP
            elif tech_lower == "php":
                attack_surface["potential_vulns"].extend([
                    "Type juggling",
                    "Deserialization",
                    "LFI/RFI"
                ])
            
            # Java/Spring
            elif tech_lower in ["java", "spring", "tomcat"]:
                attack_surface["potential_vulns"].extend([
                    "Deserialization (Java)",
                    "Spring4Shell",
                    "JNDI injection"
                ])
            
            # GraphQL
            elif tech_lower == "graphql":
                attack_surface["potential_vulns"].extend([
                    "Introspection enabled",
                    "Batch query attacks",
                    "Nested query DoS"
                ])
                attack_surface["recommended_tests"].append("graphql introspection")
            
            # Django
            elif tech_lower == "django":
                attack_surface["potential_vulns"].extend([
                    "Debug mode enabled",
                    "SQL injection (ORM bypass)",
                    "SSTI (rare)"
                ])
            
            # Node.js/Express
            elif tech_lower in ["express", "node.js"]:
                attack_surface["potential_vulns"].extend([
                    "Prototype pollution",
                    "SSRF",
                    "Path traversal"
                ])
        
        # Si WAF détecté
        if profile.waf_detected:
            attack_surface["notes"] = [
                f"WAF detected: {profile.waf_detected}",
                "Consider evasion techniques",
                "Rate limiting may be active"
            ]
        
        return attack_surface
    
    async def close(self):
        await self._client.aclose()


# Instance globale
_profiler: Optional[TechProfiler] = None


def get_tech_profiler() -> TechProfiler:
    """Récupère le profiler global."""
    global _profiler
    if _profiler is None:
        _profiler = TechProfiler()
    return _profiler


async def quick_fingerprint(url: str) -> Dict[str, Any]:
    """Shortcut: fingerprint rapide d'une URL."""
    profiler = get_tech_profiler()
    profile = await profiler.profile(url)
    return profile.to_dict()

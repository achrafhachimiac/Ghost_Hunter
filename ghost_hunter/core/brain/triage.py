"""
Ghost-Hunter Triage Engine
==========================
Two-Tier Triage System:
- Tier 1 (quick_triage): Mini-analyse ultra-rapide sur TOUTES les requêtes (no RAG) - DISABLED by default
- Tier 2 (full_triage): Analyse complète avec RAG Engine

Utilise Groq (Llama 3.1 70B) pour le triage.
Enrichi avec RAG (HackTricks, NVD/CVE, Personal Reports).
"""

import json
import re
import logging
from typing import Optional, Union
from dataclasses import dataclass

from ghost_hunter.core.contracts import (
    ScoredRequest, TriageDecision, TestPhase, Priority
)
# AIResponse is shared between GroqClient and OpenRouterClient
from ghost_hunter.core.brain.openrouter_client import AIResponse
from ghost_hunter.core.brain.prompts import TRIAGE_SYSTEM_PROMPT, get_triage_prompt

# Import clients - Groq is primary, OpenRouter is fallback
try:
    from ghost_hunter.core.brain.groq_client import GroqClient
    GROQ_CLIENT_AVAILABLE = True
except ImportError:
    GROQ_CLIENT_AVAILABLE = False
    GroqClient = None  # type: ignore

try:
    from ghost_hunter.core.brain.openrouter_client import OpenRouterClient
    OPENROUTER_CLIENT_AVAILABLE = True
except ImportError:
    OPENROUTER_CLIENT_AVAILABLE = False
    OpenRouterClient = None  # type: ignore

# Type alias for any compatible AI client
AIClient = Union['GroqClient', 'OpenRouterClient']

logger = logging.getLogger(__name__)

# Import optionnel du Knowledge Loader (legacy fallback)
try:
    from ghost_hunter.core.intelligence import get_knowledge_loader
    KNOWLEDGE_AVAILABLE = True
except ImportError:
    KNOWLEDGE_AVAILABLE = False
    logger.warning("Knowledge Loader not available")

# Import RAG Engine (new system)
try:
    from ghost_hunter.core.rag.engine import get_rag_engine, RAGEngine
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    logger.info("RAG Engine not available, using legacy KnowledgeLoader")


# Prompt ultra-court pour quick triage (Tier 1)
QUICK_TRIAGE_SYSTEM = """You are a security triage expert. Respond ONLY with JSON.
Analyze if this request MIGHT have security vulnerabilities worth investigating."""

QUICK_TRIAGE_TEMPLATE = """Request: {method} {path}
Params: {params}
Auth: {auth}

Reply JSON only: {{"worth_analyzing": true/false, "reason": "brief reason", "priority": 1-3}}"""


def _load_skip_tier1_config() -> bool:
    """Load skip_tier1 config from settings.yaml."""
    try:
        import yaml
        from pathlib import Path
        
        # Try multiple paths
        config_paths = [
            Path("config/settings.yaml"),
            Path(__file__).parent.parent.parent.parent / "config" / "settings.yaml",
        ]
        
        for config_path in config_paths:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    triage_config = config.get('triage', {})
                    return triage_config.get('skip_tier1', False)
        
        return False
    except Exception as e:
        logger.debug(f"Could not load skip_tier1 config: {e}")
        return False


# Global config loaded once
SKIP_TIER1_TRIAGE = _load_skip_tier1_config()


class TriageEngine:
    """Moteur de triage IA basé sur Groq (Llama 3.1 70B)."""
    
    # RAG config for Tier 2
    TIER2_RAG_MAX_TOKENS = 1000
    TIER2_RAG_MAX_CHUNKS = 10
    
    def __init__(
        self,
        client: AIClient,
        model: str = "llama-70b",
        confidence_threshold: int = 60,
        use_knowledge: bool = True,
        use_rag: bool = True,
        skip_tier1: Optional[bool] = None
    ):
        """
        Args:
            client: Client Groq (ou OpenRouter en fallback)
            model: Modèle à utiliser (llama-70b pour triage, llama-8b pour quick)
            confidence_threshold: Seuil de confiance pour considérer intéressant
            use_knowledge: Utiliser la Knowledge Base pour enrichir les prompts (legacy)
            use_rag: Utiliser RAG Engine pour Tier 2 (new)
            skip_tier1: Skip Tier 1 quick triage, go directly to Tier 2 with RAG
                        If None, uses config from settings.yaml
        """
        self.client = client
        self.model = model
        self.confidence_threshold = confidence_threshold
        self.use_knowledge = use_knowledge and KNOWLEDGE_AVAILABLE
        self.use_rag = use_rag and RAG_AVAILABLE
        
        # Skip Tier 1 config - use param or global config
        self.skip_tier1 = skip_tier1 if skip_tier1 is not None else SKIP_TIER1_TRIAGE
        if self.skip_tier1:
            logger.info("⚡ Tier 1 DISABLED - All requests go directly to Tier 2 with RAG")
        
        # RAG Engine (lazy loaded)
        self._rag_engine: Optional[RAGEngine] = None
        
        # Initialiser le Knowledge Loader si disponible (legacy fallback)
        self._knowledge = None
        if self.use_knowledge and not self.use_rag:
            try:
                self._knowledge = get_knowledge_loader()
                if self._knowledge.is_available:
                    logger.info("📚 Knowledge Base activée pour le triage (legacy)")
                else:
                    self._knowledge = None
                    logger.warning("📚 Knowledge Base non disponible")
            except Exception as e:
                logger.warning(f"📚 Knowledge Base error: {e}")
        
        if self.use_rag:
            logger.info("🧠 RAG Engine activé pour Tier 2 triage")
    
    @property
    def rag_engine(self) -> Optional[RAGEngine]:
        """Lazy load RAG Engine."""
        if self._rag_engine is None and self.use_rag:
            try:
                self._rag_engine = get_rag_engine()
                if not self._rag_engine.is_available():
                    logger.warning("🧠 RAG Engine not available, falling back to KnowledgeLoader")
                    self._rag_engine = None
            except Exception as e:
                logger.warning(f"🧠 RAG Engine error: {e}")
                self._rag_engine = None
        return self._rag_engine
    
    def _extract_json(self, text: str) -> Optional[dict]:
        """Extrait le JSON d'une réponse texte, même avec du texte autour."""
        if not text:
            return None
            
        # 1. Essayer de parser directement
        try:
            return json.loads(text.strip())
        except:
            pass
        
        # 2. Chercher un bloc ```json ... ```
        json_block = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if json_block:
            try:
                return json.loads(json_block.group(1).strip())
            except:
                pass
        
        # 3. Chercher un bloc ``` ... ``` générique
        code_block = re.search(r'```\s*(.*?)\s*```', text, re.DOTALL)
        if code_block:
            try:
                content = code_block.group(1).strip()
                if content.startswith('{'):
                    return json.loads(content)
            except:
                pass
        
        # 4. Chercher le premier { et trouver le } correspondant (gère les nested)
        start_idx = text.find('{')
        if start_idx != -1:
            depth = 0
            for i, char in enumerate(text[start_idx:], start_idx):
                if char == '{':
                    depth += 1
                elif char == '}':
                    depth -= 1
                    if depth == 0:
                        # Trouvé le JSON complet
                        json_str = text[start_idx:i+1]
                        try:
                            return json.loads(json_str)
                        except:
                            pass
                        break
        
        # 5. Essayer de construire un JSON à partir des patterns clés dans le texte
        result = self._extract_from_text(text)
        if result:
            return result
        
        return None
    
    def _extract_from_text(self, text: str) -> Optional[dict]:
        """Extrait les infos d'une réponse texte non-JSON (fallback intelligent)."""
        text_lower = text.lower()
        
        # Détecter si intéressant
        interesting_keywords = ['vulnerability', 'vulnerabilit', 'attack', 'exploit', 'injection', 
                                'idor', 'xss', 'sqli', 'ssrf', 'recommend', 'test', 'security']
        not_interesting_keywords = ['not vulnerable', 'no vulnerability', 'false positive', 
                                    'not interesting', 'low priority', 'unlikely']
        
        is_interesting = any(kw in text_lower for kw in interesting_keywords)
        is_not_interesting = any(kw in text_lower for kw in not_interesting_keywords)
        
        if is_not_interesting:
            is_interesting = False
        
        # Extraire les vulns suggérées
        vuln_patterns = {
            'IDOR': r'idor|insecure direct|bola|broken object',
            'SQLi': r'sql injection|sqli|sql\s+inject',
            'XSS': r'xss|cross.site.script',
            'SSRF': r'ssrf|server.side request',
            'AuthBypass': r'auth\s*bypass|authentication.*bypass|bypass.*auth',
            'RCE': r'rce|remote code|command injection',
            'XXE': r'xxe|xml external',
            'CSRF': r'csrf|cross.site request forgery',
            'Mass Assignment': r'mass.?assignment|privilege.?escalation',
        }
        
        suggested_vulns = []
        for vuln, pattern in vuln_patterns.items():
            if re.search(pattern, text_lower):
                suggested_vulns.append(vuln)
        
        # Si on a détecté des vulns, c'est intéressant
        if suggested_vulns:
            is_interesting = True
        
        # Construire la raison (premiers 500 chars du texte nettoyé)
        reason = text.strip()[:500]
        if len(text) > 500:
            reason += "..."
        
        return {
            "interesting": is_interesting,
            "confidence": 70 if is_interesting else 30,
            "reason": reason,
            "suggested_vulns": suggested_vulns or (["Generic"] if is_interesting else []),
            "attack_surface_hints": [],
            "test_phase": "safe"
        }
    
    def _build_request_data(self, scored: ScoredRequest) -> dict:
        """Construit les données de requête COMPLÈTES pour le prompt."""
        req = scored.request.request
        return {
            "method": req.method,
            "url": req.url,
            "host": req.host,
            "path": req.path,
            "query_params": req.query_params,
            "headers": dict(req.headers),  # ALL headers
            "cookies": req.cookies,  # Full cookies
            "body": req.body,  # Full body
            "body_json": req.body_json,
            "score": scored.score,
            "score_breakdown": scored.score_breakdown,  # NEW: Human-readable breakdown
            "interesting_params": scored.interesting_params,
            "potential_vulns": scored.potential_vulns,
            "has_auth": "authorization" in [h.lower() for h in req.headers.keys()],
            "response_status": req.response_status,
            "response_body": req.response_body[:2000] if req.response_body else None,
        }
    
    def _get_knowledge_context(self, potential_vulns: list) -> Optional[str]:
        """Récupère le contexte Knowledge pour les vulns potentielles (legacy)."""
        if not self._knowledge or not potential_vulns:
            return None
        
        try:
            # Récupérer le contexte pour les vulns détectées
            context = self._knowledge.get_context_for_prompt(
                vuln_types=potential_vulns,
                max_techniques=2,  # Limiter pour le triage (rapide)
                max_payloads=5
            )
            return context if context else None
        except Exception as e:
            logger.debug(f"Knowledge context error: {e}")
            return None
    
    def _get_rag_context(self, scored: ScoredRequest) -> Optional[str]:
        """
        Récupère le contexte RAG pour Tier 2 triage.
        
        Utilise la recherche sémantique pour trouver des techniques
        et CVE pertinentes basées sur la requête.
        """
        if not self.rag_engine:
            return None
        
        try:
            context = self.rag_engine.get_context_sync(
                scored,
                max_tokens=self.TIER2_RAG_MAX_TOKENS,
                max_chunks=self.TIER2_RAG_MAX_CHUNKS,
                include_payloads=False  # Pas de payloads pour triage
            )
            if context and context.results:
                logger.debug(f"🧠 RAG context retrieved ({len(context.results)} chunks)")
            return context
        except Exception as e:
            logger.warning(f"🧠 RAG context error: {e}")
            # Fallback to legacy KnowledgeLoader
            return self._get_knowledge_context(scored.potential_vulns)
    
    def _get_security_context(self, host: str) -> Optional[dict]:
        """Récupère le Security Profile pour le domaine cible."""
        try:
            from ghost_hunter.core.intelligence import get_fingerprinter
            fingerprinter = get_fingerprinter()
            profile = fingerprinter.get_profile(host)
            
            if not profile:
                return None
            
            # Construire le contexte pour le prompt
            security_profile = profile.to_security_profile()
            
            return {
                "waf": profile.waf.name if profile.waf else None,
                "waf_confidence": profile.waf.confidence if profile.waf else 0,
                "cdn": profile.cdn.name if profile.cdn else None,
                "anti_bot": profile.anti_bot.name if profile.anti_bot else None,
                "rate_limiting": profile.rate_limiting is not None,
                "backend": profile.backend_framework.name if profile.backend_framework else None,
                "frontend": profile.frontend_framework.name if profile.frontend_framework else None,
                "security_headers_count": sum(1 for v in profile.security_headers.values() if v),
                "security_headers_total": len(profile.security_headers),
                "evasion_techniques": security_profile.recommended_evasion,
            }
        except Exception as e:
            logger.debug(f"Security context error: {e}")
            return None
    
    def triage(self, scored: ScoredRequest) -> TriageDecision:
        """
        Tier 2: Analyse complète avec RAG Engine.
        
        Analyse une requête scorée et décide si elle est intéressante.
        Utilise RAG pour enrichir le contexte avec des techniques
        et CVE pertinentes.
        
        Args:
            scored: Requête avec score heuristique
            
        Returns:
            TriageDecision avec l'analyse de l'IA
        """
        request_data = self._build_request_data(scored)
        
        # Récupérer le contexte RAG (new) ou Knowledge (legacy fallback)
        if self.use_rag and self.rag_engine:
            knowledge_context = self._get_rag_context(scored)
            if knowledge_context:
                logger.debug("🧠 Using RAG context for Tier 2 triage")
        else:
            knowledge_context = self._get_knowledge_context(
                scored.potential_vulns
            )
        
        # Récupérer le Security Profile de la cible
        security_context = self._get_security_context(
            scored.request.request.host
        )
        
        # Générer le prompt enrichi
        user_prompt = get_triage_prompt(
            request_data, 
            knowledge_context,
            security_context
        )
        
        # Log si contextes utilisés
        if knowledge_context:
            logger.debug(f"📚 Triage enrichi avec Knowledge Base")
        if security_context:
            waf = security_context.get('waf', 'None')
            logger.debug(f"🛡️ Triage enrichi avec Security Profile (WAF: {waf})")
        
        # Construire le prompt complet pour debug
        full_prompt = f"[SYSTEM]\n{TRIAGE_SYSTEM_PROMPT}\n\n[USER]\n{user_prompt}"
        
        # Appeler l'IA
        try:
            response: AIResponse = self.client.chat(
                messages=[{"role": "user", "content": user_prompt}],
                model=self.model,
                system_prompt=TRIAGE_SYSTEM_PROMPT,
                temperature=0.3,  # Basse pour consistance
                max_tokens=500
            )
        except Exception as e:
            logger.error(f"AI call failed: {e}")
            decision = TriageDecision(
                request=scored,
                model_used="error",
                tokens_input=0,
                tokens_output=0,
                latency_ms=0,
                debug_prompt=full_prompt,
                debug_response=f"ERROR: {str(e)}"
            )
            decision.interesting = False
            decision.reason = f"AI error: {str(e)}"
            decision.confidence = 0
            return decision
        
        # Créer la décision par défaut
        decision = TriageDecision(
            request=scored,
            model_used=response.model,
            tokens_input=response.tokens_input,
            tokens_output=response.tokens_output,
            latency_ms=response.latency_ms,
            debug_prompt=full_prompt,
            debug_response=response.content or ""
        )
        
        # Parser la réponse JSON
        parsed = self._extract_json(response.content)
        
        if parsed:
            decision.interesting = parsed.get("interesting", False)
            decision.confidence = parsed.get("confidence", 0)
            decision.reason = parsed.get("reason", "")
            decision.suggested_vulns = parsed.get("suggested_vulns", [])
            
            # NEW: Attack Surface Expansion fields
            decision.attack_surface_hints = parsed.get("attack_surface_hints", [])
            decision.false_positive_reason = parsed.get("false_positive_reason")
            
            # If we have attack hints but not interesting, STILL escalate (pivot logic)
            if decision.attack_surface_hints and not decision.interesting:
                logger.info(f"🔄 [PIVOT] FP detected but found attack surface hints: {decision.attack_surface_hints}")
                decision.interesting = True  # Pivot: still interesting for other reasons
                decision.reason = f"FP on initial alert, but: {', '.join(decision.attack_surface_hints[:2])}"
            
            # Parser le test_phase
            phase_str = parsed.get("test_phase", "safe").lower()
            if phase_str == "risky":
                decision.test_phase = TestPhase.RISKY
            elif phase_str == "medium":
                decision.test_phase = TestPhase.MEDIUM
            else:
                decision.test_phase = TestPhase.SAFE
            
            # Décider si besoin d'analyse profonde (Sonnet)
            decision.needs_deep_analysis = (
                decision.interesting and 
                decision.confidence >= self.confidence_threshold
            )
        else:
            # Fallback ultime si même _extract_from_text a échoué
            # Cela ne devrait plus arriver car _extract_json appelle _extract_from_text
            logger.warning(f"JSON extraction failed completely for: {response.content[:100]}...")
            decision.interesting = True  # Better safe than sorry - let human review
            decision.reason = response.content.strip()[:500] if response.content else "AI response parsing failed"
            decision.confidence = 50
            decision.suggested_vulns = ["Manual Review Needed"]
        
        return decision
    
    def batch_triage(self, scored_requests: list[ScoredRequest]) -> list[TriageDecision]:
        """Trie un batch de requêtes."""
        return [self.triage(req) for req in scored_requests]
    
    def is_worth_testing(self, decision: TriageDecision) -> bool:
        """Détermine si une décision mérite des tests."""
        return (
            decision.interesting and 
            decision.confidence >= self.confidence_threshold
        )
    
    def quick_triage(self, scored: ScoredRequest) -> dict:
        """
        Tier 1: Mini-triage ultra-rapide.
        
        Analyse minimale pour décider si une requête mérite une analyse complète.
        Coût très faible (~100 tokens), latence ~200ms.
        
        Returns:
            {"worth_analyzing": bool, "reason": str, "priority": int}
        """
        req = scored.request.request
        
        # Construire un prompt minimaliste
        params = list(req.query_params.keys()) if req.query_params else []
        if req.body:
            # Extraire quelques clés du body si JSON
            try:
                body_data = json.loads(req.body) if isinstance(req.body, str) else req.body
                if isinstance(body_data, dict):
                    params.extend(list(body_data.keys())[:5])
            except:
                pass
        
        prompt = QUICK_TRIAGE_TEMPLATE.format(
            method=req.method,
            path=req.path,
            params=", ".join(params[:10]) if params else "none",
            auth="yes" if any(h.lower() in ['authorization', 'cookie'] for h in req.headers.keys()) else "no"
        )
        
        try:
            response = self.client.chat(
                messages=[{"role": "user", "content": prompt}],
                model="haiku",  # Toujours Haiku pour le quick triage
                system_prompt=QUICK_TRIAGE_SYSTEM,
                temperature=0.1,  # Très bas pour consistance
                max_tokens=100  # Réponse courte
            )
            
            # Parser la réponse
            parsed = self._extract_json(response.content)
            if parsed:
                return {
                    "worth_analyzing": parsed.get("worth_analyzing", False),
                    "reason": parsed.get("reason", ""),
                    "priority": parsed.get("priority", 2),
                    "tokens_used": response.tokens_input + response.tokens_output,
                    "latency_ms": response.latency_ms
                }
            
            # Fallback
            worth = "true" in response.content.lower() or "worth" in response.content.lower()
            return {
                "worth_analyzing": worth,
                "reason": "parse_failed",
                "priority": 2,
                "tokens_used": response.tokens_input + response.tokens_output,
                "latency_ms": response.latency_ms
            }
            
        except Exception as e:
            logger.error(f"Quick triage error: {e}")
            # En cas d'erreur, on laisse passer (fail-open)
            return {
                "worth_analyzing": True,
                "reason": f"error: {str(e)[:50]}",
                "priority": 2,
                "tokens_used": 0,
                "latency_ms": 0
            }
    
    def full_triage(self, scored: ScoredRequest) -> TriageDecision:
        """
        Tier 2: Triage complet avec RAG Engine.
        
        Utilise la recherche sémantique pour enrichir le contexte
        avec des techniques et CVE pertinentes.
        
        Alias pour la méthode triage() standard.
        """
        return self.triage(scored)
    
    def smart_triage(self, scored: ScoredRequest) -> TriageDecision:
        """
        Triage intelligent avec gestion automatique des tiers.
        
        Si skip_tier1=True: va directement au Tier 2 avec RAG
        Sinon: Tier 1 (quick) puis Tier 2 si worth_analyzing
        
        C'est LA méthode à utiliser dans le pipeline.
        
        Args:
            scored: Requête avec score heuristique
            
        Returns:
            TriageDecision complète
        """
        if self.skip_tier1:
            # Go directly to Tier 2 with RAG
            logger.debug(f"⚡ Skip Tier 1 → Direct Tier 2 for {scored.request.request.path}")
            return self.full_triage(scored)
        
        # Classic flow: Tier 1 → Tier 2 if needed
        quick_result = self.quick_triage(scored)
        
        if quick_result.get("worth_analyzing", False):
            logger.debug(f"✅ Tier 1 passed → Tier 2 for {scored.request.request.path}")
            return self.full_triage(scored)
        else:
            # Create minimal TriageDecision for rejected requests
            logger.debug(f"❌ Tier 1 rejected: {quick_result.get('reason', 'unknown')}")
            decision = TriageDecision(
                request=scored,
                model_used="tier1-quick",
                tokens_input=quick_result.get("tokens_used", 0),
                tokens_output=0,
                latency_ms=quick_result.get("latency_ms", 0)
            )
            decision.interesting = False
            decision.reason = f"Tier 1 rejected: {quick_result.get('reason', 'not worth analyzing')}"
            decision.confidence = 0
            return decision

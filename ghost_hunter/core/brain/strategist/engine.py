"""
Strategist Engine Module
========================
Classe principale StrategistEngine - Moteur de stratégie IA.
"""

import logging
from typing import Optional, List, Union, TYPE_CHECKING

from ghost_hunter.core.contracts import (
    TriageDecision, AttackPlan, PayloadVariant, TestStep
)
from ghost_hunter.core.brain.openrouter_client import AIResponse
from ghost_hunter.core.brain.prompts import STRATEGIST_SYSTEM_PROMPT, get_strategy_prompt
from ghost_hunter.core.ai_logger import get_ai_logger

# Import submodules
from ghost_hunter.core.brain.strategist.parser import (
    extract_json,
    validate_injection_points,
    collect_nested_keys,
)
from ghost_hunter.core.brain.strategist.context import (
    build_request_data,
    build_triage_result,
    get_knowledge_context,
    get_rag_context,
    get_security_context,
)
from ghost_hunter.core.brain.strategist.fallback import (
    DEFAULT_PAYLOADS,
    get_quick_payloads,
    create_fallback_plan,
    apply_waf_evasion,
)

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
    RAGEngine = None  # type: ignore
    logger.info("RAG Engine not available, using legacy KnowledgeLoader")

# Import WAF Evasion
try:
    from ghost_hunter.core.evasion.mutator import PayloadMutator
    WAF_EVASION_AVAILABLE = True
except ImportError:
    WAF_EVASION_AVAILABLE = False
    PayloadMutator = None  # type: ignore
    logger.info("WAF Evasion not available")


class StrategistEngine:
    """Moteur de stratégie IA basé sur Groq (Llama 3.1 70B)."""
    
    # RAG config for Strategist - optimized to reduce noise (Gemini recommendation)
    RAG_MAX_TOKENS = 1200  # Reduced from 1500
    RAG_MAX_CHUNKS = 10    # Reduced from 15 (30% less noise)
    
    # Re-export DEFAULT_PAYLOADS for backward compatibility
    DEFAULT_PAYLOADS = DEFAULT_PAYLOADS
    
    def __init__(
        self,
        client: AIClient,
        model: str = "llama-70b",
        use_knowledge: bool = True,
        use_rag: bool = True,
        use_waf_evasion: bool = True
    ):
        """
        Args:
            client: Client Groq (ou OpenRouter en fallback)
            model: Modèle à utiliser (llama-70b pour stratégie détaillée)
            use_knowledge: Utiliser la Knowledge Base pour enrichir les prompts (legacy)
            use_rag: Utiliser RAG Engine pour enrichir avec payloads et techniques (new)
            use_waf_evasion: Utiliser WAF Evasion pour muter les payloads bloqués
        """
        self.client = client
        self.model = model
        self.use_knowledge = use_knowledge and KNOWLEDGE_AVAILABLE
        self.use_rag = use_rag and RAG_AVAILABLE
        self.use_waf_evasion = use_waf_evasion and WAF_EVASION_AVAILABLE
        
        # RAG Engine (lazy loaded)
        self._rag_engine: Optional['RAGEngine'] = None
        
        # WAF Evasion (lazy loaded)
        self._mutator: Optional['PayloadMutator'] = None
        
        # Initialiser le Knowledge Loader si disponible (legacy fallback)
        self._knowledge = None
        if self.use_knowledge and not self.use_rag:
            try:
                self._knowledge = get_knowledge_loader()
                if self._knowledge.is_available:
                    logger.info("📚 Knowledge Base activée pour la stratégie (legacy)")
                else:
                    self._knowledge = None
            except Exception as e:
                logger.warning(f"📚 Knowledge Base error: {e}")
        
        if self.use_rag:
            logger.info("🧠 RAG Engine activé pour Strategist (800 tokens, payloads inclus)")
        
        if self.use_waf_evasion:
            logger.info("🛡️ WAF Evasion activé pour Strategist")
    
    @property
    def rag_engine(self) -> Optional['RAGEngine']:
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
    
    @property
    def mutator(self) -> Optional['PayloadMutator']:
        """Lazy load WAF Mutator."""
        if self._mutator is None and self.use_waf_evasion:
            try:
                self._mutator = PayloadMutator()
                logger.debug("🛡️ WAF Mutator loaded")
            except Exception as e:
                logger.warning(f"🛡️ WAF Mutator error: {e}")
                self._mutator = None
        return self._mutator
    
    def _log_plan(self, plan: AttackPlan, source: str = "ai") -> None:
        """Log le plan généré pour le path déterministe."""
        try:
            ai_logger = get_ai_logger()
            req = plan.request.request.request.request
            
            ai_logger.log_plan(
                endpoint=req.get_endpoint_template(),
                method=req.method,
                vuln_class=plan.vuln_class,
                injection_points=plan.injection_points,
                payloads=[p.payload for p in plan.payloads],
                reasoning=plan.reasoning,
                source=source,
                model=plan.model_used,
                host=req.host,
            )
        except Exception as e:
            logger.debug(f"Failed to log AI plan: {e}")
    
    def create_plan(self, triage: TriageDecision) -> AttackPlan:
        """
        Crée un plan d'attaque basé sur le triage.
        
        Utilise RAG Engine pour enrichir le contexte avec des techniques,
        CVE, et payloads pertinents.
        
        Args:
            triage: Décision du triage avec les vulns suggérées
            
        Returns:
            AttackPlan détaillé
        """
        request_data = build_request_data(triage)
        triage_result = build_triage_result(triage)
        
        # Récupérer le contexte RAG (new) ou Knowledge (legacy fallback)
        knowledge_context: Optional[str] = None
        knowledge_payloads: Optional[List[str]] = None
        
        if self.use_rag and self.rag_engine:
            knowledge_context, knowledge_payloads = get_rag_context(
                self.rag_engine,
                triage,
                max_tokens=self.RAG_MAX_TOKENS,
                max_chunks=self.RAG_MAX_CHUNKS
            )
            if knowledge_context:
                logger.info("🧠 Using RAG context for Strategist (800 tokens, payloads included)")
        else:
            knowledge_context, knowledge_payloads = get_knowledge_context(
                self._knowledge,
                triage.suggested_vulns
            )
        
        # Récupérer le Security Profile de la cible
        # Naviguer jusqu'au host original
        host = triage.request.request.request.host
        security_context = get_security_context(host)
        
        # Log si contextes utilisés
        if knowledge_context or knowledge_payloads:
            logger.info(f"📚 Stratégie enrichie avec Knowledge Base ({len(knowledge_payloads or [])} payloads)")
        if security_context:
            waf = security_context.get('waf', 'None')
            anti_bot = security_context.get('anti_bot', 'None')
            logger.info(f"🛡️ Stratégie adaptée au Security Profile (WAF: {waf}, Anti-Bot: {anti_bot})")
        
        # Générer le prompt enrichi
        user_prompt = get_strategy_prompt(
            request_data, 
            triage_result,
            knowledge_context=knowledge_context,
            payloads=knowledge_payloads,
            security_context=security_context
        )
        
        # Build full prompt for debug (includes system prompt)
        full_debug_prompt = f"=== SYSTEM PROMPT ===\n{STRATEGIST_SYSTEM_PROMPT}\n\n=== USER PROMPT ===\n{user_prompt}"
        
        # Appeler l'IA
        response: AIResponse = self.client.chat(
            messages=[{"role": "user", "content": user_prompt}],
            model=self.model,
            system_prompt=STRATEGIST_SYSTEM_PROMPT,
            temperature=0.5,
            max_tokens=2000
        )
        
        # DEBUG: Log AI response
        logger.info(f"🤖 Strategist AI response: model={response.model}, tokens={response.tokens_input}+{response.tokens_output}")
        if response.content:
            logger.debug(f"🤖 Strategist raw response: {response.content[:500]}...")
        
        # Plan de base - include debug prompt/response
        plan = AttackPlan(
            request=triage,
            model_used=response.model,
            tokens_input=response.tokens_input,
            tokens_output=response.tokens_output,
            debug_prompt=full_debug_prompt,
            debug_response=response.content or ""
        )
        
        # Vérifier si la réponse est valide (AIResponse n'a pas d'attribut success)
        if not response.content:
            logger.warning("⚠️ AI response is empty, using fallback")
            # Fallback
            return create_fallback_plan(triage)
        
        # Parser la réponse
        parsed = extract_json(response.content)
        
        if not parsed:
            logger.warning(f"⚠️ JSON extraction failed from response: {response.content[:200]}...")
            return create_fallback_plan(triage)
        
        logger.info(f"✅ Parsed plan: vuln_class={parsed.get('vuln_class')}, payloads={len(parsed.get('payloads', []))}")
        
        # Extract Chain of Thought analysis (Gemini recommendation)
        analysis = parsed.get("analysis", {})
        if analysis:
            plan.analysis = analysis
            logger.info(f"🧠 CoT Analysis: {list(analysis.keys())}")
        
        # Remplir le plan
        plan.vuln_class = parsed.get("vuln_class", triage.suggested_vulns[0] if triage.suggested_vulns else "Unknown")
        plan.tool = parsed.get("tool", "custom")
        plan.reasoning = parsed.get("reasoning", "")
        raw_injection_points = parsed.get("injection_points", [])
        # Valider et corriger les injection points
        plan.injection_points = validate_injection_points(raw_injection_points, triage)
        plan.baseline_needed = parsed.get("baseline_needed", True)
        plan.max_requests = parsed.get("max_requests", 10)
        plan.delay_between_ms = parsed.get("delay_between_ms", 1000)
        plan.evasion_techniques = parsed.get("evasion_techniques", [])
        
        # Parser les payloads
        raw_payloads = parsed.get("payloads", [])
        for p in raw_payloads:
            # Skip None payloads
            if p is None:
                logger.warning("⚠️ Skipping None payload")
                continue
            if isinstance(p, dict) and "payload" in p:
                payload_value = p["payload"]
                # CRITICAL: S'assurer que le payload est une string simple, pas un dict/objet
                if isinstance(payload_value, dict):
                    # L'IA a retourné un objet - c'est probablement le body original, on skip
                    logger.warning(f"⚠️ Skipping dict payload (likely original body): {list(payload_value.keys())}")
                    continue
                elif not isinstance(payload_value, str):
                    payload_value = str(payload_value)
                
                # Valider que le payload n'est pas le body original en JSON string
                if payload_value.startswith('{') and 'account_id' in payload_value:
                    logger.warning(f"⚠️ Skipping JSON-like payload (likely original body): {payload_value[:50]}...")
                    continue
                    
                plan.payloads.append(PayloadVariant(
                    payload=payload_value,
                    encoding=p.get("encoding", "none"),
                    evasion=p.get("evasion", "none")
                ))
            elif isinstance(p, str):
                # Valider que ce n'est pas le body original
                if p.startswith('{') and ('account_id' in p or 'ssid' in p):
                    logger.warning(f"⚠️ Skipping JSON-like string payload: {p[:50]}...")
                    continue
                plan.payloads.append(PayloadVariant(payload=p))
            elif isinstance(p, (int, float)):
                # Nombre brut - OK pour IDOR
                plan.payloads.append(PayloadVariant(payload=str(p)))
        
        # Parser la séquence de test
        raw_sequence = parsed.get("test_sequence", [])
        for step in raw_sequence:
            if isinstance(step, dict):
                plan.test_sequence.append(TestStep(
                    order=step.get("order", 0),
                    action=step.get("action", "send_request"),
                    description=step.get("description", ""),
                    expected_indicators=step.get("expected_indicators", [])
                ))
        
        # Log les payloads parsés
        if plan.payloads:
            logger.info(f"✅ Parsed {len(plan.payloads)} payloads from AI:")
            for i, p in enumerate(plan.payloads[:5]):
                logger.info(f"   {i+1}. {repr(p.payload)[:50]}")
        else:
            logger.warning("⚠️ No valid payloads parsed from AI response")
        
        # Fallback si pas de payloads générés - utiliser la logique intelligente
        if not plan.payloads:
            logger.info("📊 No valid payloads from AI, using smart fallback")
            fallback_plan = create_fallback_plan(triage)
            plan.payloads = fallback_plan.payloads
            logger.info(f"📊 Fallback generated {len(plan.payloads)} payloads:")
            for i, p in enumerate(plan.payloads[:5]):
                logger.info(f"   {i+1}. {repr(p.payload)[:50]}")
            if not plan.injection_points:
                plan.injection_points = fallback_plan.injection_points
            # Log comme fallback
            self._log_plan(plan, source="fallback")
        else:
            # Log le plan AI
            self._log_plan(plan, source="ai")
        
        # WAF Evasion: Muter les payloads bloqués si WAF détecté
        if self.use_waf_evasion and security_context:
            waf = security_context.get('waf', 'None')
            if waf and waf != 'None':
                plan = apply_waf_evasion(plan, self.mutator)
        
        return plan
    
    def get_quick_payloads(self, vuln_type: str) -> List[PayloadVariant]:
        """Retourne des payloads rapides pour un type de vuln."""
        return get_quick_payloads(vuln_type)

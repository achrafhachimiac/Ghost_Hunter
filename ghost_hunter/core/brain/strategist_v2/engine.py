"""
Engine principal du Strategist V2.

Orchestrateur qui coordonne l'analyse, le RAG, l'historique
et la génération de payloads pour les rounds d'attaque.
~300 lignes max selon les règles du projet.
"""

import json
import logging
from typing import List, Optional, Any
from datetime import datetime

from .contracts import (
    OriginalContext,
    RoundResult,
    RoundNPlan,
    PayloadSpec,
    CumulativeKnowledge,
    AttemptResult,
)
from .analyzer import analyze_http_response, create_round_result
from .history import AttackHistory
from .rag_queries import get_combined_context
from .prompts.system import STRATEGIST_V2_SYSTEM_PROMPT
from .prompts.builder import build_round_n_prompt

logger = logging.getLogger(__name__)


class StrategistV2Engine:
    """
    Orchestrateur du Second Round Strategist.
    
    Coordonne:
    - Historique des attaques (History)
    - Contexte RAG (WAF bypass, techniques)
    - Génération de payloads (LLM)
    - Analyse des résultats (Analyzer)
    """
    
    def __init__(
        self,
        llm_client: Optional[Any] = None,
        history: Optional[AttackHistory] = None,
    ):
        """
        Args:
            llm_client: Client LLM (Groq, OpenRouter, etc.)
            history: Gestionnaire d'historique (optionnel)
        """
        self._llm_client = llm_client
        self._history = history or AttackHistory()
    
    @property
    def llm_client(self):
        """Lazy load du client LLM."""
        if self._llm_client is None:
            try:
                # D'abord, essayer de charger la clé depuis config
                import os
                api_key = os.getenv("GROQ_API_KEY")
                
                if not api_key:
                    # Charger depuis config/api_keys.yaml
                    try:
                        import yaml
                        config_path = os.path.join(
                            os.path.dirname(__file__),
                            "../../../../config/api_keys.yaml"
                        )
                        with open(config_path) as f:
                            config = yaml.safe_load(f)
                            api_key = config.get("groq", {}).get("api_key")
                    except Exception as config_err:
                        logger.warning(f"Failed to load API key from config: {config_err}")
                
                if api_key:
                    from ghost_hunter.core.brain.groq_client import GroqClient
                    self._llm_client = GroqClient(api_key=api_key)
                    logger.info("✅ LLM client loaded from config")
                else:
                    logger.warning("⚠️ No GROQ_API_KEY found in env or config")
            except Exception as e:
                logger.warning(f"Failed to load LLM client: {e}")
        return self._llm_client
    
    # =========================================================================
    # Main Interface
    # =========================================================================
    
    def generate_next_round(
        self,
        endpoint_hash: str,
        original_context: OriginalContext,
        num_payloads: int = 5,
    ) -> RoundNPlan:
        """
        Génère le plan d'attaque pour le prochain round.
        
        Args:
            endpoint_hash: Hash de l'endpoint
            original_context: Contexte original (triage)
            num_payloads: Nombre de payloads à générer
            
        Returns:
            RoundNPlan avec les payloads générés
        """
        # Déterminer le numéro du round
        last_round = self._history.get_last_round_number(endpoint_hash)
        round_number = last_round + 1
        
        logger.info(
            f"Generating Round {round_number} for {endpoint_hash[:8]}..."
        )
        
        # Récupérer l'historique et la connaissance
        previous_rounds = self._history.get_rounds(endpoint_hash)
        cumulative_knowledge = self._history.get_knowledge(endpoint_hash)
        
        # Récupérer le contexte RAG
        rag_context = self._get_rag_context(
            original_context, cumulative_knowledge
        )
        
        # Construire le prompt cumulatif
        prompt = build_round_n_prompt(
            round_number=round_number,
            original_context=original_context,
            previous_rounds=previous_rounds,
            cumulative_knowledge=cumulative_knowledge,
            rag_context=rag_context,
            num_payloads=num_payloads,
        )
        
        # Appeler le LLM (retourne plan avec debug_prompt/response)
        plan = self._call_llm(round_number, original_context.vuln_class, prompt)
        
        logger.info(
            f"Round {round_number}: Generated {len(plan.payloads)} payloads"
        )
        
        return plan
    
    def record_round_result(
        self,
        endpoint_hash: str,
        plan: RoundNPlan,
        attempts: List[AttemptResult],
    ) -> RoundResult:
        """
        Enregistre les résultats d'un round et met à jour la connaissance.
        
        Args:
            endpoint_hash: Hash de l'endpoint
            plan: Plan d'attaque utilisé
            attempts: Résultats des tentatives
            
        Returns:
            RoundResult créé et sauvegardé
        """
        # Créer le RoundResult
        round_result = create_round_result(
            plan.round_number, plan, attempts
        )
        
        # Sauvegarder dans l'historique
        self._history.save_round(endpoint_hash, round_result)
        
        # Mettre à jour la connaissance cumulative
        knowledge = self._history.get_knowledge(endpoint_hash)
        new_knowledge = knowledge.update_with_round(round_result)
        self._history.save_knowledge(endpoint_hash, new_knowledge)
        
        logger.info(
            f"Recorded Round {plan.round_number}: "
            f"{round_result.blocked_count} blocked, "
            f"{round_result.passed_count} passed, "
            f"{round_result.interesting_count} interesting"
        )
        
        return round_result
    
    def should_continue(
        self,
        endpoint_hash: str,
        max_rounds: int = 5,
    ) -> bool:
        """
        Détermine si on doit continuer les rounds.
        
        Args:
            endpoint_hash: Hash de l'endpoint
            max_rounds: Nombre max de rounds
            
        Returns:
            True si on doit continuer
        """
        last_round = self._history.get_last_round_number(endpoint_hash)
        
        # Limite de rounds
        if last_round >= max_rounds:
            logger.info(f"Max rounds ({max_rounds}) reached")
            return False
        
        # Vérifier si le dernier round était productif
        rounds = self._history.get_rounds(endpoint_hash)
        if rounds:
            last_result = rounds[-1]
            
            # Si tout était bloqué, pas la peine de continuer
            if last_result.blocked_count == len(last_result.tests):
                logger.info("All payloads blocked in last round")
                return False
            
            # Si on a des résultats intéressants, continuer
            if last_result.interesting_count > 0:
                return True
        
        # Par défaut, continuer si pas à la limite
        return last_round < max_rounds
    
    # =========================================================================
    # Private Methods
    # =========================================================================
    
    def _get_rag_context(
        self,
        original_context: OriginalContext,
        knowledge: CumulativeKnowledge,
    ) -> str:
        """Récupère le contexte RAG combiné."""
        try:
            # Safe access to security_profile.waf (can be None)
            waf_from_profile = None
            if original_context.security_profile:
                waf_from_profile = original_context.security_profile.waf
            
            return get_combined_context(
                waf_provider=knowledge.waf_provider or waf_from_profile,
                vuln_class=original_context.vuln_class,
                blocked_patterns=knowledge.blocked_patterns,
                failed_encodings=knowledge.failed_encodings,
                working_techniques=knowledge.working_techniques,
                max_total_chunks=10,
            )
        except Exception as e:
            logger.warning(f"Failed to get RAG context: {e}")
            return ""
    
    def _call_llm(
        self,
        round_number: int,
        vuln_class: str,
        prompt: str,
    ) -> RoundNPlan:
        """Appelle le LLM et parse la réponse."""
        full_prompt = f"=== SYSTEM PROMPT ===\n{STRATEGIST_V2_SYSTEM_PROMPT}\n\n=== USER PROMPT ===\n{prompt}"
        
        try:
            if self.llm_client is None:
                logger.warning("No LLM client available")
                plan = self._fallback_plan(round_number, vuln_class)
                plan.debug_prompt = full_prompt
                plan.debug_response = "[FALLBACK - No LLM client available]"
                return plan
            
            # Appel LLM - GroqClient.chat() attend messages (liste) + system_prompt optionnel
            messages = [{"role": "user", "content": prompt}]
            llm_response = self.llm_client.chat(
                messages=messages,
                system_prompt=STRATEGIST_V2_SYSTEM_PROMPT,
                model="llama-3.3-70b-versatile",
                temperature=0.7,
                max_tokens=2000,
            )
            # Extraire le contenu de la réponse
            response = llm_response.content if hasattr(llm_response, 'content') else str(llm_response)
            
            # Parser la réponse JSON
            plan = self._parse_llm_response(round_number, vuln_class, response)
            # Sauvegarder le prompt et la réponse pour debug
            plan.debug_prompt = full_prompt
            plan.debug_response = response
            return plan
            
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            plan = self._fallback_plan(round_number, vuln_class)
            plan.debug_prompt = full_prompt
            plan.debug_response = f"[ERROR: {str(e)}]"
            return plan
    
    def _parse_llm_response(
        self,
        round_number: int,
        vuln_class: str,
        response: str,
    ) -> RoundNPlan:
        """Parse la réponse JSON du LLM."""
        try:
            # Extraire le JSON de la réponse
            json_str = self._extract_json(response)
            data = json.loads(json_str)
            
            payloads = []
            for p in data.get("payloads", []):
                payloads.append(PayloadSpec(
                    payload=p.get("payload", ""),
                    encoding=p.get("encoding", "none"),
                    injection_point=p.get("injection_point", ""),
                    reasoning=p.get("reasoning", ""),
                ))
            
            return RoundNPlan(
                round_number=round_number,
                vuln_class=vuln_class,
                payloads=payloads,
                reasoning=data.get("reasoning", ""),
                bypass_techniques=data.get("bypass_techniques", []),
            )
            
        except Exception as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return self._fallback_plan(round_number, vuln_class)
    
    def _extract_json(self, response: str) -> str:
        """Extrait le JSON d'une réponse qui peut contenir du markdown."""
        # Chercher un bloc ```json
        if "```json" in response:
            start = response.index("```json") + 7
            end = response.index("```", start)
            return response[start:end].strip()
        
        # Chercher un bloc ``` 
        if "```" in response:
            start = response.index("```") + 3
            end = response.index("```", start)
            return response[start:end].strip()
        
        # Chercher des accolades
        if "{" in response:
            start = response.index("{")
            end = response.rindex("}") + 1
            return response[start:end]
        
        return response
    
    def _fallback_plan(self, round_number: int, vuln_class: str) -> RoundNPlan:
        """Plan de fallback si le LLM échoue."""
        logger.warning(f"Using fallback plan for round {round_number}")
        
        # Payloads avec injection_point explicite pour body JSON
        fallback_payloads = {
            "IDOR": [
                PayloadSpec(payload="1018271054", injection_point="body:customer_id", reasoning="Adjacent ID - one less"),
                PayloadSpec(payload="1018271056", injection_point="body:customer_id", reasoning="Adjacent ID - one more"),
                PayloadSpec(payload="1", injection_point="body:customer_id", reasoning="Common low ID"),
                PayloadSpec(payload="0", injection_point="body:customer_id", reasoning="Boundary test - zero"),
                PayloadSpec(payload="99999999", injection_point="body:customer_id", reasoning="Large ID test"),
            ],
            "SQLI": [
                PayloadSpec(payload="1'", injection_point="body", reasoning="Single quote test"),
                PayloadSpec(payload="1 OR 1=1", injection_point="body", reasoning="Basic OR injection"),
            ],
            "XSS": [
                PayloadSpec(payload="<img/src=x>", injection_point="body", reasoning="Image tag test"),
                PayloadSpec(payload="javascript:alert(1)", injection_point="body", reasoning="JS protocol"),
            ],
        }
        
        payloads = fallback_payloads.get(
            vuln_class.upper(), 
            [PayloadSpec(payload="test", injection_point="body", reasoning="Generic test")]
        )
        
        return RoundNPlan(
            round_number=round_number,
            vuln_class=vuln_class,
            payloads=payloads,
            reasoning="Fallback plan - LLM unavailable",
        )

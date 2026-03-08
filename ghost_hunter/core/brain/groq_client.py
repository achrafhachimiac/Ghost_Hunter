"""
Ghost-Hunter Groq Client
========================
Client pour l'API Groq (Llama 8B/70B ultra-rapide).

Compatible avec l'interface OpenRouterClient pour un drop-in replacement.

Usage:
    client = GroqClient()  # Uses GROQ_API_KEY from env
    response = client.chat([{"role": "user", "content": "Hello"}])
    print(response.content)
"""

import os
import time
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Import conditionnel du SDK Groq
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    Groq = None  # type: ignore
    logger.warning("Groq SDK not installed. Run: pip install groq")

# Import AIResponse depuis openrouter_client pour compatibilité
from ghost_hunter.core.brain.openrouter_client import AIResponse


class GroqClient:
    """
    Client pour Groq API.
    
    Interface compatible avec OpenRouterClient pour permettre
    un switch transparent entre les providers.
    """
    
    # Modèles disponibles sur Groq (updated Jan 2026)
    MODELS = {
        # Tier 1 - Ultra rapide, pas de RAG
        "llama-8b": "llama-3.1-8b-instant",
        "llama-8b-instant": "llama-3.1-8b-instant",
        "tier1": "llama-3.1-8b-instant",
        
        # Tier 2 - Plus puissant, avec RAG (updated to 3.3)
        "llama-70b": "llama-3.3-70b-versatile",
        "llama-70b-versatile": "llama-3.3-70b-versatile",
        "tier2": "llama-3.3-70b-versatile",
        
        # Aliases pour compatibilité avec OpenRouterClient
        "haiku": "llama-3.1-8b-instant",  # Tier 1 = quick triage
        "sonnet": "llama-3.3-70b-versatile",  # Tier 2 = full triage
    }
    
    # Rate limits Groq (free tier)
    RATE_LIMITS = {
        "requests_per_minute": 30,
        "tokens_per_minute": 14400,
        "tokens_per_day": 500000,
    }
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        default_model: str = "llama-8b",
        timeout: int = 30,
        max_retries: int = 3,
        requests_per_minute: Optional[int] = None
    ):
        """
        Args:
            api_key: Clé API Groq (ou GROQ_API_KEY depuis env)
            default_model: Modèle par défaut
            timeout: Timeout en secondes
            max_retries: Nombre de retries
            requests_per_minute: Override rate limit (for testing)
        """
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("GROQ_API_KEY not set. Get one at https://console.groq.com")
        
        self.default_model = default_model
        self.timeout = timeout
        self.max_retries = max_retries
        self.requests_per_minute = requests_per_minute or self.RATE_LIMITS["requests_per_minute"]
        
        # Init client (séparé pour faciliter les tests)
        self._init_client()
        
        # Stats
        self.total_tokens_input = 0
        self.total_tokens_output = 0
        self.total_requests = 0
        self.total_tokens = 0  # Alias pour compatibilité tests
        
        # Rate limiting
        self._request_times: List[float] = []
    
    def _init_client(self):
        """Initialise le client Groq. Séparé pour faciliter les mocks."""
        if not GROQ_AVAILABLE:
            raise ImportError("Groq SDK not installed. Run: pip install groq")
        self.client = Groq(api_key=self.api_key)
    
    def _check_rate_limit(self):
        """Vérifie et attend si nécessaire pour respecter le rate limit."""
        now = time.time()
        minute_ago = now - 60
        
        # Nettoyer les vieux timestamps
        self._request_times = [
            ts for ts in self._request_times if ts > minute_ago
        ]
        
        # Vérifier si on dépasse la limite
        if len(self._request_times) >= self.requests_per_minute:
            wait_time = self._request_times[0] - minute_ago + 1
            logger.warning(f"Rate limit approaching, waiting {wait_time:.1f}s...")
            time.sleep(wait_time)
        
        self._request_times.append(now)
    
    def _resolve_model(self, model: Optional[str]) -> str:
        """Résout un alias de modèle en nom complet."""
        if model is None:
            return self.MODELS.get(self.default_model, self.default_model)
        return self.MODELS.get(model, model)
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        system_prompt: Optional[str] = None
    ) -> AIResponse:
        """
        Envoie une requête de chat.
        
        Interface identique à OpenRouterClient.chat() pour compatibilité.
        
        Args:
            messages: Liste de messages [{"role": "user", "content": "..."}]
            model: Modèle à utiliser (override default)
            temperature: Température (0-1)
            max_tokens: Tokens max en sortie
            system_prompt: Prompt système optionnel
            
        Returns:
            AIResponse avec le contenu et les métadonnées
        """
        model_id = self._resolve_model(model)
        
        # Ajouter le system prompt si fourni
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages
        
        # Rate limiting
        self._check_rate_limit()
        
        start_time = time.time()
        
        for attempt in range(self.max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=model_id,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                
                latency = (time.time() - start_time) * 1000
                
                # Extraire les infos
                content = response.choices[0].message.content
                tokens_in = response.usage.prompt_tokens if response.usage else 0
                tokens_out = response.usage.completion_tokens if response.usage else 0
                
                # Mettre à jour les stats
                self.total_tokens_input += tokens_in
                self.total_tokens_output += tokens_out
                self.total_requests += 1
                self.total_tokens = self.total_tokens_input + self.total_tokens_output
                
                logger.debug(f"Groq Response: {tokens_in} in, {tokens_out} out, {latency:.0f}ms")
                
                return AIResponse(
                    content=content,
                    model=model_id,
                    tokens_input=tokens_in,
                    tokens_output=tokens_out,
                    latency_ms=latency,
                    raw_response=response.model_dump() if hasattr(response, 'model_dump') else None
                )
                
            except Exception as e:
                error_str = str(e).lower()
                
                # Rate limited
                if "rate" in error_str or "429" in error_str:
                    wait_time = 2 ** attempt
                    logger.warning(f"Rate limited, waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                
                # Timeout
                if "timeout" in error_str:
                    if attempt < self.max_retries - 1:
                        logger.warning(f"Timeout, retry {attempt + 1}/{self.max_retries}")
                        continue
                
                logger.error(f"Groq API error: {e}")
                raise
        
        raise Exception(f"Failed after {self.max_retries} attempts")
    
    def quick_ask(
        self,
        question: str,
        model: str = "llama-8b",
        system_prompt: Optional[str] = None
    ) -> str:
        """Raccourci pour une question simple."""
        response = self.chat(
            messages=[{"role": "user", "content": question}],
            model=model,
            system_prompt=system_prompt
        )
        return response.content
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques d'utilisation."""
        # Pricing Groq (approximatif)
        llama_8b_price_in = 0.05 / 1_000_000  # $0.05 per 1M tokens
        llama_8b_price_out = 0.08 / 1_000_000
        llama_70b_price_in = 0.59 / 1_000_000  # $0.59 per 1M tokens
        llama_70b_price_out = 0.79 / 1_000_000
        
        # Estimation (assume 70% 8B, 30% 70B based on tier usage)
        avg_price_in = llama_8b_price_in * 0.7 + llama_70b_price_in * 0.3
        avg_price_out = llama_8b_price_out * 0.7 + llama_70b_price_out * 0.3
        
        estimated_cost = (
            self.total_tokens_input * avg_price_in +
            self.total_tokens_output * avg_price_out
        )
        
        return {
            "total_requests": self.total_requests,
            "total_tokens": self.total_tokens,
            "total_tokens_input": self.total_tokens_input,
            "total_tokens_output": self.total_tokens_output,
            "estimated_cost_usd": round(estimated_cost, 6),
            "rate_limit_remaining": self.requests_per_minute - len(self._request_times)
        }
    
    def close(self):
        """Ferme le client (no-op pour Groq SDK)."""
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def get_groq_client(
    api_key: Optional[str] = None,
    default_model: str = "llama-8b"
) -> GroqClient:
    """
    Factory function pour créer un client Groq.
    
    Args:
        api_key: Clé API (ou depuis env)
        default_model: Modèle par défaut
        
    Returns:
        Instance de GroqClient
    """
    return GroqClient(api_key=api_key, default_model=default_model)

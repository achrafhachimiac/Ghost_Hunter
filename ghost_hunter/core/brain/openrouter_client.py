"""
Ghost-Hunter OpenRouter Client
==============================
Client HTTP pour l'API OpenRouter (Claude Haiku/Sonnet).
"""

import time
import httpx
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AIResponse:
    """Réponse structurée de l'API."""
    content: str
    model: str
    tokens_input: int
    tokens_output: int
    latency_ms: float
    raw_response: Optional[Dict] = None


class OpenRouterClient:
    """Client pour OpenRouter API."""
    
    BASE_URL = "https://openrouter.ai/api/v1"
    
    # Modèles disponibles
    MODELS = {
        "haiku": "anthropic/claude-3.5-haiku",
        "sonnet": "anthropic/claude-3.5-sonnet",
    }
    
    def __init__(
        self,
        api_key: str,
        default_model: str = "haiku",
        timeout: int = 60,
        max_retries: int = 3
    ):
        """
        Args:
            api_key: Clé API OpenRouter
            default_model: Modèle par défaut (haiku ou sonnet)
            timeout: Timeout en secondes
            max_retries: Nombre de retries
        """
        self.api_key = api_key
        self.default_model = self.MODELS.get(default_model, default_model)
        self.timeout = timeout
        self.max_retries = max_retries
        
        self._client = httpx.Client(
            base_url=self.BASE_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://ghost-hunter.local",
                "X-Title": "Ghost-Hunter"
            },
            timeout=timeout
        )
        
        # Stats
        self.total_tokens_input = 0
        self.total_tokens_output = 0
        self.total_requests = 0
    
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
        
        Args:
            messages: Liste de messages [{"role": "user", "content": "..."}]
            model: Modèle à utiliser (override default)
            temperature: Température (0-1)
            max_tokens: Tokens max en sortie
            system_prompt: Prompt système optionnel
            
        Returns:
            AIResponse avec le contenu et les métadonnées
        """
        model_id = self.MODELS.get(model, model) if model else self.default_model
        
        # Ajouter le system prompt si fourni
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages
        
        payload = {
            "model": model_id,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        start_time = time.time()
        
        for attempt in range(self.max_retries):
            try:
                response = self._client.post("/chat/completions", json=payload)
                response.raise_for_status()
                
                data = response.json()
                latency = (time.time() - start_time) * 1000
                
                # Extraire les infos
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                tokens_in = usage.get("prompt_tokens", 0)
                tokens_out = usage.get("completion_tokens", 0)
                
                # Mettre à jour les stats
                self.total_tokens_input += tokens_in
                self.total_tokens_output += tokens_out
                self.total_requests += 1
                
                logger.debug(f"AI Response: {tokens_in} in, {tokens_out} out, {latency:.0f}ms")
                
                return AIResponse(
                    content=content,
                    model=model_id,
                    tokens_input=tokens_in,
                    tokens_output=tokens_out,
                    latency_ms=latency,
                    raw_response=data
                )
                
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    # Rate limited, attendre
                    wait_time = 2 ** attempt
                    logger.warning(f"Rate limited, waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                logger.error(f"HTTP error: {e.response.status_code}")
                raise
            except httpx.TimeoutException:
                if attempt < self.max_retries - 1:
                    logger.warning(f"Timeout, retry {attempt + 1}/{self.max_retries}")
                    continue
                raise
        
        raise Exception(f"Failed after {self.max_retries} attempts")
    
    def quick_ask(
        self,
        question: str,
        model: str = "haiku",
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
        # Pricing approximatif OpenRouter
        haiku_price_in = 0.00025 / 1000
        haiku_price_out = 0.00125 / 1000
        sonnet_price_in = 0.003 / 1000
        sonnet_price_out = 0.015 / 1000
        
        # Estimation (assume 50% haiku, 50% sonnet)
        avg_price_in = (haiku_price_in + sonnet_price_in) / 2
        avg_price_out = (haiku_price_out + sonnet_price_out) / 2
        
        estimated_cost = (
            self.total_tokens_input * avg_price_in +
            self.total_tokens_output * avg_price_out
        )
        
        return {
            "total_requests": self.total_requests,
            "total_tokens_input": self.total_tokens_input,
            "total_tokens_output": self.total_tokens_output,
            "estimated_cost_usd": round(estimated_cost, 4)
        }
    
    def close(self):
        """Ferme le client."""
        self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

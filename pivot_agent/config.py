"""
Pivot Agent Configuration
Supports OpenRouter for flexible model switching
"""
import os
import yaml
from pathlib import Path
from typing import Optional

# ==================== API Configuration ====================

# Ghost-Hunter API
GHOST_HUNTER_API_URL = os.getenv("GHOST_HUNTER_API_URL", "http://localhost:1010")

# Load API keys from yaml config
def _load_api_keys() -> dict:
    """Load API keys from config/api_keys.yaml"""
    config_path = Path(__file__).parent.parent / "config" / "api_keys.yaml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}

_api_config = _load_api_keys()

# ==================== OpenRouter Configuration ====================

OPENROUTER_API_KEY = os.getenv(
    "OPENROUTER_API_KEY", 
    _api_config.get("openrouter", {}).get("api_key", "")
)
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Model configuration - easily switchable
OPENROUTER_MODELS = {
    "default": "anthropic/claude-3.5-sonnet",  # Best for complex reasoning
    "fast": "anthropic/claude-3.5-haiku",       # Faster, cheaper
    "powerful": "anthropic/claude-3-opus",      # Most capable
    "fallback": "google/gemini-pro-1.5",        # If Claude is filtered
    "uncensored": "meta-llama/llama-3.1-70b-instruct",  # Less restrictive
}

# ==================== Cost-Efficient Model Routing ====================
# Haiku pour le triage (analyse simple, extraction)
# Sonnet pour l'attaque (réflexion stratégique, décisions)

MODEL_TRIAGE = os.getenv("MODEL_TRIAGE", "anthropic/claude-3.5-haiku")    # Cheap: ~$0.25/M input
MODEL_ATTACK = os.getenv("MODEL_ATTACK", "anthropic/claude-3.5-sonnet")   # Smart: ~$3/M input

# Default model selection
LLM_MODEL = os.getenv("LLM_MODEL", OPENROUTER_MODELS["default"])
LLM_TEMPERATURE = 0.1  # Low temperature for precise reasoning

# Legacy Anthropic (optional fallback)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# ==================== OpenRouter Headers ====================

OPENROUTER_HEADERS = {
    "HTTP-Referer": "https://ghost-hunter.local",  # Required by OpenRouter
    "X-Title": "Ghost-Hunter AI Pivot Agent",      # Shows in OpenRouter dashboard
}

# ==================== Redis Configuration ====================

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))

# Agent logs channel prefix
AGENT_LOGS_CHANNEL = "agent:logs"  # Full channel: agent:logs:{log_id}

# ==================== Agent Configuration ====================

MAX_ITERATIONS = 10  # Maximum pivot cycles
MAX_REQUESTS_PER_CYCLE = 5  # Limit API calls per cycle
VERBOSE_LOGGING = True

# Paths
BASE_DIR = Path(__file__).parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Rate limiting
REQUEST_DELAY_MS = 500  # Delay between requests in ms
RATE_LIMIT_DELAY = REQUEST_DELAY_MS / 1000  # Delay in seconds
REQUEST_TIMEOUT = 30.0  # HTTP request timeout in seconds

# Knowledge Base
KNOWLEDGE_BASE_PATH = str(Path(__file__).parent.parent / "knowledge")


# ==================== LLM Factory ====================

def get_llm(model: Optional[str] = None, temperature: Optional[float] = None):
    """
    Factory function to get a configured LLM instance.
    Uses OpenRouter by default for flexibility.
    
    Args:
        model: Model name (e.g., 'anthropic/claude-3.5-sonnet')
        temperature: Generation temperature (0.0-1.0)
    
    Returns:
        Configured LangChain chat model
    """
    from langchain_openai import ChatOpenAI
    
    return ChatOpenAI(
        model=model or LLM_MODEL,
        temperature=temperature if temperature is not None else LLM_TEMPERATURE,
        max_tokens=4096,
        openai_api_key=OPENROUTER_API_KEY,
        openai_api_base=OPENROUTER_BASE_URL,
        default_headers=OPENROUTER_HEADERS,
    )


def get_fast_llm():
    """Get fast/cheap model for simple tasks"""
    return get_llm(model=OPENROUTER_MODELS["fast"])


def get_powerful_llm():
    """Get most capable model for complex reasoning"""
    return get_llm(model=OPENROUTER_MODELS["powerful"])


# ==================== Cost-Efficient Model Functions ====================

def get_triage_llm():
    """
    Get the TRIAGE model (Haiku) for simple extraction/analysis tasks.
    
    Used by:
    - Analyzer: Extract patterns, identify IDOR candidates
    - Researcher: Enrich targets with knowledge base
    
    Cost: ~$0.25/M input tokens, ~$1.25/M output tokens
    """
    return get_llm(model=MODEL_TRIAGE)


def get_attack_llm():
    """
    Get the ATTACK model (Sonnet) for strategic reasoning tasks.
    
    Used by:
    - Strategist: Create detailed attack plans
    - Pivoter: Make pivot/continue/stop decisions
    
    Cost: ~$3/M input tokens, ~$15/M output tokens
    """
    return get_llm(model=MODEL_ATTACK)


def switch_model(model_key: str) -> str:
    """
    Switch to a different model.
    
    Args:
        model_key: One of 'default', 'fast', 'powerful', 'fallback', 'uncensored'
    
    Returns:
        The new model name
    """
    global LLM_MODEL
    if model_key in OPENROUTER_MODELS:
        LLM_MODEL = OPENROUTER_MODELS[model_key]
    return LLM_MODEL


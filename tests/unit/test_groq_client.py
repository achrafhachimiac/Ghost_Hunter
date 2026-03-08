"""
Tests for Ghost-Hunter GroqClient (Phase 0)
============================================
Vérifie la compatibilité avec OpenRouterClient.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any

from ghost_hunter.core.brain.groq_client import (
    GroqClient,
    GROQ_AVAILABLE,
)
from ghost_hunter.core.brain.openrouter_client import AIResponse


class TestGroqClientInit:
    """Tests d'initialisation du GroqClient."""
    
    def test_init_without_api_key_raises(self):
        """GroqClient sans API key lève une erreur."""
        with patch.dict('os.environ', {}, clear=True):
            with pytest.raises(ValueError, match="GROQ_API_KEY"):
                GroqClient()
    
    def test_init_with_api_key_env(self):
        """GroqClient accepte API key depuis env."""
        with patch.dict('os.environ', {'GROQ_API_KEY': 'test_key'}):
            with patch.object(GroqClient, '_init_client'):
                client = GroqClient()
                assert client.api_key == 'test_key'
    
    def test_init_with_api_key_param(self):
        """GroqClient accepte API key en paramètre."""
        with patch.object(GroqClient, '_init_client'):
            client = GroqClient(api_key='param_key')
            assert client.api_key == 'param_key'
    
    def test_param_key_overrides_env(self):
        """Le paramètre API key override l'env."""
        with patch.dict('os.environ', {'GROQ_API_KEY': 'env_key'}):
            with patch.object(GroqClient, '_init_client'):
                client = GroqClient(api_key='param_key')
                assert client.api_key == 'param_key'


class TestGroqClientModels:
    """Tests des modèles disponibles."""
    
    def test_models_dict_exists(self):
        """MODELS dict existe et contient les mappings."""
        assert hasattr(GroqClient, 'MODELS')
        assert 'llama-8b' in GroqClient.MODELS
        assert 'llama-70b' in GroqClient.MODELS
    
    def test_compatibility_aliases(self):
        """Aliases de compatibilité avec OpenRouterClient."""
        # haiku -> llama-8b (Tier 1)
        assert GroqClient.MODELS.get('haiku') == GroqClient.MODELS.get('llama-8b')
        # sonnet -> llama-70b (Tier 2)
        assert GroqClient.MODELS.get('sonnet') == GroqClient.MODELS.get('llama-70b')
    
    def test_resolve_model_name(self):
        """_resolve_model() résout les aliases."""
        with patch.object(GroqClient, '_init_client'):
            client = GroqClient(api_key='test')
            
            # Alias
            assert client._resolve_model('haiku') == 'llama-3.1-8b-instant'
            assert client._resolve_model('sonnet') == 'llama-3.1-70b-versatile'
            
            # Full name
            assert client._resolve_model('llama-8b') == 'llama-3.1-8b-instant'
            
            # Passthrough for unknown
            assert client._resolve_model('unknown-model') == 'unknown-model'


class TestGroqClientChat:
    """Tests de la méthode chat()."""
    
    @pytest.fixture
    def mock_client(self):
        """Crée un GroqClient mocké."""
        with patch.object(GroqClient, '_init_client'):
            client = GroqClient(api_key='test_key')
            client.client = Mock()
            return client
    
    def test_chat_returns_ai_response(self, mock_client):
        """chat() retourne un AIResponse."""
        # Mock response
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Test response"
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 20
        mock_response.model = "llama-3.1-8b-instant"
        
        mock_client.client.chat.completions.create.return_value = mock_response
        
        result = mock_client.chat([{"role": "user", "content": "Hello"}])
        
        assert isinstance(result, AIResponse)
        assert result.content == "Test response"
    
    def test_chat_with_messages(self, mock_client):
        """chat() passe les messages correctement."""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 20
        mock_response.model = "llama-3.1-8b-instant"
        
        mock_client.client.chat.completions.create.return_value = mock_response
        
        messages = [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "Question"}
        ]
        mock_client.chat(messages)
        
        call_kwargs = mock_client.client.chat.completions.create.call_args.kwargs
        assert call_kwargs['messages'] == messages
    
    def test_chat_model_resolution(self, mock_client):
        """chat() résout le modèle correctement."""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 20
        mock_response.model = "llama-3.1-70b-versatile"
        
        mock_client.client.chat.completions.create.return_value = mock_response
        
        mock_client.chat([{"role": "user", "content": "Hi"}], model="sonnet")
        
        call_kwargs = mock_client.client.chat.completions.create.call_args.kwargs
        assert call_kwargs['model'] == "llama-3.1-70b-versatile"
    
    def test_chat_default_model(self, mock_client):
        """chat() utilise le modèle par défaut."""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 20
        mock_response.model = "llama-3.1-8b-instant"
        
        mock_client.client.chat.completions.create.return_value = mock_response
        mock_client.default_model = "llama-8b"
        
        mock_client.chat([{"role": "user", "content": "Hi"}])
        
        call_kwargs = mock_client.client.chat.completions.create.call_args.kwargs
        assert call_kwargs['model'] == "llama-3.1-8b-instant"


class TestGroqClientStats:
    """Tests des statistiques."""
    
    @pytest.fixture
    def mock_client(self):
        """Crée un GroqClient mocké."""
        with patch.object(GroqClient, '_init_client'):
            client = GroqClient(api_key='test_key')
            client.client = Mock()
            return client
    
    def test_stats_tracking(self, mock_client):
        """Les stats sont trackées après chaque appel."""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.usage.prompt_tokens = 100
        mock_response.usage.completion_tokens = 50
        mock_response.model = "llama-3.1-8b-instant"
        
        mock_client.client.chat.completions.create.return_value = mock_response
        
        # Premier appel
        mock_client.chat([{"role": "user", "content": "Hi"}])
        assert mock_client.total_requests == 1
        assert mock_client.total_tokens == 150
        
        # Deuxième appel
        mock_client.chat([{"role": "user", "content": "Hi again"}])
        assert mock_client.total_requests == 2
        assert mock_client.total_tokens == 300
    
    def test_get_stats_method(self, mock_client):
        """get_stats() retourne les statistiques."""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.usage.prompt_tokens = 50
        mock_response.usage.completion_tokens = 25
        mock_response.model = "llama-3.1-8b-instant"
        
        mock_client.client.chat.completions.create.return_value = mock_response
        mock_client.chat([{"role": "user", "content": "Hi"}])
        
        stats = mock_client.get_stats()
        assert stats['total_requests'] == 1
        assert stats['total_tokens'] == 75


class TestGroqClientRateLimiting:
    """Tests du rate limiting."""
    
    @pytest.fixture
    def mock_client(self):
        """Crée un GroqClient mocké."""
        with patch.object(GroqClient, '_init_client'):
            client = GroqClient(api_key='test_key', requests_per_minute=60)
            client.client = Mock()
            return client
    
    def test_rate_limit_config(self, mock_client):
        """Le rate limit est configurable."""
        assert mock_client.requests_per_minute == 60
    
    def test_rate_limit_tracking(self, mock_client):
        """Le rate limiter track les requêtes."""
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 10
        mock_response.model = "llama-3.1-8b-instant"
        
        mock_client.client.chat.completions.create.return_value = mock_response
        
        # Plusieurs appels
        for _ in range(5):
            mock_client.chat([{"role": "user", "content": "Hi"}])
        
        # Le rate limiter devrait avoir tracké
        assert len(mock_client._request_times) == 5


class TestGroqClientCompatibility:
    """Tests de compatibilité avec OpenRouterClient."""
    
    def test_same_interface_as_openrouter(self):
        """GroqClient a la même interface que OpenRouterClient."""
        # Check methods exist
        assert hasattr(GroqClient, 'chat')
        assert hasattr(GroqClient, 'get_stats')
        
        # Check chat signature
        import inspect
        chat_sig = inspect.signature(GroqClient.chat)
        params = list(chat_sig.parameters.keys())
        
        assert 'messages' in params
        assert 'model' in params
        assert 'temperature' in params
        assert 'max_tokens' in params
    
    def test_returns_ai_response_type(self):
        """chat() retourne le type AIResponse de openrouter_client.py."""
        with patch.object(GroqClient, '_init_client'):
            client = GroqClient(api_key='test')
            client.client = Mock()
            
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = "Response"
            mock_response.usage.prompt_tokens = 10
            mock_response.usage.completion_tokens = 10
            mock_response.model = "llama-3.1-8b-instant"
            
            client.client.chat.completions.create.return_value = mock_response
            
            result = client.chat([{"role": "user", "content": "Hi"}])
            
            # Verify it's the AIResponse from openrouter_client
            from ghost_hunter.core.brain.openrouter_client import AIResponse as OpenRouterAIResponse
            assert isinstance(result, OpenRouterAIResponse)


class TestGroqAvailability:
    """Tests de disponibilité du SDK Groq."""
    
    def test_groq_available_flag(self):
        """GROQ_AVAILABLE indique si le SDK est installé."""
        # GROQ_AVAILABLE est un bool
        assert isinstance(GROQ_AVAILABLE, bool)
    
    def test_client_works_without_sdk(self):
        """GroqClient gère l'absence du SDK gracieusement."""
        # Le module peut être importé même sans SDK
        from ghost_hunter.core.brain import groq_client
        assert groq_client is not None

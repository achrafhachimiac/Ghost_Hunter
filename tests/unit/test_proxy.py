"""
Tests for Ghost-Hunter Proxy Addon
"""

import pytest
from unittest.mock import MagicMock, Mock
from ghost_hunter.core.interceptor.proxy import GhostHunterAddon
from ghost_hunter.core.contracts import InterceptedRequest


class TestGhostHunterAddon:
    
    def test_addon_instantiation(self):
        addon = GhostHunterAddon()
        assert addon.request_callback is None
        assert addon.response_callback is None
        assert addon._request_store == {}
    
    def test_set_callbacks(self):
        addon = GhostHunterAddon()
        callback = Mock()
        addon.set_request_callback(callback)
        assert addon.request_callback == callback
        
        response_callback = Mock()
        addon.set_response_callback(response_callback)
        assert addon.response_callback == response_callback
    
    def test_parse_request_creates_intercepted_request(self):
        addon = GhostHunterAddon()
        
        # Mock du flow mitmproxy
        mock_flow = MagicMock()
        mock_flow.request.method = "GET"
        mock_flow.request.pretty_url = "https://example.com/api/users?id=123"
        mock_flow.request.host = "example.com"
        mock_flow.request.path = "/api/users"
        mock_flow.request.query = {"id": "123"}
        mock_flow.request.headers = {"Authorization": "Bearer token"}
        mock_flow.request.get_text.return_value = None
        mock_flow.client_conn.peername = ("127.0.0.1", 12345)
        
        result = addon._parse_request(mock_flow)
        
        assert isinstance(result, InterceptedRequest)
        assert result.method == "GET"
        assert result.host == "example.com"
        assert result.query_params == {"id": "123"}
        assert "Authorization" in result.headers
    
    def test_parse_request_with_json_body(self):
        addon = GhostHunterAddon()
        
        mock_flow = MagicMock()
        mock_flow.request.method = "POST"
        mock_flow.request.pretty_url = "https://example.com/api/users"
        mock_flow.request.host = "example.com"
        mock_flow.request.path = "/api/users"
        mock_flow.request.query = {}
        mock_flow.request.headers = {"Content-Type": "application/json"}
        mock_flow.request.get_text.return_value = '{"name": "test", "email": "test@test.com"}'
        mock_flow.client_conn.peername = ("127.0.0.1", 12345)
        
        result = addon._parse_request(mock_flow)
        
        assert result.body == '{"name": "test", "email": "test@test.com"}'
        assert result.body_json == {"name": "test", "email": "test@test.com"}
    
    def test_parse_request_with_cookies(self):
        addon = GhostHunterAddon()
        
        mock_flow = MagicMock()
        mock_flow.request.method = "GET"
        mock_flow.request.pretty_url = "https://example.com/"
        mock_flow.request.host = "example.com"
        mock_flow.request.path = "/"
        mock_flow.request.query = {}
        mock_flow.request.headers = {"cookie": "session=abc123; user=john"}
        mock_flow.request.get_text.return_value = None
        mock_flow.client_conn.peername = ("127.0.0.1", 12345)
        
        result = addon._parse_request(mock_flow)
        
        assert result.cookies == {"session": "abc123", "user": "john"}
    
    def test_request_callback_called(self):
        addon = GhostHunterAddon()
        callback = Mock()
        addon.set_request_callback(callback)
        
        mock_flow = MagicMock()
        mock_flow.id = "flow_123"
        mock_flow.request.method = "GET"
        mock_flow.request.pretty_url = "https://example.com/"
        mock_flow.request.host = "example.com"
        mock_flow.request.path = "/"
        mock_flow.request.query = {}
        mock_flow.request.headers = {}
        mock_flow.request.get_text.return_value = None
        mock_flow.client_conn.peername = ("127.0.0.1", 12345)
        
        addon.request(mock_flow)
        
        assert callback.called
        assert "flow_123" in addon._request_store
    
    def test_response_callback_called(self):
        addon = GhostHunterAddon()
        response_callback = Mock()
        addon.set_response_callback(response_callback)
        
        # First, simulate a request
        mock_flow = MagicMock()
        mock_flow.id = "flow_456"
        mock_flow.request.method = "GET"
        mock_flow.request.pretty_url = "https://example.com/"
        mock_flow.request.host = "example.com"
        mock_flow.request.path = "/"
        mock_flow.request.query = {}
        mock_flow.request.headers = {}
        mock_flow.request.get_text.return_value = None
        mock_flow.client_conn.peername = ("127.0.0.1", 12345)
        mock_flow.response = None
        
        addon.request(mock_flow)
        
        # Then simulate the response
        mock_flow.response = MagicMock()
        mock_flow.response.status_code = 200
        mock_flow.response.headers = {"Content-Type": "application/json"}
        mock_flow.response.get_text.return_value = '{"success": true}'
        mock_flow.response.timestamp_end = 1000.5
        mock_flow.request.timestamp_start = 1000.0
        
        addon.response(mock_flow)
        
        assert response_callback.called
        assert "flow_456" not in addon._request_store  # Cleaned up


class TestProxyIntegration:
    
    def test_full_request_response_flow(self):
        addon = GhostHunterAddon()
        captured_request = None
        captured_response = None
        
        def on_request(req):
            nonlocal captured_request
            captured_request = req
        
        def on_response(req):
            nonlocal captured_response
            captured_response = req
        
        addon.set_request_callback(on_request)
        addon.set_response_callback(on_response)
        
        # Create mock flow
        mock_flow = MagicMock()
        mock_flow.id = "test_flow"
        mock_flow.request.method = "POST"
        mock_flow.request.pretty_url = "https://api.example.com/users"
        mock_flow.request.host = "api.example.com"
        mock_flow.request.path = "/users"
        mock_flow.request.query = {"page": "1"}
        mock_flow.request.headers = {"Authorization": "Bearer token123"}
        mock_flow.request.get_text.return_value = '{"name": "John"}'
        mock_flow.client_conn.peername = ("192.168.1.100", 54321)
        
        # Process request
        addon.request(mock_flow)
        
        assert captured_request is not None
        assert captured_request.method == "POST"
        assert captured_request.host == "api.example.com"
        
        # Process response
        mock_flow.response = MagicMock()
        mock_flow.response.status_code = 201
        mock_flow.response.headers = {"Content-Type": "application/json"}
        mock_flow.response.get_text.return_value = '{"id": 123}'
        mock_flow.response.timestamp_end = None
        
        addon.response(mock_flow)
        
        assert captured_response is not None
        assert captured_response.response_status == 201
        assert captured_response.response_body == '{"id": 123}'

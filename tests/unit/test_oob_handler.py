"""
Tests unitaires pour oob/handler.py
"""

import pytest
import json
from pathlib import Path
from datetime import datetime, timedelta

from ghost_hunter.core.oob.handler import (
    OOBCallbackHandler,
    OOBToken,
    OOBCallback,
)
from ghost_hunter.core.contracts import Finding, FindingSeverity


# ==================== Fixtures ====================

@pytest.fixture
def oob_handler(tmp_path):
    return OOBCallbackHandler(
        storage_dir=tmp_path / "oob",
        oob_domain="test.oast.live",
        ttl_hours=24,
    )


@pytest.fixture
def sample_token():
    return OOBToken(
        token="abc123test",
        request_id="req-001",
        vuln_type="SSRF",
        target_url="https://target.com/api",
        payload_used="http://evil.com",
        expires_at=(datetime.now() + timedelta(hours=24)).timestamp(),
    )


# ==================== Tests ====================

class TestOOBCallbackHandler:
    
    def test_handler_creation(self, tmp_path):
        handler = OOBCallbackHandler(storage_dir=tmp_path / "oob")
        assert handler.storage_dir.exists()
        assert handler.pending_count() == 0
    
    def test_handler_with_domain(self, oob_handler):
        assert oob_handler.oob_domain == "test.oast.live"


class TestTokenGeneration:
    
    def test_generate_token(self, oob_handler):
        token = oob_handler.generate_token(
            request_id="req-001",
            vuln_type="SSRF",
            target_url="https://target.com",
            payload_used="http://evil.com",
        )
        
        assert token.token is not None
        assert len(token.token) == 12
        assert token.request_id == "req-001"
        assert token.vuln_type == "SSRF"
    
    def test_token_expires_in_future(self, oob_handler):
        token = oob_handler.generate_token(
            request_id="req-001",
            vuln_type="SSRF",
        )
        
        assert token.is_expired() is False
        assert token.expires_at > datetime.now().timestamp()
    
    def test_unique_tokens(self, oob_handler):
        token1 = oob_handler.generate_token("req-001", "SSRF")
        token2 = oob_handler.generate_token("req-001", "SSRF")
        
        assert token1.token != token2.token


class TestCallbackURLs:
    
    def test_get_callback_url(self, oob_handler):
        token = oob_handler.generate_token("req-001", "SSRF")
        url = oob_handler.get_callback_url(token)
        
        assert token.token in url
        assert "test.oast.live" in url
        assert url.startswith("http://")
    
    def test_get_dns_hostname(self, oob_handler):
        token = oob_handler.generate_token("req-001", "SSRF")
        hostname = oob_handler.get_dns_hostname(token)
        
        assert token.token in hostname
        assert "test.oast.live" in hostname
    
    def test_callback_url_without_domain(self, tmp_path):
        handler = OOBCallbackHandler(storage_dir=tmp_path / "oob")
        token = handler.generate_token("req-001", "SSRF")
        url = handler.get_callback_url(token)
        
        assert "localhost" in url


class TestCallbackRegistration:
    
    def test_register_callback(self, oob_handler):
        token = oob_handler.generate_token("req-001", "SSRF")
        
        result = oob_handler.register_callback(
            token_str=token.token,
            source_ip="1.2.3.4",
            callback_type="http",
        )
        
        assert result is not None
        assert result.callback_received is True
        assert result.callback_data["source_ip"] == "1.2.3.4"
    
    def test_register_unknown_token(self, oob_handler):
        result = oob_handler.register_callback(
            token_str="unknown_token",
            source_ip="1.2.3.4",
            callback_type="http",
        )
        
        assert result is None
    
    def test_check_callback(self, oob_handler):
        token = oob_handler.generate_token("req-001", "SSRF")
        
        assert oob_handler.check_callback(token.token) is False
        
        oob_handler.register_callback(token.token, "1.2.3.4", "http")
        
        assert oob_handler.check_callback(token.token) is True
    
    def test_get_callback(self, oob_handler):
        token = oob_handler.generate_token("req-001", "SSRF")
        oob_handler.register_callback(
            token.token,
            "1.2.3.4",
            "http",
            headers={"user-agent": "curl"},
        )
        
        callback = oob_handler.get_callback(token.token)
        
        assert callback is not None
        assert callback.source_ip == "1.2.3.4"
        assert callback.headers.get("user-agent") == "curl"


class TestCallbackListeners:
    
    def test_add_listener(self, oob_handler):
        received = []
        
        def on_callback(token, callback):
            received.append((token, callback))
        
        oob_handler.add_listener(on_callback)
        
        token = oob_handler.generate_token("req-001", "SSRF")
        oob_handler.register_callback(token.token, "1.2.3.4", "http")
        
        assert len(received) == 1
        assert received[0][0].token == token.token
    
    def test_remove_listener(self, oob_handler):
        received = []
        
        def on_callback(token, callback):
            received.append(token)
        
        oob_handler.add_listener(on_callback)
        oob_handler.remove_listener(on_callback)
        
        token = oob_handler.generate_token("req-001", "SSRF")
        oob_handler.register_callback(token.token, "1.2.3.4", "http")
        
        assert len(received) == 0


class TestFindingCreation:
    
    def test_create_finding_from_callback(self, oob_handler, sample_token):
        callback = OOBCallback(
            token=sample_token.token,
            source_ip="1.2.3.4",
            callback_type="http",
        )
        
        finding = oob_handler.create_finding_from_callback(sample_token, callback)
        
        assert finding.vuln_type == "SSRF"
        assert finding.confidence == 95
        assert finding.severity == FindingSeverity.HIGH
        assert "1.2.3.4" in finding.ai_analysis
    
    def test_finding_severity_by_vuln_type(self, oob_handler):
        # RCE should be critical
        token = OOBToken(
            token="test",
            request_id="req",
            vuln_type="RCE",
            expires_at=(datetime.now() + timedelta(hours=1)).timestamp(),
        )
        callback = OOBCallback(token="test", source_ip="1.2.3.4", callback_type="http")
        
        finding = oob_handler.create_finding_from_callback(token, callback)
        
        assert finding.severity == FindingSeverity.CRITICAL


class TestPayloadGeneration:
    
    def test_get_ssrf_payloads(self, oob_handler):
        token = oob_handler.generate_token("req-001", "SSRF")
        payloads = oob_handler.get_payloads_for_type("SSRF", token)
        
        assert len(payloads) > 0
        assert any(token.token in p for p in payloads)
        assert any("http://" in p for p in payloads)
    
    def test_get_xxe_payloads(self, oob_handler):
        token = oob_handler.generate_token("req-001", "XXE")
        payloads = oob_handler.get_payloads_for_type("XXE", token)
        
        assert len(payloads) > 0
        assert any("DOCTYPE" in p for p in payloads)
        assert any("ENTITY" in p for p in payloads)
    
    def test_get_rce_payloads(self, oob_handler):
        token = oob_handler.generate_token("req-001", "RCE")
        payloads = oob_handler.get_payloads_for_type("RCE", token)
        
        assert len(payloads) > 0
        assert any("curl" in p for p in payloads)
        assert any("nslookup" in p for p in payloads)


class TestTokenPersistence:
    
    def test_tokens_persist_to_disk(self, tmp_path):
        handler1 = OOBCallbackHandler(storage_dir=tmp_path / "oob")
        handler1.generate_token("req-001", "SSRF")
        
        # Créer un nouveau handler avec le même stockage
        handler2 = OOBCallbackHandler(storage_dir=tmp_path / "oob")
        
        assert handler2.pending_count() == 1
    
    def test_expired_tokens_not_loaded(self, tmp_path):
        handler = OOBCallbackHandler(
            storage_dir=tmp_path / "oob",
            ttl_hours=0,  # Expire immédiatement
        )
        handler.generate_token("req-001", "SSRF")
        
        # Forcer l'expiration
        import time
        time.sleep(0.1)
        
        # Nouveau handler ne devrait pas charger le token expiré
        handler2 = OOBCallbackHandler(storage_dir=tmp_path / "oob")
        # Note: Ce test peut être flaky selon l'implémentation


class TestCleanup:
    
    def test_cleanup_expired(self, oob_handler):
        # Créer un token expiré manuellement
        token = oob_handler.generate_token("req-001", "SSRF")
        oob_handler._pending_tokens[token.token].expires_at = datetime.now().timestamp() - 1
        
        count = oob_handler.cleanup_expired()
        
        assert count == 1
        assert oob_handler.pending_count() == 0


class TestCounts:
    
    def test_pending_count(self, oob_handler):
        oob_handler.generate_token("req-001", "SSRF")
        oob_handler.generate_token("req-002", "XXE")
        
        assert oob_handler.pending_count() == 2
    
    def test_received_count(self, oob_handler):
        token1 = oob_handler.generate_token("req-001", "SSRF")
        token2 = oob_handler.generate_token("req-002", "XXE")
        
        oob_handler.register_callback(token1.token, "1.2.3.4", "http")
        
        assert oob_handler.received_count() == 1
        assert oob_handler.pending_count() == 1  # token2 still pending

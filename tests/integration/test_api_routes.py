"""
Dashboard API Integration Tests
===============================
Tests de non-régression pour le refactoring api.py
"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Client de test FastAPI."""
    from dashboard.api import create_app
    app = create_app()
    return TestClient(app)


class TestCoreRoutes:
    """Test des routes core."""
    
    def test_root(self, client):
        """GET / doit retourner status ok."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "Ghost Hunter" in data["message"]
    
    def test_stats(self, client):
        """GET /api/stats doit retourner les stats."""
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        # Vérifier structure minimale (knowledge_base est toujours présent)
        assert "knowledge_base" in data or "endpoints" in data or "duration_seconds" in data


class TestServicesRoutes:
    """Test des routes services."""
    
    def test_services_health(self, client):
        """GET /api/services/health doit retourner le status."""
        response = client.get("/api/services/health")
        assert response.status_code == 200
        data = response.json()
        assert "services" in data or "status" in data


class TestEndpointsRoutes:
    """Test des routes endpoints."""
    
    def test_endpoints_list(self, client):
        """GET /api/endpoints doit retourner une liste."""
        response = client.get("/api/endpoints")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        assert "endpoints" in data or "items" in data or isinstance(data.get("data"), list)
    
    def test_endpoints_summary(self, client):
        """GET /api/endpoints/summary doit retourner un résumé."""
        response = client.get("/api/endpoints/summary")
        assert response.status_code == 200


class TestBurpRoutes:
    """Test des routes Burp."""
    
    def test_burp_status(self, client):
        """GET /api/burp/status doit fonctionner."""
        response = client.get("/api/burp/status")
        assert response.status_code == 200


class TestTriageRoutes:
    """Test des routes triage."""
    
    def test_triage_history(self, client):
        """GET /api/triage/history doit retourner l'historique."""
        response = client.get("/api/triage/history")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or "history" in data


class TestConfigRoutes:
    """Test des routes config."""
    
    def test_config_scope(self, client):
        """GET /api/config/scope doit retourner le scope."""
        response = client.get("/api/config/scope")
        assert response.status_code == 200


class TestFindingsRoutes:
    """Test des routes findings."""
    
    def test_findings_list(self, client):
        """GET /api/findings doit retourner une liste."""
        response = client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestSecurityRoutes:
    """Test des routes security."""
    
    def test_security_list(self, client):
        """GET /api/security doit fonctionner."""
        response = client.get("/api/security")
        assert response.status_code == 200


class TestKBRoutes:
    """Test des routes knowledge base."""
    
    def test_kb_status(self, client):
        """GET /api/kb/status doit fonctionner."""
        response = client.get("/api/kb/status")
        assert response.status_code == 200


class TestNucleiRoutes:
    """Test des routes nuclei."""
    
    def test_nuclei(self, client):
        """GET /api/nuclei doit fonctionner."""
        response = client.get("/api/nuclei")
        assert response.status_code == 200
    
    def test_knowledge(self, client):
        """GET /api/knowledge doit fonctionner."""
        response = client.get("/api/knowledge")
        assert response.status_code == 200

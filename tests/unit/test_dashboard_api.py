"""
Tests pour l'API du Dashboard.
"""

import pytest
from fastapi.testclient import TestClient

from dashboard.api import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(data_dir=tmp_path)
    return TestClient(app)


class TestDashboardAPI:
    
    def test_root(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
    
    def test_get_stats_empty(self, client):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_intercepted"] == 0
        assert data["findings_by_severity"]["critical"] == 0
    
    def test_list_requests_empty(self, client):
        response = client.get("/api/requests")
        assert response.status_code == 200
        assert response.json() == []
    
    def test_add_request(self, client):
        response = client.post("/api/requests", json={
            "method": "GET",
            "url": "https://example.com/api",
            "host": "example.com",
            "path": "/api",
        })
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
    
    def test_list_requests_after_add(self, client):
        # Add a request
        client.post("/api/requests", json={
            "method": "POST",
            "url": "https://test.com/login",
            "host": "test.com",
            "path": "/login",
            "score": 75,
        })
        
        # List
        response = client.get("/api/requests")
        assert response.status_code == 200
        requests = response.json()
        assert len(requests) == 1
        assert requests[0]["method"] == "POST"
        assert requests[0]["score"] == 75
    
    def test_list_findings_empty(self, client):
        response = client.get("/api/findings")
        assert response.status_code == 200
        assert response.json() == []
    
    def test_add_finding(self, client):
        response = client.post("/api/findings", json={
            "endpoint": "https://example.com/api/users/1",
            "vuln_type": "IDOR",
            "severity": "high",
            "confidence": 85,
        })
        assert response.status_code == 200
    
    def test_list_findings_after_add(self, client):
        client.post("/api/findings", json={
            "endpoint": "https://example.com/search",
            "vuln_type": "SQLi",
            "severity": "critical",
            "confidence": 90,
        })
        
        response = client.get("/api/findings")
        findings = response.json()
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "SQLi"
        assert findings[0]["severity"] == "critical"
    
    def test_stats_update_on_findings(self, client):
        # Add findings of different severities
        client.post("/api/findings", json={"severity": "critical", "vuln_type": "RCE"})
        client.post("/api/findings", json={"severity": "high", "vuln_type": "SQLi"})
        client.post("/api/findings", json={"severity": "medium", "vuln_type": "XSS"})
        
        response = client.get("/api/stats")
        stats = response.json()
        
        assert stats["findings_by_severity"]["critical"] == 1
        assert stats["findings_by_severity"]["high"] == 1
        assert stats["findings_by_severity"]["medium"] == 1
    
    def test_scan_status_default(self, client):
        response = client.get("/api/scan/status")
        assert response.status_code == 200
        assert response.json()["active"] is False
    
    def test_start_scan(self, client):
        response = client.post("/api/scan/start", json={
            "target_scope": ["example.com"],
        })
        assert response.status_code == 200
        
        status = client.get("/api/scan/status").json()
        assert status["active"] is True
    
    def test_stop_scan(self, client):
        client.post("/api/scan/start", json={"target_scope": ["test.com"]})
        
        response = client.post("/api/scan/stop")
        assert response.status_code == 200
        
        status = client.get("/api/scan/status").json()
        assert status["active"] is False
    
    def test_clear_all(self, client):
        # Add some data
        client.post("/api/requests", json={"method": "GET", "url": "test"})
        client.post("/api/findings", json={"vuln_type": "XSS", "severity": "low"})
        
        # Clear
        response = client.delete("/api/clear")
        assert response.status_code == 200
        
        # Verify empty
        assert client.get("/api/requests").json() == []
        assert client.get("/api/findings").json() == []
    
    def test_request_not_found(self, client):
        response = client.get("/api/requests/nonexistent")
        assert response.status_code == 404
    
    def test_finding_not_found(self, client):
        response = client.get("/api/findings/nonexistent")
        assert response.status_code == 404
    
    def test_filter_requests_by_score(self, client):
        client.post("/api/requests", json={"method": "GET", "url": "low", "score": 20})
        client.post("/api/requests", json={"method": "GET", "url": "high", "score": 80})
        
        # Filter by min_score
        response = client.get("/api/requests?min_score=50")
        requests = response.json()
        
        assert len(requests) == 1
        assert requests[0]["score"] == 80
    
    def test_filter_findings_by_severity(self, client):
        client.post("/api/findings", json={"vuln_type": "Low", "severity": "low"})
        client.post("/api/findings", json={"vuln_type": "Critical", "severity": "critical"})
        
        response = client.get("/api/findings?severity=critical")
        findings = response.json()
        
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

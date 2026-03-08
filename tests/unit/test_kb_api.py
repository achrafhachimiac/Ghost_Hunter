"""
Tests for Knowledge Base API Endpoints
======================================
"""

import pytest
from unittest.mock import patch, MagicMock, Mock
from fastapi.testclient import TestClient

# Import the app factory
from dashboard.api import create_app


@pytest.fixture
def client():
    """Create test client."""
    app = create_app()
    return TestClient(app)


class TestKBStatusEndpoint:
    """Tests for GET /api/kb/status."""
    
    @patch('ghost_hunter.cli.kb_commands.get_kb_status')
    def test_status_healthy(self, mock_get_status, client):
        """Test status endpoint with healthy store."""
        from ghost_hunter.cli.kb_commands import KBStatus
        
        mock_get_status.return_value = KBStatus(
            total_chunks=1000,
            chunks_by_source={'nvd': 500, 'hacktricks': 500},
            last_sync={'nvd': '2024-01-01T00:00:00'},
            vector_store_healthy=True,
            errors=[]
        )
        
        response = client.get("/api/kb/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data['total_chunks'] == 1000
        assert data['vector_store_healthy'] == True
    
    @patch('ghost_hunter.cli.kb_commands.get_kb_status')
    def test_status_unhealthy(self, mock_get_status, client):
        """Test status endpoint with unhealthy store."""
        from ghost_hunter.cli.kb_commands import KBStatus
        
        mock_get_status.return_value = KBStatus(
            total_chunks=0,
            chunks_by_source={},
            last_sync={},
            vector_store_healthy=False,
            errors=['Store not initialized']
        )
        
        response = client.get("/api/kb/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data['vector_store_healthy'] == False
        assert len(data['errors']) > 0


class TestKBSyncEndpoint:
    """Tests for POST /api/kb/sync."""
    
    @patch('ghost_hunter.cli.kb_commands.sync_source')
    def test_sync_single_source(self, mock_sync, client):
        """Test syncing a single source."""
        mock_sync.return_value = {
            'source': 'cve',
            'success': True,
            'chunks_added': 100,
            'errors': []
        }
        
        response = client.post("/api/kb/sync?source=cve")
        
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == True
        assert data['chunks_added'] == 100
    
    @patch('ghost_hunter.cli.kb_commands.sync_source')
    def test_sync_all_sources(self, mock_sync, client):
        """Test syncing all sources."""
        mock_sync.side_effect = [
            {'source': 'cve', 'success': True, 'chunks_added': 100, 'errors': []},
            {'source': 'hacktricks', 'success': True, 'chunks_added': 200, 'errors': []},
            {'source': 'nuclei', 'success': True, 'chunks_added': 50, 'errors': []},
            {'source': 'personal', 'success': True, 'chunks_added': 10, 'errors': []},
            {'source': 'disclosures', 'success': True, 'chunks_added': 150, 'errors': []}
        ]
        
        response = client.post("/api/kb/sync?source=all")
        
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == True
        assert data['total_chunks_added'] == 510  # 100 + 200 + 50 + 10 + 150
    
    @patch('ghost_hunter.cli.kb_commands.sync_source')
    def test_sync_with_force(self, mock_sync, client):
        """Test syncing with force flag."""
        mock_sync.return_value = {
            'source': 'hacktricks',
            'success': True,
            'chunks_added': 200,
            'errors': []
        }
        
        response = client.post("/api/kb/sync?source=hacktricks&force=true")
        
        assert response.status_code == 200
        mock_sync.assert_called_once_with('hacktricks', force=True)


class TestKBSearchEndpoint:
    """Tests for GET /api/kb/search."""
    
    @patch('ghost_hunter.cli.kb_commands.search_kb')
    def test_search_returns_results(self, mock_search, client):
        """Test search endpoint with results."""
        mock_search.return_value = {
            'query': 'SQL injection',
            'results': [
                {'content': 'SQL injection info', 'source': 'nvd', 'score': 0.95}
            ],
            'total': 1,
            'errors': []
        }
        
        response = client.get("/api/kb/search?q=SQL%20injection")
        
        assert response.status_code == 200
        data = response.json()
        assert data['total'] == 1
        assert len(data['results']) == 1
    
    @patch('ghost_hunter.cli.kb_commands.search_kb')
    def test_search_with_limit(self, mock_search, client):
        """Test search endpoint with custom limit."""
        mock_search.return_value = {
            'query': 'IDOR',
            'results': [],
            'total': 0,
            'errors': []
        }
        
        response = client.get("/api/kb/search?q=IDOR&limit=5")
        
        assert response.status_code == 200
        mock_search.assert_called_once_with('IDOR', limit=5)
    
    def test_search_missing_query(self, client):
        """Test search endpoint without query."""
        response = client.get("/api/kb/search")
        
        # FastAPI returns 422 for missing required query param
        assert response.status_code == 422


class TestKBAddReportEndpoint:
    """Tests for POST /api/kb/add-report."""
    
    @patch('ghost_hunter.cli.kb_commands.add_report')
    def test_add_report_success(self, mock_add, client):
        """Test adding a report successfully."""
        mock_add.return_value = {
            'file': '/path/to/report.md',
            'success': True,
            'chunks_added': 5,
            'errors': []
        }
        
        response = client.post("/api/kb/add-report?path=/path/to/report.md")
        
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == True
        assert data['chunks_added'] == 5
    
    @patch('ghost_hunter.cli.kb_commands.add_report')
    def test_add_report_failure(self, mock_add, client):
        """Test adding a report that fails."""
        mock_add.return_value = {
            'file': '/nonexistent/report.md',
            'success': False,
            'chunks_added': 0,
            'errors': ['File not found']
        }
        
        response = client.post("/api/kb/add-report?path=/nonexistent/report.md")
        
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == False


class TestKBRebuildEndpoint:
    """Tests for POST /api/kb/rebuild."""
    
    @patch('ghost_hunter.cli.kb_commands.rebuild_kb')
    def test_rebuild_success(self, mock_rebuild, client):
        """Test rebuilding KB successfully."""
        mock_rebuild.return_value = {
            'success': True,
            'total_chunks': 500,
            'chunks_by_source': {'nvd': 200, 'hacktricks': 300},
            'errors': []
        }
        
        response = client.post("/api/kb/rebuild")
        
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == True
        assert data['total_chunks'] == 500
    
    @patch('ghost_hunter.cli.kb_commands.rebuild_kb')
    def test_rebuild_failure(self, mock_rebuild, client):
        """Test rebuilding KB with failures."""
        mock_rebuild.return_value = {
            'success': False,
            'total_chunks': 100,
            'chunks_by_source': {'nvd': 100},
            'errors': ['HackTricks sync failed']
        }
        
        response = client.post("/api/kb/rebuild")
        
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == False
        assert 'HackTricks sync failed' in data['errors']

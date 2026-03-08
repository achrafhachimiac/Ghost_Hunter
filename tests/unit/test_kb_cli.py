"""
Tests for Ghost-Hunter Knowledge Base CLI Commands
==================================================
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock
import tempfile

from ghost_hunter.cli.kb_commands import (
    KBStatus,
    get_kb_status,
    sync_source,
    add_report,
    search_kb,
    rebuild_kb,
    main,
    print_status,
    print_search_results
)


class TestKBStatus:
    """Tests for KBStatus dataclass."""
    
    def test_kb_status_creation(self):
        """Test KBStatus creation."""
        status = KBStatus(
            total_chunks=1000,
            chunks_by_source={'nvd': 500, 'hacktricks': 500},
            last_sync={'nvd': '2024-01-01T00:00:00'},
            vector_store_healthy=True,
            errors=[]
        )
        
        assert status.total_chunks == 1000
        assert status.chunks_by_source['nvd'] == 500
        assert status.vector_store_healthy == True
    
    def test_kb_status_to_dict(self):
        """Test KBStatus to_dict method."""
        status = KBStatus(
            total_chunks=100,
            chunks_by_source={'nvd': 100},
            last_sync={},
            vector_store_healthy=True,
            errors=[]
        )
        
        result = status.to_dict()
        
        assert result['total_chunks'] == 100
        assert result['vector_store_healthy'] == True


class TestGetKBStatus:
    """Tests for get_kb_status function."""
    
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_status_with_healthy_store(self, mock_get_store):
        """Test status when vector store is healthy."""
        mock_store = MagicMock()
        mock_store.get_stats.return_value = {
            'total_chunks': 1000,
            'chunks_by_source': {'nvd': 500, 'hacktricks': 500}
        }
        mock_get_store.return_value = mock_store
        
        status = get_kb_status()
        
        assert status.vector_store_healthy == True
        assert status.total_chunks == 1000
        assert len(status.errors) == 0
    
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_status_with_no_store(self, mock_get_store):
        """Test status when vector store is unavailable."""
        mock_get_store.return_value = None
        
        status = get_kb_status()
        
        assert status.vector_store_healthy == False
        assert status.total_chunks == 0
        assert len(status.errors) > 0
    
    def test_status_with_import_error(self):
        """Test status when RAG module import fails."""
        with patch.dict('sys.modules', {'ghost_hunter.core.rag.vector_store': None}):
            # This should handle the import error gracefully
            status = get_kb_status()
            
            # Either works or returns error status
            assert isinstance(status, KBStatus)


class TestSyncSource:
    """Tests for sync_source function."""
    
    @patch('ghost_hunter.core.rag.ingestors.nvd.NVDIngestor')
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_sync_cve_source(self, mock_get_store, mock_ingestor_class):
        """Test syncing CVE/NVD source."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store
        
        mock_ingestor = MagicMock()
        mock_chunks = [MagicMock(), MagicMock()]
        mock_ingestor.ingest.return_value = mock_chunks
        mock_ingestor_class.return_value = mock_ingestor
        
        result = sync_source('cve')
        
        assert result['success'] == True
        assert result['chunks_added'] == 2
        mock_store.add_chunks.assert_called_once_with(mock_chunks)
    
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_sync_unknown_source(self, mock_get_store):
        """Test syncing unknown source."""
        mock_get_store.return_value = MagicMock()
        
        result = sync_source('unknown_source')
        
        assert result['success'] == False
        assert len(result['errors']) > 0
    
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_sync_no_store(self, mock_get_store):
        """Test sync when vector store unavailable."""
        mock_get_store.return_value = None
        
        result = sync_source('cve')
        
        assert result['success'] == False
        assert 'Vector store not initialized' in result['errors']


class TestAddReport:
    """Tests for add_report function."""
    
    @patch('ghost_hunter.core.rag.ingestors.personal.PersonalReportsIngestor')
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_add_valid_report(self, mock_get_store, mock_ingestor_class):
        """Test adding a valid report file."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store
        
        mock_ingestor = MagicMock()
        mock_chunks = [MagicMock(), MagicMock(), MagicMock()]
        mock_ingestor.ingest_file.return_value = mock_chunks
        mock_ingestor_class.return_value = mock_ingestor
        
        with tempfile.NamedTemporaryFile(suffix='.md', delete=False) as f:
            f.write(b"# Test Report\n\nContent here")
            temp_path = f.name
        
        try:
            result = add_report(temp_path)
            
            assert result['success'] == True
            assert result['chunks_added'] == 3
        finally:
            Path(temp_path).unlink()
    
    def test_add_nonexistent_file(self):
        """Test adding a file that doesn't exist."""
        result = add_report('/nonexistent/path/report.md')
        
        assert result['success'] == False
        assert 'File not found' in result['errors'][0]
    
    def test_add_non_markdown_file(self):
        """Test adding a non-markdown file."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"Some text")
            temp_path = f.name
        
        try:
            result = add_report(temp_path)
            
            assert result['success'] == False
            assert 'Not a markdown file' in result['errors'][0]
        finally:
            Path(temp_path).unlink()


class TestSearchKB:
    """Tests for search_kb function."""
    
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_search_returns_results(self, mock_get_store):
        """Test search returns formatted results."""
        mock_store = Mock(spec=['query_sync'])  # Only has query_sync
        
        # Create mock chunks
        mock_chunk1 = MagicMock()
        mock_chunk1.content = "SQL Injection vulnerability in login form"
        mock_chunk1.metadata = {'source': 'nvd', 'score': 0.95}
        
        mock_chunk2 = MagicMock()
        mock_chunk2.content = "IDOR in user profile API"
        mock_chunk2.metadata = {'source': 'hacktricks', 'score': 0.85}
        
        mock_store.query_sync.return_value = [
            (mock_chunk1, 0.95),
            (mock_chunk2, 0.85)
        ]
        mock_get_store.return_value = mock_store
        
        result = search_kb("SQL injection")
        
        assert result['total'] == 2
        assert len(result['results']) == 2
        assert result['results'][0]['source'] == 'nvd'
        assert len(result['errors']) == 0
    
    def test_search_empty_query(self):
        """Test search with empty query."""
        result = search_kb("")
        
        assert result['total'] == 0
        assert 'Empty query' in result['errors']
    
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_search_truncates_long_content(self, mock_get_store):
        """Test that search truncates long content."""
        mock_store = Mock(spec=['query_sync'])  # Only has query_sync
        
        mock_chunk = MagicMock()
        mock_chunk.content = "A" * 1000  # Very long content
        mock_chunk.metadata = {'source': 'test', 'score': 0.9}
        
        mock_store.query_sync.return_value = [(mock_chunk, 0.9)]
        mock_get_store.return_value = mock_store
        
        result = search_kb("test")
        
        # Content should be truncated to 500 chars + ...
        assert len(result['results'][0]['content']) == 503
    
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_search_no_store(self, mock_get_store):
        """Test search when store unavailable."""
        mock_get_store.return_value = None
        
        result = search_kb("test query")
        
        assert result['total'] == 0
        assert 'Vector store not available' in result['errors']


class TestRebuildKB:
    """Tests for rebuild_kb function."""
    
    @patch('ghost_hunter.cli.kb_commands.sync_source')
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_rebuild_success(self, mock_get_store, mock_sync):
        """Test successful rebuild."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store
        
        # Mock successful syncs
        mock_sync.side_effect = [
            {'success': True, 'chunks_added': 100, 'errors': []},  # nvd
            {'success': True, 'chunks_added': 200, 'errors': []},  # hacktricks
            {'success': True, 'chunks_added': 50, 'errors': []},   # nuclei
            {'success': True, 'chunks_added': 10, 'errors': []}    # personal
        ]
        
        result = rebuild_kb()
        
        assert result['success'] == True
        assert result['total_chunks'] == 360
        mock_store.clear.assert_called_once()
    
    @patch('ghost_hunter.cli.kb_commands.sync_source')
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_rebuild_partial_failure(self, mock_get_store, mock_sync):
        """Test rebuild with partial failures."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store
        
        mock_sync.side_effect = [
            {'success': True, 'chunks_added': 100, 'errors': []},
            {'success': False, 'chunks_added': 0, 'errors': ['HackTricks error']},
            {'success': True, 'chunks_added': 50, 'errors': []},
            {'success': True, 'chunks_added': 10, 'errors': []}
        ]
        
        result = rebuild_kb()
        
        assert result['success'] == False  # Has errors
        assert result['total_chunks'] == 160
        assert 'HackTricks error' in result['errors']


class TestCLIMain:
    """Tests for CLI main function."""
    
    def test_no_command_shows_help(self, capsys):
        """Test that no command shows help."""
        result = main([])
        
        assert result == 1
        captured = capsys.readouterr()
        # Should have printed help
    
    @patch('ghost_hunter.cli.kb_commands.get_kb_status')
    def test_status_command(self, mock_get_status, capsys):
        """Test status command."""
        mock_get_status.return_value = KBStatus(
            total_chunks=100,
            chunks_by_source={'nvd': 100},
            last_sync={},
            vector_store_healthy=True,
            errors=[]
        )
        
        result = main(['status'])
        
        assert result == 0
        captured = capsys.readouterr()
        assert 'Knowledge Base Status' in captured.out
    
    @patch('ghost_hunter.cli.kb_commands.get_kb_status')
    def test_status_command_json(self, mock_get_status, capsys):
        """Test status command with JSON output."""
        mock_get_status.return_value = KBStatus(
            total_chunks=100,
            chunks_by_source={'nvd': 100},
            last_sync={},
            vector_store_healthy=True,
            errors=[]
        )
        
        result = main(['--json', 'status'])
        
        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output['total_chunks'] == 100
    
    @patch('ghost_hunter.cli.kb_commands.sync_source')
    def test_sync_cve_command(self, mock_sync, capsys):
        """Test sync-cve command."""
        mock_sync.return_value = {
            'source': 'cve',
            'success': True,
            'chunks_added': 50,
            'errors': []
        }
        
        result = main(['sync-cve'])
        
        assert result == 0
        mock_sync.assert_called_once_with('cve', force=False)
    
    @patch('ghost_hunter.cli.kb_commands.sync_source')
    def test_sync_hacktricks_command(self, mock_sync, capsys):
        """Test sync-hacktricks command."""
        mock_sync.return_value = {
            'source': 'hacktricks',
            'success': True,
            'chunks_added': 100,
            'errors': []
        }
        
        result = main(['sync-hacktricks'])
        
        assert result == 0
        mock_sync.assert_called_once_with('hacktricks', force=False)
    
    @patch('ghost_hunter.cli.kb_commands.sync_source')
    def test_sync_generic_command(self, mock_sync, capsys):
        """Test generic sync command."""
        mock_sync.return_value = {
            'source': 'nuclei',
            'success': True,
            'chunks_added': 30,
            'errors': []
        }
        
        result = main(['sync', 'nuclei', '--force'])
        
        assert result == 0
        mock_sync.assert_called_once_with('nuclei', force=True)
    
    @patch('ghost_hunter.cli.kb_commands.add_report')
    def test_add_report_command(self, mock_add, capsys):
        """Test add-report command."""
        mock_add.return_value = {
            'file': '/path/to/report.md',
            'success': True,
            'chunks_added': 5,
            'errors': []
        }
        
        result = main(['add-report', '/path/to/report.md'])
        
        assert result == 0
        mock_add.assert_called_once_with('/path/to/report.md')
    
    @patch('ghost_hunter.cli.kb_commands.search_kb')
    def test_search_command(self, mock_search, capsys):
        """Test search command."""
        mock_search.return_value = {
            'query': 'SQL injection',
            'results': [{'content': 'Test', 'source': 'nvd', 'score': 0.9}],
            'total': 1,
            'errors': []
        }
        
        result = main(['search', 'SQL', 'injection'])
        
        assert result == 0
        mock_search.assert_called_once_with('SQL injection', limit=10)
    
    @patch('ghost_hunter.cli.kb_commands.search_kb')
    def test_search_command_with_limit(self, mock_search, capsys):
        """Test search command with limit."""
        mock_search.return_value = {
            'query': 'IDOR',
            'results': [],
            'total': 0,
            'errors': []
        }
        
        result = main(['search', 'IDOR', '--limit', '5'])
        
        mock_search.assert_called_once_with('IDOR', limit=5)
    
    def test_rebuild_requires_confirm(self, capsys):
        """Test rebuild command requires confirmation."""
        result = main(['rebuild'])
        
        assert result == 1
        captured = capsys.readouterr()
        assert '--confirm' in captured.out
    
    @patch('ghost_hunter.cli.kb_commands.rebuild_kb')
    def test_rebuild_with_confirm(self, mock_rebuild, capsys):
        """Test rebuild command with confirmation."""
        mock_rebuild.return_value = {
            'success': True,
            'total_chunks': 500,
            'chunks_by_source': {'nvd': 200, 'hacktricks': 300},
            'errors': []
        }
        
        result = main(['rebuild', '--confirm'])
        
        assert result == 0
        mock_rebuild.assert_called_once()


class TestPrintFunctions:
    """Tests for print helper functions."""
    
    def test_print_status_healthy(self, capsys):
        """Test printing healthy status."""
        status = KBStatus(
            total_chunks=1000,
            chunks_by_source={'nvd': 500, 'hacktricks': 500},
            last_sync={'nvd': '2024-01-01T00:00:00'},
            vector_store_healthy=True,
            errors=[]
        )
        
        print_status(status)
        
        captured = capsys.readouterr()
        assert '✅' in captured.out
        assert '1,000' in captured.out or '1000' in captured.out
    
    def test_print_status_unhealthy(self, capsys):
        """Test printing unhealthy status."""
        status = KBStatus(
            total_chunks=0,
            chunks_by_source={},
            last_sync={},
            vector_store_healthy=False,
            errors=['Store not initialized']
        )
        
        print_status(status)
        
        captured = capsys.readouterr()
        assert '❌' in captured.out
        assert 'Store not initialized' in captured.out
    
    def test_print_search_results(self, capsys):
        """Test printing search results."""
        results = {
            'query': 'SQL injection',
            'results': [
                {'content': 'Test content', 'source': 'nvd', 'score': 0.95},
                {'content': 'More content', 'source': 'hacktricks', 'score': 0.85}
            ],
            'total': 2,
            'errors': []
        }
        
        print_search_results(results)
        
        captured = capsys.readouterr()
        assert 'SQL injection' in captured.out
        assert 'Found 2 results' in captured.out
    
    def test_print_search_no_results(self, capsys):
        """Test printing when no results."""
        results = {
            'query': 'nothing',
            'results': [],
            'total': 0,
            'errors': []
        }
        
        print_search_results(results)
        
        captured = capsys.readouterr()
        assert 'No results found' in captured.out

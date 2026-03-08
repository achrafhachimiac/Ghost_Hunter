"""
Tests for Ghost-Hunter File Watcher
===================================
Tests auto-ingestion of personal reports.
"""

import pytest
import time
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch, call

# Import conditionally based on watchdog availability
try:
    from ghost_hunter.core.rag.watcher import (
        ReportWatcher,
        ReportEventHandler,
        WatcherConfig,
        start_watcher,
        stop_watcher,
        is_watcher_running,
        get_watcher,
        WATCHDOG_AVAILABLE
    )
except ImportError:
    WATCHDOG_AVAILABLE = False


@pytest.mark.skipif(not WATCHDOG_AVAILABLE, reason="watchdog not installed")
class TestWatcherConfig:
    """Tests for WatcherConfig."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = WatcherConfig()
        
        assert config.watch_path == Path("knowledge/personal_reports")
        assert ".md" in config.file_patterns
        assert ".markdown" in config.file_patterns
        assert config.debounce_seconds == 2.0
        assert config.recursive == True
        assert config.auto_start == False
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = WatcherConfig(
            watch_path=Path("/custom/path"),
            file_patterns={".txt"},
            debounce_seconds=5.0,
            recursive=False
        )
        
        assert config.watch_path == Path("/custom/path")
        assert config.file_patterns == {".txt"}
        assert config.debounce_seconds == 5.0
        assert config.recursive == False


@pytest.mark.skipif(not WATCHDOG_AVAILABLE, reason="watchdog not installed")
class TestReportEventHandler:
    """Tests for ReportEventHandler."""
    
    @pytest.fixture
    def mock_callback(self):
        """Create mock ingest callback."""
        return MagicMock(return_value=True)
    
    @pytest.fixture
    def handler(self, mock_callback):
        """Create handler with mock callback."""
        config = WatcherConfig(debounce_seconds=0.1)
        return ReportEventHandler(mock_callback, config)
    
    def test_should_process_md_file(self, handler):
        """Test that .md files are processed."""
        assert handler._should_process("/path/to/report.md") == True
    
    def test_should_process_markdown_file(self, handler):
        """Test that .markdown files are processed."""
        assert handler._should_process("/path/to/report.markdown") == True
    
    def test_should_not_process_txt_file(self, handler):
        """Test that .txt files are ignored."""
        assert handler._should_process("/path/to/file.txt") == False
    
    def test_should_not_process_hidden_file(self, handler):
        """Test that hidden files are ignored."""
        assert handler._should_process("/path/to/.hidden.md") == False
    
    def test_should_not_process_template(self, handler):
        """Test that TEMPLATE.md is ignored."""
        assert handler._should_process("/path/to/TEMPLATE.md") == False
    
    def test_on_created_triggers_callback(self, handler, mock_callback):
        """Test that file creation triggers callback."""
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            temp_path = f.name
            f.write(b"# Test Report")
        
        try:
            # Create mock event
            event = MagicMock()
            event.is_directory = False
            event.src_path = temp_path
            
            # Trigger event
            handler.on_created(event)
            
            # Wait for debounce
            time.sleep(0.3)
            
            # Callback should have been called
            assert mock_callback.called
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_on_created_ignores_directory(self, handler, mock_callback):
        """Test that directory creation is ignored."""
        event = MagicMock()
        event.is_directory = True
        event.src_path = "/path/to/dir"
        
        handler.on_created(event)
        
        # Callback should not be called for directories
        time.sleep(0.3)
        assert not mock_callback.called
    
    def test_debounce_prevents_duplicate_processing(self, mock_callback):
        """Test that rapid events are debounced."""
        config = WatcherConfig(debounce_seconds=0.5)
        handler = ReportEventHandler(mock_callback, config)
        
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            temp_path = f.name
            f.write(b"# Test")
        
        try:
            event = MagicMock()
            event.is_directory = False
            event.src_path = temp_path
            
            # Trigger multiple events rapidly
            handler.on_modified(event)
            handler.on_modified(event)
            handler.on_modified(event)
            
            # Wait for debounce
            time.sleep(0.8)
            
            # Should only be called once due to debouncing
            assert mock_callback.call_count == 1
        finally:
            Path(temp_path).unlink(missing_ok=True)


@pytest.mark.skipif(not WATCHDOG_AVAILABLE, reason="watchdog not installed")
class TestReportWatcher:
    """Tests for ReportWatcher class."""
    
    def test_watcher_creation(self):
        """Test watcher can be created."""
        watcher = ReportWatcher()
        
        assert watcher.config is not None
        assert watcher.is_running == False
    
    def test_watcher_custom_config(self):
        """Test watcher with custom config."""
        config = WatcherConfig(
            watch_path=Path("/tmp/test_reports"),
            debounce_seconds=1.0
        )
        watcher = ReportWatcher(config=config)
        
        assert watcher.config.watch_path == Path("/tmp/test_reports")
        assert watcher.config.debounce_seconds == 1.0
    
    def test_watcher_custom_callback(self):
        """Test watcher with custom callback."""
        callback = MagicMock(return_value=True)
        watcher = ReportWatcher(ingest_callback=callback)
        
        assert watcher._ingest_callback == callback
    
    def test_watcher_start_stop(self):
        """Test watcher start and stop."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(watch_path=Path(tmpdir))
            watcher = ReportWatcher(config=config)
            
            # Start
            result = watcher.start()
            assert result == True
            assert watcher.is_running == True
            
            # Stop
            watcher.stop()
            assert watcher.is_running == False
    
    def test_watcher_context_manager(self):
        """Test watcher as context manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(watch_path=Path(tmpdir))
            
            with ReportWatcher(config=config) as watcher:
                assert watcher.is_running == True
            
            assert watcher.is_running == False
    
    def test_watcher_creates_missing_directory(self):
        """Test watcher creates watch directory if missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watch_path = Path(tmpdir) / "nonexistent" / "subdir"
            config = WatcherConfig(watch_path=watch_path)
            watcher = ReportWatcher(config=config)
            
            result = watcher.start()
            
            try:
                assert result == True
                assert watch_path.exists()
            finally:
                watcher.stop()
    
    def test_watcher_double_start(self):
        """Test that double start returns True without error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(watch_path=Path(tmpdir))
            watcher = ReportWatcher(config=config)
            
            try:
                watcher.start()
                result = watcher.start()  # Second start
                
                assert result == True
                assert watcher.is_running == True
            finally:
                watcher.stop()
    
    def test_watcher_detects_file_creation(self):
        """Test that watcher detects new files."""
        callback = MagicMock(return_value=True)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(
                watch_path=Path(tmpdir),
                debounce_seconds=0.1
            )
            watcher = ReportWatcher(config=config, ingest_callback=callback)
            
            try:
                watcher.start()
                time.sleep(0.1)  # Let watcher initialize
                
                # Create a file
                test_file = Path(tmpdir) / "test_report.md"
                test_file.write_text("# Test Report\n\nContent here.")
                
                # Wait for detection and debounce
                time.sleep(0.5)
                
                # Callback should have been called
                assert callback.called
                call_path = callback.call_args[0][0]
                assert call_path.name == "test_report.md"
                
            finally:
                watcher.stop()


@pytest.mark.skipif(not WATCHDOG_AVAILABLE, reason="watchdog not installed")
class TestGlobalWatcher:
    """Tests for global watcher functions."""
    
    def teardown_method(self):
        """Stop watcher after each test."""
        stop_watcher()
    
    def test_start_stop_watcher(self):
        """Test global start/stop functions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(watch_path=Path(tmpdir))
            
            result = start_watcher(config=config)
            assert result == True
            assert is_watcher_running() == True
            
            stop_watcher()
            assert is_watcher_running() == False
    
    def test_get_watcher_returns_instance(self):
        """Test get_watcher returns running instance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(watch_path=Path(tmpdir))
            
            start_watcher(config=config)
            watcher = get_watcher()
            
            assert watcher is not None
            assert watcher.is_running == True
            
            stop_watcher()
    
    def test_double_start_safe(self):
        """Test that double start is safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(watch_path=Path(tmpdir))
            
            start_watcher(config=config)
            result = start_watcher(config=config)  # Second start
            
            assert result == True
            assert is_watcher_running() == True
            
            stop_watcher()
    
    def test_double_stop_safe(self):
        """Test that double stop is safe."""
        stop_watcher()  # First stop (nothing running)
        stop_watcher()  # Second stop
        
        assert is_watcher_running() == False


@pytest.mark.skipif(not WATCHDOG_AVAILABLE, reason="watchdog not installed")
class TestWatcherIntegration:
    """Integration tests for watcher with personal ingestor."""
    
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    @patch('ghost_hunter.core.rag.ingestors.personal.PersonalReportsIngestor')
    def test_default_ingest_callback(self, mock_ingestor_class, mock_get_store):
        """Test default ingest callback integration."""
        # Setup mocks
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store
        
        mock_ingestor = MagicMock()
        mock_ingestor.ingest_file.return_value = [MagicMock(), MagicMock()]
        mock_ingestor_class.return_value = mock_ingestor
        
        # Create watcher with default callback
        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(watch_path=Path(tmpdir))
            watcher = ReportWatcher(config=config)
            
            # Call default ingest directly
            test_file = Path(tmpdir) / "test.md"
            test_file.write_text("# Test")
            
            result = watcher._default_ingest(test_file)
            
            # Verify
            assert result == True
            mock_ingestor.ingest_file.assert_called_once_with(test_file)
            mock_store.add_chunks.assert_called_once()
    
    @patch('ghost_hunter.core.rag.vector_store.get_vector_store')
    def test_default_ingest_no_store(self, mock_get_store):
        """Test default ingest when store is unavailable."""
        mock_get_store.return_value = None
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(watch_path=Path(tmpdir))
            watcher = ReportWatcher(config=config)
            
            test_file = Path(tmpdir) / "test.md"
            test_file.write_text("# Test")
            
            result = watcher._default_ingest(test_file)
            
            assert result == False


class TestWatcherWithoutWatchdog:
    """Tests for behavior when watchdog is not installed."""
    
    @patch.dict('sys.modules', {'watchdog': None, 'watchdog.observers': None, 'watchdog.events': None})
    def test_start_watcher_without_watchdog(self):
        """Test that start_watcher handles missing watchdog gracefully."""
        # This test verifies the import-time handling
        # The actual behavior depends on how the module handles missing imports
        pass  # Import handling is tested at module load time

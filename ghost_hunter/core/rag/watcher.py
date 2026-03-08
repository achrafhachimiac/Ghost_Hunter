"""
Ghost-Hunter File Watcher
=========================
Auto-ingest personal reports when files are created/modified.

Usage:
    from ghost_hunter.core.rag.watcher import start_watcher, stop_watcher
    
    # Start watching (background thread)
    start_watcher()
    
    # Stop watching
    stop_watcher()
"""

import logging
import threading
import time
from pathlib import Path
from typing import Optional, Callable, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Optional watchdog import
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None  # type: ignore
    FileSystemEventHandler = object  # type: ignore
    logger.warning("watchdog not installed. Run: pip install watchdog")


@dataclass
class WatcherConfig:
    """Configuration for file watcher."""
    watch_path: Path = field(default_factory=lambda: Path("knowledge/personal_reports"))
    file_patterns: Set[str] = field(default_factory=lambda: {".md", ".markdown"})
    debounce_seconds: float = 2.0  # Wait before processing (avoid duplicate events)
    recursive: bool = True
    auto_start: bool = False  # Don't start automatically


class ReportEventHandler(FileSystemEventHandler):
    """Handle file system events for personal reports."""
    
    def __init__(
        self,
        ingest_callback: Callable[[Path], bool],
        config: WatcherConfig
    ):
        """
        Args:
            ingest_callback: Function to call when a file should be ingested.
                            Should return True on success, False on failure.
            config: Watcher configuration
        """
        super().__init__()
        self.ingest_callback = ingest_callback
        self.config = config
        self._pending: dict[str, float] = {}  # path -> timestamp for debouncing
        self._lock = threading.Lock()
    
    def _should_process(self, path: str) -> bool:
        """Check if file should be processed."""
        p = Path(path)
        
        # Check extension
        if p.suffix.lower() not in self.config.file_patterns:
            return False
        
        # Skip hidden files
        if p.name.startswith('.'):
            return False
        
        # Skip TEMPLATE.md
        if p.name == "TEMPLATE.md":
            return False
        
        return True
    
    def _debounce_process(self, path: str):
        """Process file after debounce delay."""
        with self._lock:
            if path not in self._pending:
                return
            
            scheduled_time = self._pending[path]
            if time.time() < scheduled_time:
                return
            
            del self._pending[path]
        
        # Process file
        try:
            file_path = Path(path)
            if not file_path.exists():
                logger.debug(f"File no longer exists: {path}")
                return
            
            logger.info(f"📄 Auto-ingesting: {file_path.name}")
            success = self.ingest_callback(file_path)
            
            if success:
                logger.info(f"✅ Auto-ingested: {file_path.name}")
            else:
                logger.warning(f"⚠️ Failed to ingest: {file_path.name}")
                
        except Exception as e:
            logger.error(f"❌ Error ingesting {path}: {e}")
    
    def _schedule_process(self, path: str):
        """Schedule file for processing after debounce delay."""
        with self._lock:
            self._pending[path] = time.time() + self.config.debounce_seconds
        
        # Schedule processing
        timer = threading.Timer(
            self.config.debounce_seconds + 0.1,
            self._debounce_process,
            args=[path]
        )
        timer.daemon = True
        timer.start()
    
    def on_created(self, event):
        """Handle file creation."""
        if event.is_directory:
            return
        
        if self._should_process(event.src_path):
            logger.debug(f"📁 File created: {event.src_path}")
            self._schedule_process(event.src_path)
    
    def on_modified(self, event):
        """Handle file modification."""
        if event.is_directory:
            return
        
        if self._should_process(event.src_path):
            logger.debug(f"📝 File modified: {event.src_path}")
            self._schedule_process(event.src_path)


class ReportWatcher:
    """
    Watch for personal report files and auto-ingest them.
    
    Usage:
        watcher = ReportWatcher()
        watcher.start()
        # ... later ...
        watcher.stop()
    """
    
    def __init__(
        self,
        config: Optional[WatcherConfig] = None,
        ingest_callback: Optional[Callable[[Path], bool]] = None
    ):
        """
        Args:
            config: Watcher configuration. Uses defaults if None.
            ingest_callback: Custom ingest function. Uses default if None.
        """
        if not WATCHDOG_AVAILABLE:
            raise ImportError("watchdog not installed. Run: pip install watchdog")
        
        self.config = config or WatcherConfig()
        self._ingest_callback = ingest_callback or self._default_ingest
        self._observer: Optional[Observer] = None
        self._running = False
    
    def _default_ingest(self, file_path: Path) -> bool:
        """Default ingestion using PersonalReportsIngestor."""
        try:
            from ghost_hunter.core.rag.ingestors.personal import PersonalReportsIngestor
            from ghost_hunter.core.rag.vector_store import get_vector_store
            
            # Get vector store
            store = get_vector_store()
            if not store:
                logger.error("Vector store not available")
                return False
            
            # Create ingestor and ingest single file
            ingestor = PersonalReportsIngestor()
            chunks = ingestor.ingest_file(file_path)
            
            if not chunks:
                logger.warning(f"No chunks generated from {file_path}")
                return False
            
            # Add to vector store
            store.add_chunks(chunks)
            logger.info(f"Added {len(chunks)} chunks from {file_path.name}")
            return True
            
        except Exception as e:
            logger.error(f"Ingest error: {e}")
            return False
    
    @property
    def is_running(self) -> bool:
        """Check if watcher is running."""
        return self._running and self._observer is not None
    
    @property
    def watch_path(self) -> Path:
        """Get the path being watched."""
        return self.config.watch_path
    
    def start(self) -> bool:
        """
        Start watching for file changes.
        
        Returns:
            True if started successfully, False otherwise
        """
        if self._running:
            logger.warning("Watcher already running")
            return True
        
        # Ensure watch path exists
        watch_path = self.config.watch_path
        if not watch_path.is_absolute():
            # Try relative to project root
            project_root = Path(__file__).parent.parent.parent.parent
            watch_path = project_root / self.config.watch_path
        
        if not watch_path.exists():
            try:
                watch_path.mkdir(parents=True, exist_ok=True)
                logger.info(f"📁 Created watch directory: {watch_path}")
            except Exception as e:
                logger.error(f"Failed to create watch directory: {e}")
                return False
        
        try:
            # Create event handler
            handler = ReportEventHandler(
                ingest_callback=self._ingest_callback,
                config=self.config
            )
            
            # Create and start observer
            self._observer = Observer()
            self._observer.schedule(
                handler,
                str(watch_path),
                recursive=self.config.recursive
            )
            self._observer.start()
            self._running = True
            
            logger.info(f"👁️ Watching for reports: {watch_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start watcher: {e}")
            self._observer = None
            self._running = False
            return False
    
    def stop(self):
        """Stop watching for file changes."""
        if not self._running:
            return
        
        try:
            if self._observer:
                self._observer.stop()
                self._observer.join(timeout=5.0)
                self._observer = None
            
            self._running = False
            logger.info("👁️ Watcher stopped")
            
        except Exception as e:
            logger.error(f"Error stopping watcher: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


# Global watcher instance
_global_watcher: Optional[ReportWatcher] = None
_watcher_lock = threading.Lock()


def get_watcher() -> Optional[ReportWatcher]:
    """Get the global watcher instance."""
    return _global_watcher


def start_watcher(config: Optional[WatcherConfig] = None) -> bool:
    """
    Start the global file watcher.
    
    Args:
        config: Optional configuration override
        
    Returns:
        True if started successfully
    """
    global _global_watcher
    
    if not WATCHDOG_AVAILABLE:
        logger.warning("watchdog not installed, watcher disabled")
        return False
    
    with _watcher_lock:
        if _global_watcher is not None and _global_watcher.is_running:
            logger.debug("Watcher already running")
            return True
        
        try:
            _global_watcher = ReportWatcher(config=config)
            return _global_watcher.start()
        except Exception as e:
            logger.error(f"Failed to start watcher: {e}")
            return False


def stop_watcher():
    """Stop the global file watcher."""
    global _global_watcher
    
    with _watcher_lock:
        if _global_watcher is not None:
            _global_watcher.stop()
            _global_watcher = None


def is_watcher_running() -> bool:
    """Check if the global watcher is running."""
    return _global_watcher is not None and _global_watcher.is_running

"""
Ghost-Hunter RAG Ingestors
==========================
Plugins pour ingérer différentes sources de données.

Chaque ingestor implémente BaseIngestor et s'enregistre via @IngestorRegistry.register()
"""

from .base import BaseIngestor, IngestorConfig
from .registry import IngestorRegistry

__all__ = [
    "BaseIngestor",
    "IngestorConfig", 
    "IngestorRegistry",
]

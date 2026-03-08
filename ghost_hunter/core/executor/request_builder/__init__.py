"""
Request Builder module - Constructs HTTP requests with injected payloads.

Extracted from http_runner.py - Phase 7 refactoring.
Split into multiple injectors for maintainability.
"""

from .base import RequestBuilder
from .query_injector import QueryInjector
from .body_injector import BodyInjector
from .header_injector import HeaderInjector, CookieInjector
from .path_injector import PathInjector

__all__ = [
    'RequestBuilder',
    'QueryInjector',
    'BodyInjector',
    'HeaderInjector',
    'CookieInjector',
    'PathInjector',
]

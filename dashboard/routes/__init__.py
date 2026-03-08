"""
Dashboard Routes Package
========================
All API routers for the Ghost Hunter Dashboard.
"""

from dashboard.routes.core import router as core_router
from dashboard.routes.services import router as services_router
from dashboard.routes.nuclei import router as nuclei_router
from dashboard.routes.burp import router as burp_router
from dashboard.routes.endpoints import router as endpoints_router
from dashboard.routes.triage import router as triage_router
from dashboard.routes.test import router as test_router
from dashboard.routes.requests import router as requests_router
from dashboard.routes.findings import router as findings_router
from dashboard.routes.config import router as config_router
from dashboard.routes.intelligence import router as intelligence_router
from dashboard.routes.security import router as security_router
from dashboard.routes.pivot import router as pivot_router
from dashboard.routes.kb import router as kb_router
from dashboard.routes.multi_round import router as multi_round_router

# List of all routers to include
all_routers = [
    (core_router, {"tags": ["core"]}),
    (services_router, {"tags": ["services"]}),
    (nuclei_router, {"tags": ["nuclei"]}),
    (burp_router, {"tags": ["burp"]}),
    (endpoints_router, {"tags": ["endpoints"]}),
    (triage_router, {"tags": ["triage"]}),
    (test_router, {"tags": ["test"]}),
    (requests_router, {"tags": ["requests"]}),
    (findings_router, {"tags": ["findings"]}),
    (config_router, {"tags": ["config"]}),
    (intelligence_router, {"tags": ["intelligence"]}),
    (security_router, {"tags": ["security"]}),
    (pivot_router, {"tags": ["pivot"]}),
    (kb_router, {"tags": ["knowledge-base"]}),
    (multi_round_router, {"tags": ["multi-round"]}),
]

__all__ = [
    "core_router",
    "services_router",
    "nuclei_router",
    "burp_router",
    "endpoints_router",
    "triage_router",
    "test_router",
    "requests_router",
    "findings_router",
    "config_router",
    "intelligence_router",
    "security_router",
    "pivot_router",
    "kb_router",
    "multi_round_router",
    "all_routers",
]

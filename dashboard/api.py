"""
Ghost Hunter Dashboard API
==========================
API REST modulaire avec tous les routers extraits dans dashboard/routes/

Architecture:
- Routes: dashboard/routes/*.py (14 routers)
- Schemas: dashboard/schemas/*.py
- Dependencies: dashboard/deps.py
- Storage: dashboard/utils/storage.py
"""

import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# Import all routers
from dashboard.routes import (
    core_router,
    services_router,
    nuclei_router,
    burp_router,
    endpoints_router,
    triage_router,
    test_router,
    requests_router,
    findings_router,
    config_router,
    intelligence_router,
    security_router,
    pivot_router,
    kb_router,
    multi_round_router,
)

logger = logging.getLogger(__name__)


def create_app(
    data_dir: Path = Path("data"),
    config_dir: Path = Path("config"),
    static_dir: Optional[Path] = None,
) -> FastAPI:
    """Crée l'application FastAPI."""
    
    if static_dir is None:
        static_dir = Path(__file__).parent / "static"
    
    # Ensure directories exist
    data_dir.mkdir(exist_ok=True)
    (data_dir / "findings").mkdir(exist_ok=True)
    (data_dir / "logs").mkdir(exist_ok=True)
    
    app = FastAPI(
        title="Ghost Hunter Dashboard",
        description="AI-Powered Bug Bounty Command Center",
        version="2.0.0",
    )
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # ══════════════════════════════════════════════════════════════════
    # INCLUDE ALL ROUTERS
    # ══════════════════════════════════════════════════════════════════
    app.include_router(core_router)
    app.include_router(services_router)
    app.include_router(nuclei_router)
    app.include_router(burp_router)
    app.include_router(endpoints_router)
    app.include_router(triage_router)
    app.include_router(test_router)
    app.include_router(requests_router)
    app.include_router(findings_router)
    app.include_router(config_router)
    app.include_router(intelligence_router)
    app.include_router(security_router)
    app.include_router(pivot_router)
    app.include_router(kb_router)
    app.include_router(multi_round_router)
    
    # ══════════════════════════════════════════════════════════════════
    # STATIC FILES & DASHBOARD
    # ══════════════════════════════════════════════════════════════════
    if static_dir and static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
        
        @app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard():
            index_file = static_dir / "index.html"
            if index_file.exists():
                return HTMLResponse(content=index_file.read_text())
            return HTMLResponse(content="<h1>Dashboard not found</h1>")
    
    return app


# Point d'entrée pour uvicorn
app = create_app()


def run_server(host: str = "0.0.0.0", port: int = 1010):
    """Lance le serveur."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()

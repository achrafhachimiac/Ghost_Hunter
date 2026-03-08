# 🔧 REFACTORING TODO - Dashboard API

> **Objectif**: Transformer `api.py` (2448 lignes, 63 routes) en architecture modulaire maintenable.
> 
> **Règle d'or**: Zéro régression métier - chaque phase est testable indépendamment.

---

## 📊 ÉTAT ACTUEL

| Métrique | Valeur |
|----------|--------|
| **Lignes totales** | 2448 |
| **Routes API** | 63 |
| **Pydantic Models** | 10 (dont 2 définies DANS create_app!) |
| **Fonctions helper** | 12 |
| **Imports dynamiques** | 35+ (lazy imports dans les routes) |
| **Dépendances internes** | `redis_store`, `pipeline`, `dedup`, `fingerprinter`, `pivot_agent`, `kb_commands` |

### ⚠️ PROBLÈMES ARCHITECTURAUX DÉTECTÉS

1. **2 Pydantic models définis DANS `create_app()`** (anti-pattern):
   - `PivotRunRequest` (L1814)
   - `ScanDomainRequest` (L2198)

2. **35+ imports dynamiques** dans les routes (lazy loading):
   - `from ghost_hunter.core.contracts import ...`
   - `from ghost_hunter.core.intelligence import ...`
   - `from pivot_agent.redis_logger import ...`
   - `from ghost_hunter.cli.kb_commands import ...`

3. **`get_manager()` défini dans `create_app()`** avec `nonlocal` (L199-207)

4. **Fonctions helpers définies dans `create_app()`**:
   - `persist_finding_to_disk()` (L159-170)
   - `load_findings_from_disk()` (L172-186)
   - `get_manager()` (L199-207)

### Routes par domaine fonctionnel

| Domaine | Routes | Lignes (estimé) | Complexité |
|---------|--------|-----------------|------------|
| **Core** (`/`, `/api/reset`, `/api/stats`) | 3 | ~150 | Basse |
| **Services** (`/api/services/*`) | 7 | ~100 | Basse |
| **Endpoints** (`/api/endpoints/*`) | 5 | ~350 | **Haute** |
| **Burp Import** (`/api/burp/*`) | 2 | ~180 | Moyenne |
| **Triage** (`/api/triage/*`, `/api/endpoints/*/triage`) | 4 | ~250 | **Haute** |
| **Test Execution** (`/api/endpoints/*/test`, `/api/run`) | 2 | ~300 | **Haute** |
| **Requests** (`/api/requests/*`) | 4 | ~80 | Basse |
| **Findings** (`/api/findings/*`) | 4 | ~150 | Moyenne |
| **Config/Scan** (`/api/config/*`, `/api/scan/*`, `/api/clear`) | 6 | ~100 | Basse |
| **Intelligence** (`/api/intelligence/*`) | 10 | ~200 | Moyenne |
| **Security** (`/api/security/*`) | 6 | ~180 | Moyenne |
| **Pivot Agent** (`/api/pivot/*`) | 6 | ~350 | **Haute** |
| **Knowledge Base** (`/api/kb/*`) | 5 | ~150 | Moyenne |
| **Nuclei** (`/api/nuclei`) | 1 | ~30 | Basse |
| **Knowledge Legacy** (`/api/knowledge`) | 1 | ~40 | Basse |
| **Dashboard HTML** (`/dashboard`) | 1 | ~10 | Basse |

---

## 🎯 STRUCTURE CIBLE

```
dashboard/
├── api.py                    # ~100 lignes - Factory + mount routers
├── __init__.py
├── deps.py                   # ~60 lignes - Dépendances partagées
├── schemas/                  # 6 fichiers - Pydantic models
│   ├── __init__.py           # Exports
│   ├── common.py             # RequestSummary, FindingSummary, ServiceAction
│   ├── burp.py               # BurpRequestData, BurpResponseData, BurpImport*
│   ├── scan.py               # ScanConfig
│   ├── pivot.py              # PivotRunRequest
│   └── security.py           # ScanDomainRequest
├── routes/                   # 14 fichiers - APIRouter par domaine
│   ├── __init__.py           # Exports tous les routers
│   ├── core.py               # /, /api/reset, /api/stats (3 routes)
│   ├── services.py           # /api/services/* (7 routes)
│   ├── nuclei.py             # /api/nuclei, /api/knowledge (2 routes)
│   ├── burp.py               # /api/burp/* (2 routes)
│   ├── endpoints.py          # /api/endpoints/* (3 routes)
│   ├── triage.py             # /api/triage/*, POST triage (3 routes)
│   ├── test.py               # /api/endpoints/*/test, /api/run (2 routes)
│   ├── requests.py           # /api/requests/*, POST /api/triage (4 routes)
│   ├── findings.py           # /api/findings/* (3 routes)
│   ├── config.py             # /api/config/*, /api/scan/*, /api/clear (6 routes)
│   ├── intelligence.py       # /api/intelligence/* (10 routes)
│   ├── security.py           # /api/security/* (5 routes)
│   ├── pivot.py              # /api/pivot/* (6 routes)
│   └── kb.py                 # /api/kb/* (6 routes)
└── utils/                    # Helpers
    ├── __init__.py
    ├── storage.py            # Storage mémoire + persistence disque
    └── converters.py         # InterceptedRequest builders (optionnel)
```

**Total: ~20 fichiers au lieu de 1 fichier de 2448 lignes**

---

## 📋 PHASES DE REFACTORING

### PHASE 0: Préparation (30 min)
> **But**: Créer l'infrastructure de test pour détecter les régressions

- [ ] **0.1** Créer `tests/integration/test_api_routes.py`
  - Tester TOUTES les routes existantes avant refactoring
  - Capturer les réponses attendues (snapshot testing)
  
- [ ] **0.2** Ajouter script de validation
  ```bash
  # scripts/validate_api_routes.py
  # Compare les routes avant/après refactoring
  ```

- [ ] **0.3** Documenter les dépendances inter-routes
  - Quelles routes appellent d'autres routes?
  - Quelles routes partagent du state?

---

### PHASE 1: Extraction des Schemas (20 min)
> **But**: Séparer les Pydantic models - ZERO impact sur les routes

#### 1.1 Créer `dashboard/schemas/__init__.py`
```python
from .common import RequestSummary, FindingSummary, ServiceAction
from .burp import BurpRequestData, BurpResponseData, BurpImportRequest, BurpImportResponse
from .scan import ScanConfig
from .pivot import PivotRunRequest
from .security import ScanDomainRequest
```

#### 1.2 Créer `dashboard/schemas/common.py`
Déplacer (depuis le niveau module):
- `RequestSummary` (L57-67)
- `FindingSummary` (L70-79)
- `ServiceAction` (L82-84)

#### 1.3 Créer `dashboard/schemas/burp.py`
Déplacer (depuis le niveau module):
- `BurpResponseData` (L96-100)
- `BurpRequestData` (L102-108)
- `BurpImportRequest` (L110-113)
- `BurpImportResponse` (L115-121)

#### 1.4 Créer `dashboard/schemas/scan.py`
Déplacer (depuis le niveau module):
- `ScanConfig` (L86-93)

#### 1.5 Créer `dashboard/schemas/pivot.py`
Déplacer:
- `PivotRunRequest` (L1814-1817) - ⚠️ **ATTENTION: défini DANS create_app()!**

#### 1.6 Créer `dashboard/schemas/security.py` (NOUVEAU)
Déplacer:
- `ScanDomainRequest` (L2198-2201) - ⚠️ **ATTENTION: défini DANS create_app()!**

#### 1.7 Mettre à jour les imports dans `api.py`
```python
from dashboard.schemas import (
    RequestSummary, FindingSummary, ServiceAction,
    BurpRequestData, BurpImportRequest, BurpImportResponse,
    ScanConfig, ScanDomainRequest, PivotRunRequest
)
```

**✅ Validation Phase 1**: `pytest tests/integration/test_api_routes.py -v`

---

### PHASE 2: Extraction des Dépendances (20 min)
> **But**: Centraliser les singletons et helpers partagés

#### 2.1 Créer `dashboard/deps.py`

```python
"""
Dépendances partagées pour toutes les routes.
"""
import logging
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# ==================== Singletons ====================

_dedup_engine = None
_pipeline = None
_service_manager = None

def get_dedup():
    """Retourne l'instance DedupEngine (singleton connecté à Redis)."""
    global _dedup_engine
    if _dedup_engine is None:
        from ghost_hunter.core.interceptor.dedup import DedupEngine
        _dedup_engine = DedupEngine()
        logger.info("DedupEngine initialized (Redis backend)")
    return _dedup_engine

def get_pipeline():
    """Retourne le pipeline complet (lazy init)."""
    global _pipeline
    if _pipeline is None:
        try:
            from ghost_hunter.main import GhostHunterPipeline
            _pipeline = GhostHunterPipeline()
            logger.info("Pipeline initialized")
        except Exception as e:
            logger.warning(f"Could not initialize pipeline: {e}")
            return None
    return _pipeline

def get_service_manager():
    """Retourne le ServiceManager (lazy init)."""
    global _service_manager
    if _service_manager is None:
        try:
            from ghost_hunter.service_manager import get_service_manager as gsm
            _service_manager = gsm()
        except Exception as e:
            logger.error(f"Failed to load service manager: {e}")
            return None
    return _service_manager

def get_redis_store():
    """Retourne le RedisStore centralisé."""
    from ghost_hunter.core.redis_store import get_redis_store
    return get_redis_store()
```

#### 2.2 Créer `dashboard/utils/storage.py`

Déplacer:
- `storage` dict (L176-182)
- `persist_finding_to_disk()` (L162-173)
- `load_findings_from_disk()` (L175-186)

```python
"""
Storage utilities - mémoire + persistance disque.
"""
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict

logger = logging.getLogger(__name__)

# Storage en mémoire (legacy)
storage = {
    "requests": {},
    "findings": {},
    "triage_history": [],
    "scan_active": False,
    "started_at": datetime.now().timestamp(),
}

def persist_finding_to_disk(finding: Dict, findings_dir: Path) -> bool:
    """Persist a finding to disk for survival across restarts."""
    try:
        finding_id = finding.get("id", f"unknown-{datetime.now().timestamp()}")
        filename = f"finding_{finding_id.replace('/', '_')}.json"
        filepath = findings_dir / filename
        with open(filepath, "w") as f:
            json.dump(finding, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to persist finding to disk: {e}")
        return False

def load_findings_from_disk(findings_dir: Path) -> Dict[str, Dict]:
    """Load all findings from disk."""
    findings = {}
    try:
        for filepath in findings_dir.glob("finding_*.json"):
            try:
                with open(filepath) as f:
                    finding = json.load(f)
                    findings[finding.get("id", filepath.stem)] = finding
            except Exception as e:
                logger.error(f"Failed to load finding {filepath}: {e}")
    except Exception as e:
        logger.error(f"Failed to scan findings directory: {e}")
    return findings
```

#### 2.3 Mettre à jour `api.py`

```python
from dashboard.deps import get_dedup, get_pipeline, get_service_manager, get_redis_store
from dashboard.utils.storage import storage, persist_finding_to_disk, load_findings_from_disk
```

**✅ Validation Phase 2**: `pytest tests/integration/test_api_routes.py -v`

---

### PHASE 3: Extraction des Routes - BASSE COMPLEXITÉ (45 min)
> **But**: Extraire les routes simples sans logique complexe

#### 3.1 Créer `dashboard/routes/core.py`

Routes à déplacer:
- `GET /` (L212-214)
- `POST /api/reset` (L216-300)
- `GET /api/stats` (L393-467)

```python
"""Routes core: health, reset, stats."""
from fastapi import APIRouter, HTTPException
from datetime import datetime
from pathlib import Path
import json

from dashboard.deps import get_pipeline, get_redis_store
from dashboard.utils.storage import storage

router = APIRouter(tags=["core"])

@router.get("/")
async def root():
    return {"status": "ok", "message": "Ghost Hunter Dashboard API v2.0"}

@router.post("/api/reset")
async def reset_all_data():
    # ... (copier le code existant)
    pass

@router.get("/api/stats")
async def get_stats():
    # ... (copier le code existant)
    pass
```

#### 3.2 Créer `dashboard/routes/services.py`

Routes à déplacer (L311-390):
- `GET /api/services/health`
- `GET /api/services/{service_name}/logs`
- `POST /api/services/start-all`
- `POST /api/services/stop-all`
- `POST /api/services/{service_name}/start`
- `POST /api/services/{service_name}/stop`
- `POST /api/services/{service_name}/restart`

#### 3.3 Créer `dashboard/routes/requests.py`

Routes à déplacer (L1375-1434):
- `GET /api/requests`
- `GET /api/requests/{request_id}`
- `POST /api/requests`
- `POST /api/triage` (la simple, pas celle des endpoints)

#### 3.4 Créer `dashboard/routes/config.py`

Routes à déplacer (L1552-1610):
- `GET /api/config/scope`
- `PUT /api/config/scope`
- `GET /api/scan/status`
- `POST /api/scan/start`
- `POST /api/scan/stop`
- `DELETE /api/clear`

#### 3.5 Créer `dashboard/routes/kb.py`

Routes à déplacer (L2257-2422):
- `GET /api/kb/status`
- `POST /api/kb/sync`
- `POST /api/kb/sync-disclosures`
- `GET /api/kb/search`
- `POST /api/kb/add-report`
- `POST /api/kb/rebuild`

#### 3.6 Créer `dashboard/routes/nuclei.py` (NOUVEAU)

Routes à déplacer:
- `GET /api/nuclei` (L469-492)
- `GET /api/knowledge` (L495-527) - legacy route

**✅ Validation Phase 3**: `pytest tests/integration/test_api_routes.py -v`

---

### PHASE 4: Extraction des Routes - MOYENNE COMPLEXITÉ (60 min)
> **But**: Extraire les routes avec logique business modérée

#### 4.1 Créer `dashboard/routes/burp.py`

Routes à déplacer (L529-670):
- `POST /api/burp/import` - **ATTENTION**: Contient la logique de conversion `BurpRequestData` → `InterceptedRequest`
- `GET /api/burp/status`

**Points d'attention**:
- Importation de `InterceptedRequest` depuis `ghost_hunter.core.contracts`
- Parsing URL avec `urlparse`, `parse_qs`
- Appel à `pipeline.process_request()` et `pipeline.triage_request()`

#### 4.2 Créer `dashboard/routes/findings.py`

Routes à déplacer (L1437-1550):
- `GET /api/findings`
- `GET /api/findings/{finding_id}`
- `POST /api/findings`

**Points d'attention**:
- Agrégation depuis 4 sources: pipeline, Redis, disk, storage local
- Tri par sévérité

#### 4.3 Créer `dashboard/routes/intelligence.py`

Routes à déplacer (L1612-1796):
- `GET /api/intelligence/status`
- `GET /api/intelligence/knowledge/search`
- `GET /api/intelligence/knowledge/vuln-context/{vuln_type}`
- `GET /api/intelligence/knowledge/patterns`
- `POST /api/intelligence/knowledge/match-patterns`
- `GET /api/intelligence/knowledge/wordlists`
- `GET /api/intelligence/osint/subdomains/{domain}`
- `GET /api/intelligence/osint/host/{ip}`
- `GET /api/intelligence/fingerprint`
- `GET /api/intelligence/attack-surface`

#### 4.4 Créer `dashboard/routes/security.py`

Routes à déplacer (L1798-2254):
- `GET /api/security` (L1798) - Liste tous les profils
- `GET /api/security/{domain}` (L2157) - Profil d'un domaine
- `GET /api/security/{domain}/recommendations` (L2174) - Recommandations évasion
- `POST /api/security/scan/domain` (L2203) - Scan un domaine
- `POST /api/security/scan/scope` (L2223) - Scan tous les domaines du scope

**⚠️ ATTENTION**: `ScanDomainRequest` est défini DANS `create_app()` juste avant la route (L2198).
Déplacer dans `schemas/security.py` d'abord!

**✅ Validation Phase 4**: `pytest tests/integration/test_api_routes.py -v`

---

### PHASE 5: Extraction des Routes - HAUTE COMPLEXITÉ (90 min)
> **But**: Extraire les routes critiques avec le maximum de logique

#### 5.1 Créer `dashboard/routes/endpoints.py`

Routes à déplacer (L673-800):
- `GET /api/endpoints` - **COMPLEXE**: filtres multiples, pagination, tri
- `GET /api/endpoints/summary`
- `GET /api/endpoints/{endpoint_hash}`

**Points d'attention**:
- Appel à `pipeline.dedup.get_all_endpoints_data()`
- Logique de filtrage: status, search, exclude, never_triaged
- Tri par score, last_seen, seen_count, triaged_at

#### 5.2 Créer `dashboard/routes/triage.py`

Routes à déplacer (L804-970):
- `POST /api/endpoints/{endpoint_hash}/triage` - **TRÈS COMPLEXE**: 
  - Reconstruction de `InterceptedRequest`, `FilteredRequest`, `ScoredRequest`
  - Appel à `pipeline.triage_engine.full_triage()`
  - Mise à jour du status dans dedup
  - Sauvegarde dans Redis + storage local
- `GET /api/triage/history`
- `DELETE /api/triage/history`

**Points d'attention**:
- Reconstruction complète de la requête depuis les données stockées
- `triage_entry` avec tous les champs: original_request, original_response
- Double sauvegarde: Redis + storage local

#### 5.3 Créer `dashboard/routes/test.py`

Routes à déplacer (L973-1220):
- `POST /api/endpoints/{endpoint_hash}/test` - **TRÈS COMPLEXE**:
  - Reconstruction de la requête complète
  - Création du `TriageDecision` simulé
  - Appel à `pipeline.create_attack_plan()`
  - Exécution via `pipeline.execute_plan_sync()`
  - Mise à jour status: VULNERABLE ou TESTED
  - Persistance findings: Redis + disk
- `POST /api/run` - Exécution directe HTTP (pour Pivot Agent)

**Points d'attention**:
- Normalisation des headers (SKIP_HEADERS)
- Gestion du proxy GonzoProxy
- Logging de debug détaillé

#### 5.4 Créer `dashboard/routes/pivot.py`

Routes à déplacer (L1819-2156):
- `POST /api/pivot/run/{log_id}` - **TRÈS COMPLEXE**:
  - Récupération des données depuis pipeline.dedup ou Redis
  - Construction du `initial_state` pour LangGraph
  - Injection des headers/cookies de session
  - Lancement en background via `BackgroundTasks`
- `GET /api/pivot/logs/{log_id}`
- `GET /api/pivot/status/{log_id}`
- `POST /api/pivot/stop/{log_id}`
- `DELETE /api/pivot/logs/{log_id}`
- `DELETE /api/pivot/logs`

**Points d'attention**:
- Import dynamique de `pivot_agent`
- Construction de l'URL complète avec query params
- `AgentLogger` pour les logs Redis

**✅ Validation Phase 5**: `pytest tests/integration/test_api_routes.py -v`

---

### PHASE 6: Assemblage Final (30 min)
> **But**: Nettoyer `api.py` et assembler les routers

#### 6.1 Créer `dashboard/routes/__init__.py`

```python
"""All API routers."""
from .core import router as core_router
from .services import router as services_router
from .endpoints import router as endpoints_router
from .burp import router as burp_router
from .triage import router as triage_router
from .test import router as test_router
from .requests import router as requests_router
from .findings import router as findings_router
from .config import router as config_router
from .intelligence import router as intelligence_router
from .security import router as security_router
from .pivot import router as pivot_router
from .kb import router as kb_router
from .nuclei import router as nuclei_router  # AJOUTÉ

__all__ = [
    'core_router',
    'services_router',
    'endpoints_router',
    'burp_router',
    'triage_router',
    'test_router',
    'requests_router',
    'findings_router',
    'config_router',
    'intelligence_router',
    'security_router',
    'pivot_router',
    'kb_router',
    'nuclei_router',  # AJOUTÉ
]
```

#### 6.2 Réécrire `dashboard/api.py`

```python
"""
Ghost Hunter Dashboard API
==========================
Factory pattern avec routers modulaires.
"""
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from dashboard.routes import (
    core_router,
    services_router,
    endpoints_router,
    burp_router,
    triage_router,
    test_router,
    requests_router,
    findings_router,
    config_router,
    intelligence_router,
    security_router,
    pivot_router,
    kb_router,
)

logger = logging.getLogger(__name__)


def create_app(
    data_dir: Path = Path("data"),
    config_dir: Path = Path("config"),
    static_dir: Optional[Path] = None,
) -> FastAPI:
    """Crée l'application FastAPI avec tous les routers."""
    
    if static_dir is None:
        static_dir = Path(__file__).parent / "static"
    
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
    
    # Mount all routers
    app.include_router(core_router)
    app.include_router(services_router)
    app.include_router(endpoints_router)
    app.include_router(burp_router)
    app.include_router(triage_router)
    app.include_router(test_router)
    app.include_router(requests_router)
    app.include_router(findings_router)
    app.include_router(config_router)
    app.include_router(intelligence_router)
    app.include_router(security_router)
    app.include_router(pivot_router)
    app.include_router(kb_router)
    app.include_router(nuclei_router)  # AJOUTÉ
    
    # Static files
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


def run_server(host: str = "0.0.0.0", port: int = 8080):
    """Lance le serveur."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
```

**✅ Validation Phase 6**: 
```bash
# Test complet
pytest tests/integration/test_api_routes.py -v

# Test manuel
uvicorn dashboard.api:app --reload --port 1010
# Vérifier que toutes les routes fonctionnent dans le browser
```

---

### PHASE 7: Nettoyage (15 min)
> **But**: Supprimer le code mort et optimiser

- [ ] **7.1** Supprimer `api.py.bak` si créé
- [ ] **7.2** Vérifier qu'aucun import n'est cassé
- [ ] **7.3** Mettre à jour `start.sh` si nécessaire
- [ ] **7.4** Vérifier les tests existants dans `tests/`
- [ ] **7.5** Mettre à jour la documentation (`ARCHITECTURE.md`)

---

## 🧪 TESTS DE NON-RÉGRESSION

### Checklist complète des 63 routes

| # | Méthode | Route | Router cible |
|---|---------|-------|--------------|
| 1 | GET | `/` | core |
| 2 | POST | `/api/reset` | core |
| 3 | GET | `/api/stats` | core |
| 4 | GET | `/api/services/health` | services |
| 5 | GET | `/api/services/{service_name}/logs` | services |
| 6 | POST | `/api/services/start-all` | services |
| 7 | POST | `/api/services/stop-all` | services |
| 8 | POST | `/api/services/{service_name}/start` | services |
| 9 | POST | `/api/services/{service_name}/stop` | services |
| 10 | POST | `/api/services/{service_name}/restart` | services |
| 11 | GET | `/api/nuclei` | nuclei |
| 12 | GET | `/api/knowledge` | nuclei |
| 13 | POST | `/api/burp/import` | burp |
| 14 | GET | `/api/burp/status` | burp |
| 15 | GET | `/api/endpoints` | endpoints |
| 16 | GET | `/api/endpoints/summary` | endpoints |
| 17 | GET | `/api/endpoints/{endpoint_hash}` | endpoints |
| 18 | POST | `/api/endpoints/{endpoint_hash}/triage` | triage |
| 19 | GET | `/api/triage/history` | triage |
| 20 | DELETE | `/api/triage/history` | triage |
| 21 | POST | `/api/endpoints/{endpoint_hash}/test` | test |
| 22 | POST | `/api/run` | test |
| 23 | GET | `/api/requests` | requests |
| 24 | GET | `/api/requests/{request_id}` | requests |
| 25 | POST | `/api/requests` | requests |
| 26 | POST | `/api/triage` | requests |
| 27 | GET | `/api/findings` | findings |
| 28 | GET | `/api/findings/{finding_id}` | findings |
| 29 | POST | `/api/findings` | findings |
| 30 | GET | `/api/config/scope` | config |
| 31 | PUT | `/api/config/scope` | config |
| 32 | GET | `/api/scan/status` | config |
| 33 | POST | `/api/scan/start` | config |
| 34 | POST | `/api/scan/stop` | config |
| 35 | DELETE | `/api/clear` | config |
| 36 | GET | `/api/intelligence/status` | intelligence |
| 37 | GET | `/api/intelligence/knowledge/search` | intelligence |
| 38 | GET | `/api/intelligence/knowledge/vuln-context/{vuln_type}` | intelligence |
| 39 | GET | `/api/intelligence/knowledge/patterns` | intelligence |
| 40 | POST | `/api/intelligence/knowledge/match-patterns` | intelligence |
| 41 | GET | `/api/intelligence/knowledge/wordlists` | intelligence |
| 42 | GET | `/api/intelligence/osint/subdomains/{domain}` | intelligence |
| 43 | GET | `/api/intelligence/osint/host/{ip}` | intelligence |
| 44 | GET | `/api/intelligence/fingerprint` | intelligence |
| 45 | GET | `/api/intelligence/attack-surface` | intelligence |
| 46 | GET | `/api/security` | security |
| 47 | GET | `/api/security/{domain}` | security |
| 48 | GET | `/api/security/{domain}/recommendations` | security |
| 49 | POST | `/api/security/scan/domain` | security |
| 50 | POST | `/api/security/scan/scope` | security |
| 51 | POST | `/api/pivot/run/{log_id}` | pivot |
| 52 | GET | `/api/pivot/logs/{log_id}` | pivot |
| 53 | GET | `/api/pivot/status/{log_id}` | pivot |
| 54 | POST | `/api/pivot/stop/{log_id}` | pivot |
| 55 | DELETE | `/api/pivot/logs/{log_id}` | pivot |
| 56 | DELETE | `/api/pivot/logs` | pivot |
| 57 | GET | `/api/kb/status` | kb |
| 58 | POST | `/api/kb/sync` | kb |
| 59 | POST | `/api/kb/sync-disclosures` | kb |
| 60 | GET | `/api/kb/search` | kb |
| 61 | POST | `/api/kb/add-report` | kb |
| 62 | POST | `/api/kb/rebuild` | kb |
| 63 | GET | `/dashboard` | core (static) |

### Script de validation automatique

Créer `scripts/validate_api_refactoring.py`:

```python
#!/usr/bin/env python3
"""
Valide que toutes les routes existent après refactoring.
"""
import httpx
import sys

BASE_URL = "http://localhost:1010"

ROUTES_TO_CHECK = [
    ("GET", "/"),
    ("GET", "/api/stats"),
    ("GET", "/api/services/health"),
    ("GET", "/api/endpoints"),
    ("GET", "/api/endpoints/summary"),
    ("GET", "/api/burp/status"),
    ("GET", "/api/triage/history"),
    ("GET", "/api/requests"),
    ("GET", "/api/findings"),
    ("GET", "/api/config/scope"),
    ("GET", "/api/scan/status"),
    ("GET", "/api/intelligence/status"),
    ("GET", "/api/security"),
    ("GET", "/api/kb/status"),
]

def check_routes():
    """Vérifie que toutes les routes répondent."""
    errors = []
    
    with httpx.Client(timeout=5.0) as client:
        for method, path in ROUTES_TO_CHECK:
            try:
                if method == "GET":
                    resp = client.get(f"{BASE_URL}{path}")
                else:
                    resp = client.request(method, f"{BASE_URL}{path}")
                
                if resp.status_code >= 500:
                    errors.append(f"❌ {method} {path} → {resp.status_code}")
                else:
                    print(f"✅ {method} {path} → {resp.status_code}")
            except Exception as e:
                errors.append(f"❌ {method} {path} → {e}")
    
    if errors:
        print("\n🚨 ERREURS DÉTECTÉES:")
        for err in errors:
            print(f"  {err}")
        sys.exit(1)
    else:
        print("\n✅ Toutes les routes fonctionnent!")
        sys.exit(0)

if __name__ == "__main__":
    check_routes()
```

---

## 📈 MÉTRIQUES ATTENDUES APRÈS REFACTORING

| Métrique | Avant | Après |
|----------|-------|-------|
| `api.py` | 2448 lignes | ~100 lignes |
| Fichiers | 1 | **20** (api + 6 schemas + 14 routes + utils) |
| Pydantic Models hors scope | 2 | 0 |
| Imports dynamiques | 35+ dans 1 fichier | Répartis par router |
| Complexité max par fichier | Très haute | Moyenne |
| Testabilité | Difficile | Facile (chaque router isolé) |
| Temps de navigation | Long | Rapide (fichiers focalisés) |

### Répartition des routes par router

| Router | Routes | Lignes estimées |
|--------|--------|-----------------|
| `core.py` | 3 | ~180 |
| `services.py` | 7 | ~100 |
| `nuclei.py` | 2 | ~70 |
| `burp.py` | 2 | ~180 |
| `endpoints.py` | 3 | ~120 |
| `triage.py` | 3 | ~200 |
| `test.py` | 2 | ~300 |
| `requests.py` | 4 | ~80 |
| `findings.py` | 3 | ~150 |
| `config.py` | 6 | ~100 |
| `intelligence.py` | 10 | ~200 |
| `security.py` | 5 | ~180 |
| `pivot.py` | 6 | ~350 |
| `kb.py` | 6 | ~180 |
| **TOTAL** | **63** | ~2400 (réparti) |

---

## ⚠️ POINTS DE VIGILANCE

### Variables globales partagées
- `storage` dict (utilisé par plusieurs routes)
- `_dedup_engine`, `_pipeline` singletons

### Imports circulaires potentiels
- `deps.py` → `ghost_hunter.main` → potentiel cycle

### State entre routes
- `storage["triage_history"]` modifié par plusieurs routes
- Redis comme source de vérité (déjà thread-safe)

### Background tasks
- Routes utilisant `BackgroundTasks`: services, pivot, test
- S'assurer que le context est bien passé

### ⚠️ IMPORTS DYNAMIQUES (35+ occurrences)

Ces imports sont faits **dans les routes** pour éviter les imports circulaires et le temps de démarrage.
**Ne pas les déplacer au niveau module sans vérifier les dépendances !**

```python
# Exemples d'imports dynamiques à conserver dans les routes:
from ghost_hunter.core.contracts import InterceptedRequest, FilteredRequest, ScoredRequest
from ghost_hunter.core.interceptor.dedup import EndpointStatus
from ghost_hunter.core.intelligence import get_knowledge_loader, get_fingerprinter
from ghost_hunter.core.scanner import get_nuclei_scanner
from ghost_hunter.core.evasion import get_proxy_manager
from pivot_agent import get_pivot_agent
from pivot_agent.redis_logger import AgentLogger, stop_agent
from ghost_hunter.cli.kb_commands import sync_source, search_kb
```

### ⚠️ FONCTIONS DÉFINIES DANS `create_app()`

Ces fonctions utilisent des variables de closure (`findings_dir`, `_service_manager`):

| Fonction | Ligne | Variables closure |
|----------|-------|-------------------|
| `persist_finding_to_disk()` | L159 | `findings_dir` |
| `load_findings_from_disk()` | L172 | `findings_dir` |
| `get_manager()` | L199 | `_service_manager` (nonlocal) |

**Solution**: Passer `findings_dir` en paramètre ou utiliser `app.state`.

---

## 🚀 COMMANDES DE VALIDATION

```bash
# Avant chaque phase
git stash  # ou commit

# Après chaque phase
PYTHONPATH=. pytest tests/integration/test_api_routes.py -v
uvicorn dashboard.api:app --port 1010 &
python scripts/validate_api_refactoring.py
kill %1

# Si erreur
git stash pop  # ou revert
```

---

## 📅 ESTIMATION TEMPS TOTAL

| Phase | Durée |
|-------|-------|
| Phase 0 (Préparation) | 30 min |
| Phase 1 (Schemas) | 20 min |
| Phase 2 (Deps) | 20 min |
| Phase 3 (Routes simples) | 45 min |
| Phase 4 (Routes moyennes) | 60 min |
| Phase 5 (Routes complexes) | 90 min |
| Phase 6 (Assemblage) | 30 min |
| Phase 7 (Nettoyage) | 15 min |
| **TOTAL** | **~5h** |

---

*Document créé le 2026-01-08*
*Dernière mise à jour: 2026-01-08*

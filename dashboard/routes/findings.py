"""
Findings routes - Vulnerability findings management.

Routes:
- GET /api/findings - List all findings (from all sources)
- GET /api/findings/{finding_id} - Get finding details
- POST /api/findings - Add a finding
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
import json

from fastapi import APIRouter, HTTPException, Query
import logging

from dashboard.deps import get_pipeline, get_redis_store
from dashboard.utils.storage import storage
from dashboard.schemas import FindingSummary

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["findings"])

# Findings directory for disk persistence
FINDINGS_DIR = Path("data/findings")


def load_findings_from_disk() -> Dict[str, Any]:
    """Load findings from disk."""
    findings = {}
    if FINDINGS_DIR.exists():
        for file in FINDINGS_DIR.glob("*.json"):
            try:
                with open(file) as f:
                    finding = json.load(f)
                    findings[finding.get("id", file.stem)] = finding
            except Exception as e:
                logger.debug(f"Failed to load finding {file}: {e}")
    return findings


@router.get("/findings", response_model=List[FindingSummary])
async def list_findings(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
):
    """Liste les findings from all sources (pipeline, Redis, disk)."""
    all_findings = {}
    
    # 1. From pipeline memory (current session)
    try:
        pipeline = get_pipeline()
        if pipeline and hasattr(pipeline, 'findings_store'):
            for f_id, finding in pipeline.findings_store.items():
                sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                all_findings[f_id] = {
                    "id": finding.id,
                    "endpoint": finding.endpoint,
                    "vuln_type": finding.vuln_type,
                    "severity": sev,
                    "confidence": finding.confidence,
                    "status": finding.status.value if hasattr(finding.status, 'value') else str(finding.status),
                    "discovered_at": finding.discovered_at,
                }
    except Exception as e:
        logger.debug(f"Pipeline findings not available: {e}")
    
    # 2. From Redis (persistent across dashboard restarts)
    try:
        redis_findings = get_redis_store().get_all_findings()
        for f_id, finding in redis_findings.items():
            if f_id not in all_findings:  # Don't override pipeline data
                all_findings[f_id] = {
                    "id": f_id,
                    "endpoint": finding.get("endpoint", finding.get("url", "")),
                    "vuln_type": finding.get("vuln_type", finding.get("type", "Unknown")),
                    "severity": finding.get("severity", "info"),
                    "confidence": finding.get("confidence", 0),
                    "status": finding.get("status", "new"),
                    "discovered_at": finding.get("discovered_at", finding.get("updated_at", 0)),
                }
    except Exception as e:
        logger.debug(f"Redis findings not available: {e}")
    
    # 3. From disk (survives Redis flushes and full restarts)
    try:
        disk_findings = load_findings_from_disk()
        for f_id, finding in disk_findings.items():
            if f_id not in all_findings:  # Don't override
                all_findings[f_id] = {
                    "id": f_id,
                    "endpoint": finding.get("endpoint", finding.get("url", "")),
                    "vuln_type": finding.get("vuln_type", finding.get("type", "Unknown")),
                    "severity": finding.get("severity", "info"),
                    "confidence": finding.get("confidence", 0),
                    "status": finding.get("status", "new"),
                    "discovered_at": finding.get("discovered_at", 0),
                }
    except Exception as e:
        logger.debug(f"Disk findings not available: {e}")
    
    # 4. From local storage (API added findings)
    for f_id, finding in storage.get("findings", {}).items():
        if f_id not in all_findings:
            all_findings[f_id] = {
                "id": f_id,
                "endpoint": finding.get("endpoint", ""),
                "vuln_type": finding.get("vuln_type", "Unknown"),
                "severity": finding.get("severity", "info"),
                "confidence": finding.get("confidence", 0),
                "status": finding.get("status", "new"),
                "discovered_at": finding.get("discovered_at", 0),
            }
    
    # Filter by severity if requested
    findings = list(all_findings.values())
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    
    # Sort by severity then by date
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: (severity_order.get(x.get("severity", "info"), 5), -x.get("discovered_at", 0)))
    
    return findings[:limit]


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    """Récupère un finding."""
    try:
        pipeline = get_pipeline()
        if pipeline and finding_id in pipeline.findings_store:
            return pipeline.findings_store[finding_id]
    except:
        pass
    
    if finding_id in storage["findings"]:
        return storage["findings"][finding_id]
    raise HTTPException(status_code=404, detail="Finding not found")


@router.post("/findings")
async def add_finding(finding: Dict[str, Any]):
    """Ajoute un finding."""
    f_id = finding.get("id", str(datetime.now().timestamp()))
    storage["findings"][f_id] = {
        "id": f_id,
        "endpoint": finding.get("endpoint", ""),
        "vuln_type": finding.get("vuln_type", "Unknown"),
        "severity": finding.get("severity", "info"),
        "confidence": finding.get("confidence", 0),
        "status": finding.get("status", "new"),
        "discovered_at": datetime.now().timestamp(),
    }
    return {"status": "ok", "id": f_id}

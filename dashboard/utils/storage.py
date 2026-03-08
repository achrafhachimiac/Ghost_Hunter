"""
Dashboard storage utilities.
============================
Storage en mémoire (legacy) et persistence disque.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)

# Storage en mémoire (legacy, progressivement migré vers Redis)
storage = {
    "requests": {},
    "findings": {},
    "triage_history": [],  # Migré vers Redis
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

"""Dashboard utils package."""

from dashboard.utils.storage import (
    storage,
    persist_finding_to_disk,
    load_findings_from_disk,
)

__all__ = [
    "storage",
    "persist_finding_to_disk",
    "load_findings_from_disk",
]

"""
HTTP Runner Constants - Extracted from http_runner.py for maintainability.

Contains:
- ERROR_PATTERNS: Regex patterns for detecting vulnerabilities in responses
- EXECUTION_LIMITS: Hardcoded limits for payload/injection point execution
- Helper functions: _safe_get_payload_value
"""

import logging
from typing import Union

logger = logging.getLogger(__name__)


# ==================== Execution Limits ====================

MAX_PAYLOADS = 30
"""Maximum number of payloads to test per execution."""

MAX_INJECTION_POINTS = 5
"""Maximum number of injection points to test per execution."""

DEFAULT_TIMEOUT_SECONDS = 30
"""Default timeout for HTTP requests."""

TIMING_ANOMALY_THRESHOLD_MS = 5000
"""Response time threshold (ms) to consider as timing anomaly."""


# ==================== Error Patterns ====================

ERROR_PATTERNS = {
    "sqli": [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?_",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB)",
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\Wpg_",
        r"valid PostgreSQL result",
        r"PG::SyntaxError",
        r"Driver.*?SQL[\-\_\ ]*Server",
        r"OLE DB.*?SQL Server",
        r"\[SQL Server\]",
        r"SQLServer JDBC Driver",
        r"ODBC SQL Server Driver",
        r"SQLSrvException",
        r"ORA-\d{5}",
        r"Oracle error",
        r"OracleException",
        r"Oracle.*?Driver",
        r"SQL error.*?ORA-",
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"SQLITE_ERROR",
        r"sqlite3\.OperationalError",
        r"near \".+?\": syntax error",
    ],
    "xss": [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
    ],
    "lfi": [
        r"root:.*:0:0:",
        r"\[boot loader\]",
        r"; for 16-bit app support",
        r"/etc/passwd",
        r"No such file or directory",
        r"include_path",
        r"failed to open stream",
    ],
    "ssrf": [
        r"localhost",
        r"127\.0\.0\.1",
        r"169\.254\.169\.254",
        r"metadata\.google",
    ],
    "rce": [
        r"uid=\d+.*gid=\d+",
        r"root:x:0:0",
        r"www-data",
        r"Permission denied",
        r"command not found",
    ],
}
"""Regex patterns indicating potential vulnerabilities by type."""


# ==================== Helper Functions ====================

def _safe_get_payload_value(payload) -> str:
    """
    Safely extract payload value from various payload types.
    
    Handles:
    - None payload
    - Dict payload (with 'payload' key)
    - PayloadVariant objects (with .payload attribute)
    - String payload
    - Any other type (converted to string)
    
    Args:
        payload: The payload in any format
        
    Returns:
        str: The payload value or empty string if extraction fails
    """
    if payload is None:
        return ""
    
    try:
        if isinstance(payload, dict):
            return str(payload.get('payload', '')) if payload.get('payload') else ""
        elif hasattr(payload, 'payload'):
            # Handle PayloadVariant or similar objects
            if payload.payload is None:
                return ""
            return str(payload.payload)
        elif isinstance(payload, str):
            return payload
        else:
            return str(payload)
    except Exception:
        return ""


# ==================== Severity Mappings ====================

VULN_SEVERITY_MAP = {
    "sqli": "HIGH",
    "rce": "CRITICAL",
    "cmdi": "CRITICAL",
    "ssrf": "HIGH",
    "xxe": "HIGH",
    "lfi": "HIGH",
    "rfi": "HIGH",
    "idor": "MEDIUM",
    "xss": "MEDIUM",
    "csrf": "MEDIUM",
    "open_redirect": "LOW",
}
"""Default severity mapping by vulnerability type."""


# ==================== Time-Based Vulnerability Types ====================

TIME_BASED_VULN_TYPES = frozenset(["SQLI", "CMDI", "RCE"])
"""Vulnerability types that can have time-based detection."""

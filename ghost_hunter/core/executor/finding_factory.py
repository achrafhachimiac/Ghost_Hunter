"""
Finding Factory - Extracted from http_runner.py for maintainability.

Creates Finding objects with proper severity, confidence, subtype, and analysis.
"""

import logging
from typing import Optional

from ..contracts import (
    Finding,
    FindingSeverity,
    FindingStatus,
    ResponseSignature,
)

logger = logging.getLogger(__name__)


# Severity mapping by vulnerability type
SEVERITY_MAP = {
    "SQLI": FindingSeverity.HIGH,
    "SQL_INJECTION": FindingSeverity.HIGH,
    "RCE": FindingSeverity.CRITICAL,
    "CMDI": FindingSeverity.CRITICAL,
    "COMMAND_INJECTION": FindingSeverity.CRITICAL,
    "SSRF": FindingSeverity.HIGH,
    "IDOR": FindingSeverity.MEDIUM,
    "XSS": FindingSeverity.MEDIUM,
    "CROSS_SITE_SCRIPTING": FindingSeverity.MEDIUM,
    "LFI": FindingSeverity.HIGH,
    "RFI": FindingSeverity.HIGH,
    "XXE": FindingSeverity.HIGH,
    "SSTI": FindingSeverity.HIGH,
    "OPEN_REDIRECT": FindingSeverity.LOW,
    "CSRF": FindingSeverity.MEDIUM,
}


class FindingFactory:
    """
    Factory for creating Finding objects with computed properties.
    
    Computes:
    - Severity based on vuln type and indicators
    - Confidence score based on evidence strength
    - Subtype (time-based, error-based, reflected)
    - Analysis text summarizing the finding
    """
    
    @classmethod
    def create(
        cls,
        endpoint: str,
        method: str,
        vuln_class: str,
        signature: ResponseSignature,
        payload: str,
        injection_point: str,
        request_sent: Optional[str] = None,
        response_received: Optional[str] = None,
        tool_used: str = "custom_http",
    ) -> Finding:
        """
        Create a Finding with computed severity, confidence, subtype, and analysis.
        
        Args:
            endpoint: Target URL
            method: HTTP method
            vuln_class: Vulnerability class (SQLi, XSS, etc.)
            signature: ResponseSignature with detection indicators
            payload: The payload that triggered the finding
            injection_point: Where the payload was injected
            request_sent: Raw request (optional)
            response_received: Raw response (optional, truncated to 2000 chars)
            tool_used: Tool identifier
            
        Returns:
            Finding: Fully populated Finding object
        """
        severity = cls.determine_severity(signature, vuln_class)
        confidence = cls.calculate_confidence(signature, vuln_class)
        subtype = cls.determine_subtype(signature, vuln_class)
        analysis = cls.generate_analysis(signature, vuln_class)
        
        return Finding(
            endpoint=endpoint,
            method=method,
            vuln_type=vuln_class,
            vuln_subtype=subtype,
            severity=severity,
            status=FindingStatus.NEW,
            confidence=confidence,
            request_sent=request_sent,
            response_received=response_received[:2000] if response_received else None,
            payload_successful=payload,
            ai_analysis=analysis,
            reproduction_steps=[
                f"Target URL: {endpoint}",
                f"Injection point: {injection_point}",
                f"Payload: {payload}",
            ],
            tool_used=tool_used,
        )
    
    @classmethod
    def determine_severity(
        cls,
        signature: ResponseSignature,
        vuln_class: str,
    ) -> FindingSeverity:
        """
        Determine finding severity based on vuln type and indicators.
        
        Severity is upgraded if multiple error patterns are found.
        """
        vuln_upper = vuln_class.upper()
        base_severity = SEVERITY_MAP.get(vuln_upper, FindingSeverity.MEDIUM)
        
        # Upgrade severity if multiple error patterns confirm the vuln
        if signature.error_patterns_found and len(signature.error_patterns_found) >= 2:
            if base_severity == FindingSeverity.MEDIUM:
                return FindingSeverity.HIGH
            elif base_severity == FindingSeverity.HIGH:
                return FindingSeverity.CRITICAL
        
        return base_severity
    
    @classmethod
    def calculate_confidence(
        cls,
        signature: ResponseSignature,
        vuln_class: str,
    ) -> int:
        """
        Calculate confidence score (0-95) based on evidence.
        
        Scoring:
        - Base: 30
        - Per error pattern: +20 (max 3 patterns counted)
        - Reflection found: +25
        - Timing anomaly: +15
        - Maximum: 95
        """
        confidence = 30  # Base confidence
        
        if signature.error_patterns_found:
            # Cap at 3 patterns for scoring
            pattern_count = min(len(signature.error_patterns_found), 3)
            confidence += 20 * pattern_count
        
        if signature.reflection_found:
            confidence += 25
        
        if signature.timing_anomaly:
            confidence += 15
        
        return min(confidence, 95)
    
    @classmethod
    def determine_subtype(
        cls,
        signature: ResponseSignature,
        vuln_class: str,
    ) -> str:
        """
        Determine vulnerability subtype based on detection method.
        
        Returns:
        - "time-based": If timing anomaly detected
        - "error-based": If error patterns found
        - "reflected": If payload reflection found
        - "unknown": No specific detection method
        """
        if signature.timing_anomaly:
            return "time-based"
        if signature.error_patterns_found:
            return "error-based"
        if signature.reflection_found:
            return "reflected"
        return "unknown"
    
    @classmethod
    def generate_analysis(
        cls,
        signature: ResponseSignature,
        vuln_class: str,
    ) -> str:
        """
        Generate human-readable analysis of the finding.
        """
        parts = []
        
        if signature.error_patterns_found:
            patterns_preview = signature.error_patterns_found[:3]
            parts.append(f"Error patterns detected: {', '.join(patterns_preview)}")
        
        if signature.reflection_found:
            parts.append("Payload was reflected in response")
        
        if signature.timing_anomaly:
            time_ms = getattr(signature, 'response_time_ms', 0) or 0
            parts.append(f"Response took {time_ms:.0f}ms (potential time-based)")
        
        return ". ".join(parts) if parts else f"Potential {vuln_class} detected"

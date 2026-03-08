"""
Diff Checker Tool
Compare HTTP responses to detect data leaks, privilege escalation, etc.

SEMANTIC IDOR DETECTION:
The key insight is that IDOR is confirmed when:
- Request(ID_A) → Response(Internal_ID_X)
- Request(ID_B) → Response(Internal_ID_Y)  (with same session!)
- X != Y means we accessed DIFFERENT user's data = CONFIRMED IDOR

This is more reliable than status codes or text similarity.
"""

import json
import re
import base64
from typing import Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class DiffType(str, Enum):
    """Types of differences detected"""
    DATA_LEAK = "data_leak"           # New sensitive data exposed
    PRIVILEGE_CHANGE = "privilege"     # Access to unauthorized resource
    FIELD_ADDED = "field_added"        # New field appeared
    FIELD_REMOVED = "field_removed"    # Field disappeared
    VALUE_CHANGED = "value_changed"    # Value differs
    STATUS_CHANGED = "status_changed"  # HTTP status code changed
    SIZE_CHANGED = "size_changed"      # Response size significantly changed
    STRUCTURE_CHANGED = "structure"    # JSON structure differs
    IDOR_CONFIRMED = "idor_confirmed"  # Semantic IDOR detected


@dataclass
class DiffResult:
    """Single difference found between responses"""
    diff_type: DiffType
    path: str                          # JSON path or location
    expected: Any = None
    actual: Any = None
    severity: str = "info"             # critical, high, medium, low, info
    description: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.diff_type.value,
            "path": self.path,
            "expected": str(self.expected)[:200] if self.expected else None,
            "actual": str(self.actual)[:200] if self.actual else None,
            "severity": self.severity,
            "description": self.description
        }


@dataclass
class IDOREvidence:
    """Evidence of a semantic IDOR vulnerability"""
    baseline_id: str           # ID used in baseline request
    attack_id: str             # ID used in attack request
    baseline_internal_id: str  # Internal ID from baseline response
    attack_internal_id: str    # Internal ID from attack response
    id_field: str              # Field name where ID was found
    json_path: str             # Full JSON path
    confidence: float          # 0.0 - 1.0
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "attack_id": self.attack_id,
            "baseline_internal_id": self.baseline_internal_id,
            "attack_internal_id": self.attack_internal_id,
            "id_field": self.id_field,
            "json_path": self.json_path,
            "confidence": self.confidence
        }


@dataclass
class ComparisonReport:
    """Full comparison report between two responses"""
    differences: list[DiffResult] = field(default_factory=list)
    idor_evidence: list[IDOREvidence] = field(default_factory=list)
    is_identical: bool = True
    has_data_leak: bool = False
    has_privilege_issue: bool = False
    has_idor: bool = False              # NEW: Semantic IDOR detected
    idor_confidence: float = 0.0        # NEW: Confidence level
    summary: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "is_identical": self.is_identical,
            "has_data_leak": self.has_data_leak,
            "has_privilege_issue": self.has_privilege_issue,
            "has_idor": self.has_idor,
            "idor_confidence": self.idor_confidence,
            "summary": self.summary,
            "differences": [d.to_dict() for d in self.differences],
            "idor_evidence": [e.to_dict() for e in self.idor_evidence]
        }
    
    def get_by_severity(self, severity: str) -> list[DiffResult]:
        return [d for d in self.differences if d.severity == severity]
    
    def get_by_type(self, diff_type: DiffType) -> list[DiffResult]:
        return [d for d in self.differences if d.diff_type == diff_type]


class DiffChecker:
    """
    Compare HTTP responses to detect security-relevant differences
    
    KEY FEATURE: Semantic IDOR Detection
    - Extracts identifier fields from both responses
    - Compares internal IDs to detect cross-user access
    - Much more reliable than status code comparison
    """
    
    # Fields that indicate unique identifiers (IDOR pivots)
    IDENTIFIER_FIELDS = {
        # Primary identifiers
        "id", "uuid", "_id", "uid", "guid",
        # User identifiers  
        "user_id", "userId", "patient_id", "patientId", "account_id", "accountId",
        "subject_id", "subjectId", "owner_id", "ownerId", "creator_id",
        # Object identifiers
        "document_id", "documentId", "file_id", "fileId", "record_id", "recordId",
        "appointment_id", "appointmentId", "consultation_id",
        # Healthcare / encrypted record identifiers
        "tanker_group_identifier", "tanker_id", "master_patient_id",
        "practitioner_id", "practice_id", "agenda_id",
        # Generic patterns
        "identifier", "ref", "reference", "external_id", "internal_id"
    }
    
    # Fields that indicate sensitive data
    SENSITIVE_FIELDS = {
        # PII
        "email", "phone", "address", "ssn", "dob", "date_of_birth",
        "first_name", "last_name", "full_name", "name",
        # Financial
        "credit_card", "card_number", "cvv", "iban", "account_number",
        "balance", "salary", "income",
        # Medical / healthcare data
        "patient", "diagnosis", "prescription", "medical_history",
        "appointment", "consultation", "symptom", "treatment",
        # Auth
        "password", "token", "secret", "api_key", "session",
        # IDs that shouldn't cross boundaries
        "user_id", "patient_id", "account_id", "private"
    }
    
    # Fields that indicate privilege/role
    PRIVILEGE_FIELDS = {
        "role", "admin", "is_admin", "permissions", "scope",
        "can_edit", "can_delete", "is_owner", "access_level",
        "practitioner", "doctor", "staff"
    }
    
    def __init__(self):
        pass
    
    def extract_identifiers(self, data: Any, path: str = "$") -> dict[str, tuple[str, Any]]:
        """
        Extract all identifier fields from a JSON structure.
        Returns: {json_path: (field_name, value)}
        """
        identifiers = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}"
                key_lower = key.lower()
                
                # Check if this is an identifier field
                is_identifier = (
                    key_lower in {k.lower() for k in self.IDENTIFIER_FIELDS} or
                    key_lower.endswith("_id") or
                    key_lower.endswith("id") and len(key_lower) > 2 or
                    "identifier" in key_lower or
                    "uuid" in key_lower
                )
                
                if is_identifier and value is not None:
                    # Store as (field_name, value)
                    identifiers[current_path] = (key, value)
                
                # Recurse into nested structures
                if isinstance(value, (dict, list)):
                    nested = self.extract_identifiers(value, current_path)
                    identifiers.update(nested)
                    
        elif isinstance(data, list):
            for i, item in enumerate(data):
                nested = self.extract_identifiers(item, f"{path}[{i}]")
                identifiers.update(nested)
        
        return identifiers
    
    def detect_semantic_idor(
        self,
        baseline_json: Any,
        attack_json: Any,
        baseline_request_id: str = "",
        attack_request_id: str = ""
    ) -> list[IDOREvidence]:
        """
        CORE SEMANTIC IDOR DETECTION
        
        Golden Rule:
        If Request(ID_A) gives Response(Internal_ID_A) 
        and Request(ID_B) gives Response(Internal_ID_B)
        with SAME session → IDOR CONFIRMED!
        
        Returns list of IDOR evidence found.
        """
        evidence_list = []
        
        # Extract identifiers from both responses
        baseline_ids = self.extract_identifiers(baseline_json)
        attack_ids = self.extract_identifiers(attack_json)
        
        # Compare identifiers at same paths
        for path, (field_name, baseline_value) in baseline_ids.items():
            if path in attack_ids:
                attack_field, attack_value = attack_ids[path]
                
                # IDOR DETECTED if internal ID changed!
                if baseline_value != attack_value:
                    # Calculate confidence based on field type
                    confidence = self._calculate_idor_confidence(field_name, baseline_value, attack_value)
                    
                    if confidence >= 0.6:  # Minimum threshold
                        evidence_list.append(IDOREvidence(
                            baseline_id=str(baseline_request_id),
                            attack_id=str(attack_request_id),
                            baseline_internal_id=str(baseline_value),
                            attack_internal_id=str(attack_value),
                            id_field=field_name,
                            json_path=path,
                            confidence=confidence
                        ))
        
        return evidence_list
    
    def _calculate_idor_confidence(self, field_name: str, baseline_val: Any, attack_val: Any) -> float:
        """Calculate confidence that this is a real IDOR based on field and values"""
        confidence = 0.5  # Base confidence
        
        field_lower = field_name.lower()
        
        # High confidence fields
        if field_lower in ("id", "user_id", "patient_id", "subject_id", "account_id"):
            confidence += 0.4
        elif "id" in field_lower or "identifier" in field_lower:
            confidence += 0.3
        elif field_lower in self.IDENTIFIER_FIELDS:
            confidence += 0.25
        
        # Both values are numeric IDs → higher confidence
        try:
            int(baseline_val)
            int(attack_val)
            confidence += 0.1
        except (ValueError, TypeError):
            pass
        
        # Values are UUIDs → higher confidence
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if (isinstance(baseline_val, str) and re.match(uuid_pattern, baseline_val, re.I) and
            isinstance(attack_val, str) and re.match(uuid_pattern, attack_val, re.I)):
            confidence += 0.15
        
        # Cap at 1.0
        return min(confidence, 1.0)
    
    def compare_json(
        self,
        baseline: Any,
        modified: Any,
        path: str = ""
    ) -> list[DiffResult]:
        """
        Recursively compare two JSON structures
        Returns list of differences found
        """
        diffs = []
        
        # Handle type mismatches
        if type(baseline) != type(modified):
            diffs.append(DiffResult(
                diff_type=DiffType.STRUCTURE_CHANGED,
                path=path or "root",
                expected=type(baseline).__name__,
                actual=type(modified).__name__,
                severity="medium",
                description=f"Type changed from {type(baseline).__name__} to {type(modified).__name__}"
            ))
            return diffs
        
        # Compare dictionaries
        if isinstance(baseline, dict):
            baseline_keys = set(baseline.keys())
            modified_keys = set(modified.keys())
            
            # Fields added in modified
            for key in modified_keys - baseline_keys:
                current_path = f"{path}.{key}" if path else key
                severity = self._assess_field_severity(key, modified[key])
                diff_type = DiffType.DATA_LEAK if severity in ("critical", "high") else DiffType.FIELD_ADDED
                
                diffs.append(DiffResult(
                    diff_type=diff_type,
                    path=current_path,
                    expected=None,
                    actual=modified[key],
                    severity=severity,
                    description=f"New field '{key}' exposed" + (
                        " - POTENTIAL DATA LEAK" if diff_type == DiffType.DATA_LEAK else ""
                    )
                ))
            
            # Fields removed in modified
            for key in baseline_keys - modified_keys:
                current_path = f"{path}.{key}" if path else key
                diffs.append(DiffResult(
                    diff_type=DiffType.FIELD_REMOVED,
                    path=current_path,
                    expected=baseline[key],
                    actual=None,
                    severity="info",
                    description=f"Field '{key}' removed"
                ))
            
            # Recurse into common fields
            for key in baseline_keys & modified_keys:
                current_path = f"{path}.{key}" if path else key
                child_diffs = self.compare_json(baseline[key], modified[key], current_path)
                diffs.extend(child_diffs)
        
        # Compare lists
        elif isinstance(baseline, list):
            # Check if list lengths differ
            if len(baseline) != len(modified):
                diffs.append(DiffResult(
                    diff_type=DiffType.SIZE_CHANGED,
                    path=path or "root",
                    expected=len(baseline),
                    actual=len(modified),
                    severity="medium" if len(modified) > len(baseline) else "low",
                    description=f"Array length changed: {len(baseline)} → {len(modified)}"
                ))
            
            # Compare elements (up to min length)
            for i in range(min(len(baseline), len(modified))):
                child_diffs = self.compare_json(baseline[i], modified[i], f"{path}[{i}]")
                diffs.extend(child_diffs)
        
        # Compare primitives
        else:
            if baseline != modified:
                field_name = path.split(".")[-1] if path else ""
                severity = self._assess_field_severity(field_name, modified)
                
                diffs.append(DiffResult(
                    diff_type=DiffType.VALUE_CHANGED,
                    path=path,
                    expected=baseline,
                    actual=modified,
                    severity=severity,
                    description=f"Value changed: {baseline} → {modified}"
                ))
        
        return diffs
    
    def _assess_field_severity(self, field_name: str, value: Any) -> str:
        """Assess the security severity of a field based on its name and value"""
        field_lower = field_name.lower()
        
        # Critical: Clear sensitive data
        if any(s in field_lower for s in ("password", "secret", "ssn", "credit_card", "cvv")):
            return "critical"
        
        # High: PII or medical data
        if any(s in field_lower for s in self.SENSITIVE_FIELDS):
            return "high"
        
        # High: Privilege fields
        if any(s in field_lower for s in self.PRIVILEGE_FIELDS):
            return "high"
        
        # Medium: IDs that might indicate IDOR
        if "id" in field_lower and isinstance(value, (int, str)):
            return "medium"
        
        return "low"
    
    def compare_responses(
        self,
        baseline_body: str,
        baseline_status: int,
        modified_body: str,
        modified_status: int,
        baseline_headers: dict[str, str] = None,
        modified_headers: dict[str, str] = None,
        baseline_request_id: str = "",
        attack_request_id: str = ""
    ) -> ComparisonReport:
        """
        Compare two HTTP responses comprehensively
        Used to detect IDOR, data leaks, privilege escalation
        
        NOW WITH SEMANTIC IDOR DETECTION!
        """
        report = ComparisonReport()
        
        # Compare status codes
        if baseline_status != modified_status:
            report.is_identical = False
            
            # Status code going from 403/401 to 200 is suspicious
            if baseline_status in (401, 403) and modified_status == 200:
                report.differences.append(DiffResult(
                    diff_type=DiffType.PRIVILEGE_CHANGE,
                    path="status_code",
                    expected=baseline_status,
                    actual=modified_status,
                    severity="critical",
                    description=f"Access granted! Status changed from {baseline_status} to {modified_status}"
                ))
                report.has_privilege_issue = True
            else:
                report.differences.append(DiffResult(
                    diff_type=DiffType.STATUS_CHANGED,
                    path="status_code",
                    expected=baseline_status,
                    actual=modified_status,
                    severity="medium",
                    description=f"Status code changed: {baseline_status} → {modified_status}"
                ))
        
        # Compare body content
        baseline_json = None
        modified_json = None
        
        try:
            baseline_json = json.loads(baseline_body) if baseline_body else {}
            modified_json = json.loads(modified_body) if modified_body else {}
            
            json_diffs = self.compare_json(baseline_json, modified_json)
            if json_diffs:
                report.is_identical = False
                report.differences.extend(json_diffs)
                
                # Check for data leaks
                data_leak_diffs = [d for d in json_diffs if d.diff_type == DiffType.DATA_LEAK]
                if data_leak_diffs:
                    report.has_data_leak = True
                
                # Check for privilege issues
                priv_diffs = [d for d in json_diffs if d.diff_type == DiffType.PRIVILEGE_CHANGE]
                if priv_diffs:
                    report.has_privilege_issue = True
            
            # ===== SEMANTIC IDOR DETECTION =====
            # Both responses are 200? Check for internal ID differences!
            if baseline_status == 200 and modified_status == 200:
                idor_evidence = self.detect_semantic_idor(
                    baseline_json, modified_json,
                    baseline_request_id, attack_request_id
                )
                
                if idor_evidence:
                    report.idor_evidence = idor_evidence
                    report.has_idor = True
                    report.is_identical = False
                    
                    # Calculate overall IDOR confidence
                    max_confidence = max(e.confidence for e in idor_evidence)
                    report.idor_confidence = max_confidence
                    
                    # Add IDOR-specific diff results
                    for evidence in idor_evidence:
                        report.differences.append(DiffResult(
                            diff_type=DiffType.IDOR_CONFIRMED,
                            path=evidence.json_path,
                            expected=f"{evidence.baseline_internal_id} (for request_id={evidence.baseline_id})",
                            actual=f"{evidence.attack_internal_id} (for request_id={evidence.attack_id})",
                            severity="critical",
                            description=f"🚨 IDOR CONFIRMED! Field '{evidence.id_field}' shows different internal ID when requesting different external ID. Confidence: {evidence.confidence:.0%}"
                        ))
                    
        except json.JSONDecodeError:
            # Fall back to simple text comparison
            if baseline_body != modified_body:
                report.is_identical = False
                
                # Check size difference
                baseline_len = len(baseline_body) if baseline_body else 0
                modified_len = len(modified_body) if modified_body else 0
                
                if abs(baseline_len - modified_len) > 100:
                    report.differences.append(DiffResult(
                        diff_type=DiffType.SIZE_CHANGED,
                        path="body",
                        expected=baseline_len,
                        actual=modified_len,
                        severity="medium",
                        description=f"Response size changed significantly: {baseline_len} → {modified_len} bytes"
                    ))
        
        # Generate summary
        if report.has_idor:
            # IDOR takes priority!
            report.summary = f"🚨 IDOR CONFIRMED with {report.idor_confidence:.0%} confidence! Found {len(report.idor_evidence)} internal ID(s) that differ between requests."
        elif report.is_identical:
            report.summary = "Responses are identical - no IDOR detected"
        else:
            critical_count = len(report.get_by_severity("critical"))
            high_count = len(report.get_by_severity("high"))
            
            if critical_count > 0:
                report.summary = f"⚠️ CRITICAL: {critical_count} critical differences found!"
            elif high_count > 0:
                report.summary = f"🔴 HIGH: {high_count} high-severity differences found"
            else:
                report.summary = f"Found {len(report.differences)} differences"
        
        return report
    
    def detect_idor(
        self,
        original_response: str,
        original_status: int,
        tampered_response: str,
        tampered_status: int,
        tampered_id: str,
        original_id: str = ""
    ) -> dict[str, Any]:
        """
        Specifically detect IDOR vulnerability using SEMANTIC analysis
        Compare original request response with response using tampered ID
        
        THE GOLDEN RULE:
        - Request(ID_A) → Response(Internal_ID_X)
        - Request(ID_B) → Response(Internal_ID_Y)
        - If X != Y and both returned 200 → IDOR CONFIRMED!
        
        Returns confirmation dict with vulnerability details
        """
        report = self.compare_responses(
            original_response, original_status,
            tampered_response, tampered_status,
            baseline_request_id=original_id,
            attack_request_id=tampered_id
        )
        
        is_idor = False
        evidence = []
        confidence = 0.0
        idor_type = "none"
        
        # ===== PRIMARY: SEMANTIC IDOR DETECTION =====
        if report.has_idor:
            is_idor = True
            confidence = report.idor_confidence
            idor_type = "semantic_id_mismatch"
            
            for e in report.idor_evidence:
                evidence.append(
                    f"Field '{e.id_field}' at '{e.json_path}': "
                    f"Request(id={e.baseline_id}) → Internal({e.baseline_internal_id}), "
                    f"Request(id={e.attack_id}) → Internal({e.attack_internal_id}) "
                    f"[Confidence: {e.confidence:.0%}]"
                )
        
        # ===== SECONDARY: Privilege Escalation =====
        if report.has_privilege_issue:
            is_idor = True
            confidence = max(confidence, 0.95)
            idor_type = "privilege_escalation" if idor_type == "none" else idor_type
            evidence.append("Bypassed authorization check (401/403 → 200)")
        
        # ===== TERTIARY: Data leak detection =====
        if report.has_data_leak:
            if not is_idor:
                confidence = 0.6
            is_idor = True
            evidence.append("Response contains sensitive fields from different context")
        
        # ===== FALLBACK: Both 200 with different content =====
        if not is_idor and tampered_status == 200 and original_status == 200:
            try:
                tampered_json = json.loads(tampered_response)
                original_json = json.loads(original_response)
                
                # If we get DIFFERENT data with status 200, it's suspicious
                if tampered_json != original_json:
                    # But only if it's not just an error response
                    has_error = any(k in str(tampered_json).lower() for k in ("error", "unauthorized", "forbidden", "not found"))
                    
                    if not has_error:
                        is_idor = True
                        confidence = 0.5  # Lower confidence - needs manual review
                        idor_type = "content_difference"
                        evidence.append(f"Got different content for tampered ID (needs manual verification)")
                        
            except json.JSONDecodeError:
                pass
        
        return {
            "is_vulnerable": is_idor,
            "original_id": original_id,
            "tampered_id": tampered_id,
            "evidence": evidence,
            "confidence": confidence,
            "idor_type": idor_type,
            "severity": "critical" if confidence >= 0.8 else ("high" if confidence >= 0.6 else ("medium" if is_idor else "none")),
            "report": report.to_dict()
        }


# Singleton instance
_checker: DiffChecker = None

def get_checker() -> DiffChecker:
    """Get or create the global checker instance"""
    global _checker
    if _checker is None:
        _checker = DiffChecker()
    return _checker


class TokenDecoder:
    """
    Automatically decode Base64 and JWT tokens found in responses.
    Useful for extracting hidden IDs that can be used as pivot points.
    """
    
    @staticmethod
    def decode_base64(value: str) -> Optional[str]:
        """Try to decode a Base64 string"""
        if not isinstance(value, str) or len(value) < 4:
            return None
        
        # Add padding if needed
        padded = value + "=" * (4 - len(value) % 4) if len(value) % 4 else value
        
        try:
            # Try standard base64
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            # Check if it looks like valid data
            if decoded.isprintable() and len(decoded) > 2:
                return decoded
        except:
            pass
        
        try:
            # Try URL-safe base64
            decoded = base64.urlsafe_b64decode(padded).decode('utf-8', errors='ignore')
            if decoded.isprintable() and len(decoded) > 2:
                return decoded
        except:
            pass
        
        return None
    
    @staticmethod
    def decode_jwt(token: str) -> Optional[dict]:
        """Decode a JWT token (without verification)"""
        if not isinstance(token, str):
            return None
        
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        result = {}
        
        try:
            # Decode header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = base64.urlsafe_b64decode(header_padded)
            result['header'] = json.loads(header)
        except:
            pass
        
        try:
            # Decode payload
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = base64.urlsafe_b64decode(payload_padded)
            result['payload'] = json.loads(payload)
        except:
            pass
        
        return result if result else None
    
    @staticmethod
    def extract_encoded_ids(data: Any, path: str = "$") -> dict[str, dict]:
        """
        Recursively scan JSON for encoded tokens and decode them.
        Returns: {json_path: {"original": value, "decoded": decoded_value, "type": "base64|jwt"}}
        """
        results = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}"
                
                if isinstance(value, str):
                    # Try JWT first
                    jwt_result = TokenDecoder.decode_jwt(value)
                    if jwt_result:
                        results[current_path] = {
                            "original": value[:50] + "..." if len(value) > 50 else value,
                            "decoded": jwt_result,
                            "type": "jwt",
                            "field": key
                        }
                    else:
                        # Try Base64 for fields that look encoded
                        key_lower = key.lower()
                        if any(hint in key_lower for hint in ("token", "key", "identifier", "id", "encoded", "data")):
                            b64_result = TokenDecoder.decode_base64(value)
                            if b64_result and b64_result != value:
                                results[current_path] = {
                                    "original": value[:50] + "..." if len(value) > 50 else value,
                                    "decoded": b64_result,
                                    "type": "base64",
                                    "field": key
                                }
                
                # Recurse into nested structures
                if isinstance(value, (dict, list)):
                    nested = TokenDecoder.extract_encoded_ids(value, current_path)
                    results.update(nested)
                    
        elif isinstance(data, list):
            for i, item in enumerate(data):
                nested = TokenDecoder.extract_encoded_ids(item, f"{path}[{i}]")
                results.update(nested)
        
        return results
    
    @staticmethod
    def extract_ids_from_decoded(decoded_data: dict) -> list[dict]:
        """
        Extract potential pivot IDs from decoded JWT/Base64 data.
        Returns list of {field, value, type} dicts.
        """
        ids = []
        
        def scan_dict(d: dict, prefix: str = ""):
            for key, value in d.items():
                full_key = f"{prefix}.{key}" if prefix else key
                key_lower = key.lower()
                
                # Check if this looks like an ID field
                is_id = (
                    key_lower in ("id", "uid", "sub", "user_id", "patient_id", "account_id") or
                    key_lower.endswith("_id") or
                    key_lower.endswith("id") and len(key_lower) > 2 or
                    "identifier" in key_lower
                )
                
                if is_id and value is not None:
                    ids.append({
                        "field": full_key,
                        "value": value,
                        "source": "decoded_token"
                    })
                
                if isinstance(value, dict):
                    scan_dict(value, full_key)
        
        if isinstance(decoded_data, dict):
            scan_dict(decoded_data)
        
        return ids


# Token decoder singleton
_token_decoder: TokenDecoder = None

def get_token_decoder() -> TokenDecoder:
    """Get or create the global token decoder instance"""
    global _token_decoder
    if _token_decoder is None:
        _token_decoder = TokenDecoder()
    return _token_decoder

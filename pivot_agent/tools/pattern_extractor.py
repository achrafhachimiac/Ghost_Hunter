"""
Pattern Extractor Tool
Extract pivotable data from HTTP responses: IDs, tokens, sensitive data
With full JSONPath traceability for intelligent pivoting.
"""

import re
import json
import base64
from typing import Any, Optional
from dataclasses import dataclass, field


@dataclass
class ExtractedValue:
    """A single extracted value with full provenance"""
    value: str
    pattern_type: str  # uuid, tanker_id, numeric_id, etc.
    json_path: str     # e.g., "$.data.appointments[0].doctor_id"
    source_url: str    # The endpoint URL where this was found
    source_field: Optional[str] = None  # The JSON field name
    context: Optional[str] = None  # Surrounding context for debugging
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "type": self.pattern_type,
            "json_path": self.json_path,
            "source_url": self.source_url,
            "source_field": self.source_field,
            "context": self.context
        }


@dataclass
class ExtractedPatterns:
    """Container for all extracted patterns from a response"""
    uuids: list[str] = field(default_factory=list)
    numeric_ids: list[str] = field(default_factory=list)
    jwts: list[str] = field(default_factory=list)
    api_keys: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    signed_ids: list[str] = field(default_factory=list)  # Rails signed IDs, etc.
    phone_numbers: list[str] = field(default_factory=list)
    timestamps: list[str] = field(default_factory=list)
    tanker_ids: list[str] = field(default_factory=list)  # Tanker-style encrypted IDs
    base64_ids: list[str] = field(default_factory=list)  # Generic Base64 encoded IDs
    custom: dict[str, list[str]] = field(default_factory=dict)
    
    # NEW: Full provenance tracking
    provenance: list[ExtractedValue] = field(default_factory=list)
    source_url: str = ""  # URL this extraction came from
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "uuids": self.uuids,
            "numeric_ids": self.numeric_ids,
            "jwts": self.jwts,
            "api_keys": self.api_keys,
            "emails": self.emails,
            "urls": self.urls,
            "signed_ids": self.signed_ids,
            "phone_numbers": self.phone_numbers,
            "timestamps": self.timestamps,
            "tanker_ids": self.tanker_ids,
            "base64_ids": self.base64_ids,
            "custom": self.custom,
            "provenance": [p.to_dict() for p in self.provenance],
            "source_url": self.source_url
        }
    
    def is_empty(self) -> bool:
        return not any([
            self.uuids, self.numeric_ids, self.jwts, self.api_keys,
            self.emails, self.urls, self.signed_ids, self.phone_numbers,
            self.timestamps, self.tanker_ids, self.base64_ids, self.custom
        ])
    
    def merge(self, other: "ExtractedPatterns") -> "ExtractedPatterns":
        """Merge another ExtractedPatterns into this one (deduped)"""
        return ExtractedPatterns(
            uuids=list(set(self.uuids + other.uuids)),
            numeric_ids=list(set(self.numeric_ids + other.numeric_ids)),
            jwts=list(set(self.jwts + other.jwts)),
            api_keys=list(set(self.api_keys + other.api_keys)),
            emails=list(set(self.emails + other.emails)),
            urls=list(set(self.urls + other.urls)),
            signed_ids=list(set(self.signed_ids + other.signed_ids)),
            phone_numbers=list(set(self.phone_numbers + other.phone_numbers)),
            timestamps=list(set(self.timestamps + other.timestamps)),
            tanker_ids=list(set(self.tanker_ids + other.tanker_ids)),
            base64_ids=list(set(self.base64_ids + other.base64_ids)),
            custom={k: list(set(v)) for k, v in {**self.custom, **other.custom}.items()},
            provenance=self.provenance + other.provenance,
            source_url=self.source_url or other.source_url
        )
    
    def get_all_ids_with_provenance(self) -> list[ExtractedValue]:
        """Get all ID-like values with their full provenance"""
        return [p for p in self.provenance if p.pattern_type in (
            "uuid", "numeric_id", "tanker_id", "base64_id", "signed_id"
        )]
    
    def get_provenance_for_value(self, value: str) -> Optional[ExtractedValue]:
        """Get provenance info for a specific value"""
        for p in self.provenance:
            if p.value == value:
                return p
        return None


class PatternExtractor:
    """Extract pivotable patterns from HTTP responses with full provenance tracking"""
    
    # Regex patterns for common identifiers
    PATTERNS = {
        # UUID v4 (most common in APIs)
        "uuid": re.compile(
            r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
        ),
        
        # Numeric IDs (standalone numbers that look like IDs)
        "numeric_id": re.compile(
            r'(?:["\':])\s*(\d{4,12})\s*(?:["\',}\]])'
        ),
        
        # JWT tokens
        "jwt": re.compile(
            r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'
        ),
        
        # API keys (common patterns)
        "api_key": re.compile(
            r'\b(?:sk|pk|api|key|token|secret|access)[_-]?[a-zA-Z0-9]{20,}\b',
            re.IGNORECASE
        ),
        
        # Email addresses
        "email": re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ),
        
        # URLs (internal API endpoints)
        "url": re.compile(
            r'https?://[^\s"\'<>\]]+',
            re.IGNORECASE
        ),
        
        # Rails/Django signed IDs (base64-ish with signature)
        "signed_id": re.compile(
            r'\b[A-Za-z0-9+/=]{40,}--[A-Za-z0-9+/=]+\b'
        ),
        
        # Phone numbers (international format)
        "phone": re.compile(
            r'(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        ),
        
        # ISO timestamps
        "timestamp": re.compile(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'
        ),
        
        # NEW: Tanker-style IDs - Base64 ending with == or =
        # These are typically encryption keys/IDs used by Tanker SDK
        # Uses lookahead/behind instead of word boundary because = breaks \b
        "tanker_id": re.compile(
            r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={1,2}(?![A-Za-z0-9+/=])'
        ),
        
        # NEW: Generic Base64 IDs (long base64 strings in JSON values)
        # Matches base64 strings 24+ chars that look like encoded IDs
        # Standard base64: multiple of 4 chars with optional = or == padding
        "base64_id": re.compile(
            r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}(?:={0,2})(?![A-Za-z0-9+/=])'
        ),
    }
    
    # Field names that typically contain sensitive/pivotable data
    INTERESTING_FIELDS = {
        "id", "user_id", "userId", "account_id", "accountId",
        "patient_id", "patientId", "doctor_id", "doctorId",
        "appointment_id", "appointmentId", "booking_id", "bookingId",
        "token", "access_token", "refresh_token", "api_key",
        "email", "phone", "address", "ssn", "dob", "date_of_birth",
        "credit_card", "card_number", "cvv", "iban",
        "password", "secret", "key", "signature",
        "practitioner_id", "practice_id", "organization_id",
        # Healthcare / encrypted-record fields
        "subject_id", "subjectId", "tanker_public_key", "encrypted_data",
        "document_id", "documentId", "group_id", "groupId",
        "identity_key", "public_identity", "private_identity",
        "resource_id", "resourceId", "share_id", "shareId"
    }
    
    def __init__(self, custom_patterns: dict[str, re.Pattern] = None):
        """Initialize with optional custom patterns"""
        self.patterns = {**self.PATTERNS}
        if custom_patterns:
            self.patterns.update(custom_patterns)
        self._current_source_url = ""
    
    def extract_from_text(self, text: str, json_path: str = "$") -> ExtractedPatterns:
        """Extract all patterns from raw text with provenance"""
        result = ExtractedPatterns(source_url=self._current_source_url)
        
        if not text:
            return result
        
        # Extract each pattern type with provenance
        for match in self.PATTERNS["uuid"].finditer(text):
            value = match.group()
            result.uuids.append(value)
            result.provenance.append(ExtractedValue(
                value=value,
                pattern_type="uuid",
                json_path=json_path,
                source_url=self._current_source_url,
                context=text[max(0, match.start()-20):match.end()+20]
            ))
        
        for match in self.PATTERNS["jwt"].finditer(text):
            value = match.group()
            result.jwts.append(value)
            result.provenance.append(ExtractedValue(
                value=value,
                pattern_type="jwt",
                json_path=json_path,
                source_url=self._current_source_url
            ))
        
        for match in self.PATTERNS["tanker_id"].finditer(text):
            value = match.group()
            # Validate it's actually base64
            if self._is_valid_base64(value):
                result.tanker_ids.append(value)
                result.provenance.append(ExtractedValue(
                    value=value,
                    pattern_type="tanker_id",
                    json_path=json_path,
                    source_url=self._current_source_url,
                    context=text[max(0, match.start()-20):match.end()+20]
                ))
        
        for match in self.PATTERNS["base64_id"].finditer(text):
            value = match.group()
            # Avoid duplicates with tanker_ids and validate
            if value not in result.tanker_ids and self._is_valid_base64(value):
                # Skip if it looks like a JWT or signed_id
                if not value.startswith("eyJ") and "--" not in value:
                    result.base64_ids.append(value)
                    result.provenance.append(ExtractedValue(
                        value=value,
                        pattern_type="base64_id",
                        json_path=json_path,
                        source_url=self._current_source_url
                    ))
        
        # Standard extractions (without full provenance for performance)
        result.api_keys = list(set(self.PATTERNS["api_key"].findall(text)))
        result.emails = list(set(self.PATTERNS["email"].findall(text)))
        result.urls = list(set(self.PATTERNS["url"].findall(text)))
        result.signed_ids = list(set(self.PATTERNS["signed_id"].findall(text)))
        result.phone_numbers = list(set(self.PATTERNS["phone"].findall(text)))
        result.timestamps = list(set(self.PATTERNS["timestamp"].findall(text)))
        
        # Numeric IDs need special handling (capture group)
        for match in self.PATTERNS["numeric_id"].finditer(text):
            value = match.group(1)
            result.numeric_ids.append(value)
            result.provenance.append(ExtractedValue(
                value=value,
                pattern_type="numeric_id",
                json_path=json_path,
                source_url=self._current_source_url,
                context=text[max(0, match.start()-20):match.end()+20]
            ))
        
        result.numeric_ids = list(set(result.numeric_ids))
        result.uuids = list(set(result.uuids))
        
        return result
    
    def _is_valid_base64(self, s: str) -> bool:
        """Check if a string is valid base64"""
        try:
            # Check length is multiple of 4 or has valid padding
            if len(s) < 16:
                return False
            base64.b64decode(s)
            return True
        except Exception:
            return False
    
    def extract_from_json(
        self, 
        data: Any, 
        path: str = "$",
        source_url: str = ""
    ) -> ExtractedPatterns:
        """
        Recursively extract patterns from JSON data with full JSONPath tracking.
        Returns values with their exact location in the JSON structure.
        """
        result = ExtractedPatterns(source_url=source_url or self._current_source_url)
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}"
                
                # Check if field name is interesting
                if key.lower() in {f.lower() for f in self.INTERESTING_FIELDS}:
                    if isinstance(value, (str, int)):
                        if key not in result.custom:
                            result.custom[key] = []
                        result.custom[key].append(str(value))
                        
                        # Add to provenance with field context
                        result.provenance.append(ExtractedValue(
                            value=str(value),
                            pattern_type=f"field:{key}",
                            json_path=current_path,
                            source_url=source_url or self._current_source_url,
                            source_field=key
                        ))
                
                # Recursively process
                child_result = self.extract_from_json(value, current_path, source_url)
                result = result.merge(child_result)
                
        elif isinstance(data, list):
            for i, item in enumerate(data):
                child_result = self.extract_from_json(item, f"{path}[{i}]", source_url)
                result = result.merge(child_result)
                
        elif isinstance(data, str):
            # Extract patterns from string values with JSONPath
            text_result = self.extract_from_text(data, path)
            result = result.merge(text_result)
        
        return result
    
    def extract_from_response(
        self,
        body: str,
        headers: dict[str, str] = None,
        url: str = None
    ) -> ExtractedPatterns:
        """
        Extract patterns from a complete HTTP response
        Handles both JSON and raw text bodies with full provenance
        """
        # Store source URL for provenance tracking
        self._current_source_url = url or ""
        result = ExtractedPatterns(source_url=url or "")
        
        # Extract from URL
        if url:
            url_result = self.extract_from_text(url, "$.url")
            result = result.merge(url_result)
        
        # Extract from headers
        if headers:
            for header_name, header_value in headers.items():
                header_result = self.extract_from_text(
                    header_value, 
                    f"$.headers.{header_name}"
                )
                result = result.merge(header_result)
        
        # Extract from body
        if body:
            # Try to parse as JSON first
            try:
                json_data = json.loads(body)
                json_result = self.extract_from_json(json_data, "$.body", url)
                result = result.merge(json_result)
            except json.JSONDecodeError:
                # Fall back to raw text extraction
                text_result = self.extract_from_text(body, "$.body")
                result = result.merge(text_result)
        
        return result
    
    def find_idor_candidates(self, patterns: ExtractedPatterns) -> list[dict[str, Any]]:
        """
        Identify potential IDOR candidates from extracted patterns
        Returns list of candidates with full provenance for intelligent pivoting
        """
        candidates = []
        
        # UUIDs are prime IDOR targets
        for uuid in patterns.uuids:
            provenance = patterns.get_provenance_for_value(uuid)
            candidates.append({
                "type": "uuid",
                "value": uuid,
                "pivot_suggestion": "Try using another user's UUID from a different endpoint",
                "provenance": provenance.to_dict() if provenance else None
            })
        
        # Tanker-style IDs (encrypted record keys)
        for tanker_id in patterns.tanker_ids:
            provenance = patterns.get_provenance_for_value(tanker_id)
            candidates.append({
                "type": "tanker_id",
                "value": tanker_id,
                "pivot_suggestion": "Tanker encrypted ID - try replaying on document/share endpoints",
                "provenance": provenance.to_dict() if provenance else None
            })
        
        # Base64 IDs
        for b64_id in patterns.base64_ids:
            provenance = patterns.get_provenance_for_value(b64_id)
            candidates.append({
                "type": "base64_id",
                "value": b64_id,
                "pivot_suggestion": "Base64 encoded ID - decode and analyze, or replay as-is",
                "provenance": provenance.to_dict() if provenance else None
            })
        
        # Numeric IDs are classic IDOR targets
        for num_id in patterns.numeric_ids:
            provenance = patterns.get_provenance_for_value(num_id)
            try:
                id_int = int(num_id)
                candidates.append({
                    "type": "numeric_id",
                    "value": num_id,
                    "pivot_suggestion": f"Try {id_int - 1}, {id_int + 1}, or sequential scan",
                    "nearby_values": [str(id_int - 1), str(id_int + 1)],
                    "provenance": provenance.to_dict() if provenance else None
                })
            except ValueError:
                pass
        
        # Custom fields with ID-like names
        for field_name, values in patterns.custom.items():
            if "id" in field_name.lower():
                for value in values:
                    provenance = patterns.get_provenance_for_value(value)
                    candidates.append({
                        "type": f"custom_field:{field_name}",
                        "value": value,
                        "field_name": field_name,
                        "pivot_suggestion": f"Field '{field_name}' extracted - replay on related endpoints",
                        "provenance": provenance.to_dict() if provenance else None
                    })
        
        return candidates
    
    def build_provenance_map(self, patterns: ExtractedPatterns) -> dict[str, dict[str, Any]]:
        """
        Build a provenance map for state tracking.
        Maps each extracted value to its origin information.
        """
        provenance_map = {}
        
        for prov in patterns.provenance:
            provenance_map[prov.value] = {
                "type": prov.pattern_type,
                "json_path": prov.json_path,
                "source_url": prov.source_url,
                "source_field": prov.source_field,
                "context": prov.context
            }
        
        return provenance_map


# Singleton instance
_extractor: PatternExtractor = None

def get_extractor() -> PatternExtractor:
    """Get or create the global extractor instance"""
    global _extractor
    if _extractor is None:
        _extractor = PatternExtractor()
    return _extractor


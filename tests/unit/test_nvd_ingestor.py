"""
Tests pour l'ingestor NVD (CVE).

Teste:
- Filtrage CWE web
- Rate limiting
- Conversion CVE → Chunk
- Filtrage CVSS
"""

import pytest
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from ghost_hunter.core.rag.ingestors.nvd import (
    # CWE utilities
    load_cwe_whitelist,
    _normalize_cwe,
    _get_default_web_cwes,
    extract_cwe_from_cve,
    extract_cvss_score,
    get_severity_from_cvss,
    # Rate limiter
    RateLimiter,
    # NVD client
    NVDApiClient,
    # Sync service
    NVDSyncService,
    # Ingestor
    NVDIngestor,
    # Helpers
    sync_nvd_cves,
    is_pipeline_active,
)
from ghost_hunter.core.rag.ingestors.registry import IngestorRegistry


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def sample_cve_xss():
    """CVE avec XSS (CWE-79)."""
    return {
        "cve": {
            "id": "CVE-2024-12345",
            "descriptions": [
                {"lang": "en", "value": "XSS vulnerability in Example App allows remote attackers to inject scripts."}
            ],
            "weaknesses": [
                {
                    "description": [
                        {"lang": "en", "value": "CWE-79"}
                    ]
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 6.1,
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def sample_cve_sqli():
    """CVE avec SQLi (CWE-89)."""
    return {
        "cve": {
            "id": "CVE-2024-67890",
            "descriptions": [
                {"lang": "en", "value": "SQL injection in login form allows authentication bypass."}
            ],
            "weaknesses": [
                {
                    "description": [
                        {"lang": "en", "value": "CWE-89"}
                    ]
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 9.8,
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def sample_cve_buffer_overflow():
    """CVE avec Buffer Overflow (CWE-120) - NON WEB."""
    return {
        "cve": {
            "id": "CVE-2024-11111",
            "descriptions": [
                {"lang": "en", "value": "Buffer overflow in native code allows RCE."}
            ],
            "weaknesses": [
                {
                    "description": [
                        {"lang": "en", "value": "CWE-120"}
                    ]
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 9.0,
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def sample_cve_low_cvss():
    """CVE avec CVSS faible."""
    return {
        "cve": {
            "id": "CVE-2024-22222",
            "descriptions": [
                {"lang": "en", "value": "Minor information disclosure."}
            ],
            "weaknesses": [
                {
                    "description": [
                        {"lang": "en", "value": "CWE-79"}
                    ]
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 3.5,
                        }
                    }
                ]
            }
        }
    }


# ============================================================================
# Tests: CWE Utilities
# ============================================================================

class TestNormalizeCwe:
    """Tests pour _normalize_cwe()."""
    
    def test_already_normalized(self):
        assert _normalize_cwe("CWE-79") == "CWE-79"
    
    def test_lowercase(self):
        assert _normalize_cwe("cwe-89") == "CWE-89"
    
    def test_number_only(self):
        assert _normalize_cwe("79") == "CWE-79"
    
    def test_with_spaces(self):
        assert _normalize_cwe(" CWE-79 ") == "CWE-79"


class TestExtractCweFromCve:
    """Tests pour extract_cwe_from_cve()."""
    
    def test_extracts_single_cwe(self, sample_cve_xss):
        cwes = extract_cwe_from_cve(sample_cve_xss)
        assert cwes == ["CWE-79"]
    
    def test_extracts_from_sqli(self, sample_cve_sqli):
        cwes = extract_cwe_from_cve(sample_cve_sqli)
        assert cwes == ["CWE-89"]
    
    def test_empty_for_no_weaknesses(self):
        cve = {"cve": {"id": "CVE-2024-00000", "weaknesses": []}}
        cwes = extract_cwe_from_cve(cve)
        assert cwes == []
    
    def test_empty_for_missing_weaknesses(self):
        cve = {"cve": {"id": "CVE-2024-00000"}}
        cwes = extract_cwe_from_cve(cve)
        assert cwes == []


class TestExtractCvssScore:
    """Tests pour extract_cvss_score()."""
    
    def test_extracts_v31_score(self, sample_cve_xss):
        score = extract_cvss_score(sample_cve_xss)
        assert score == 6.1
    
    def test_extracts_critical_score(self, sample_cve_sqli):
        score = extract_cvss_score(sample_cve_sqli)
        assert score == 9.8
    
    def test_none_for_no_metrics(self):
        cve = {"cve": {"id": "CVE-2024-00000", "metrics": {}}}
        score = extract_cvss_score(cve)
        assert score is None
    
    def test_v2_fallback(self):
        cve = {
            "cve": {
                "metrics": {
                    "cvssMetricV2": [
                        {"cvssData": {"baseScore": 7.5}}
                    ]
                }
            }
        }
        score = extract_cvss_score(cve)
        assert score == 7.5


class TestGetSeverityFromCvss:
    """Tests pour get_severity_from_cvss()."""
    
    def test_critical(self):
        assert get_severity_from_cvss(9.5) == "critical"
        assert get_severity_from_cvss(10.0) == "critical"
    
    def test_high(self):
        assert get_severity_from_cvss(7.0) == "high"
        assert get_severity_from_cvss(8.9) == "high"
    
    def test_medium(self):
        assert get_severity_from_cvss(4.0) == "medium"
        assert get_severity_from_cvss(6.9) == "medium"
    
    def test_low(self):
        assert get_severity_from_cvss(0.1) == "low"
        assert get_severity_from_cvss(3.9) == "low"
    
    def test_none_score(self):
        assert get_severity_from_cvss(None) == "unknown"
    
    def test_zero(self):
        assert get_severity_from_cvss(0) == "none"


class TestLoadCweWhitelist:
    """Tests pour load_cwe_whitelist()."""
    
    def test_default_cwes_returned_if_no_file(self, tmp_path):
        result = load_cwe_whitelist(tmp_path / "nonexistent.yaml")
        assert isinstance(result, set)
        assert "CWE-79" in result  # XSS
        assert "CWE-89" in result  # SQLi
    
    def test_loads_from_config(self):
        # Should load from actual config file
        result = load_cwe_whitelist()
        assert isinstance(result, set)
        assert len(result) > 10  # At least some CWEs


# ============================================================================
# Tests: Rate Limiter
# ============================================================================

class TestRateLimiter:
    """Tests pour RateLimiter."""
    
    def test_allows_under_limit(self):
        limiter = RateLimiter(requests_per_window=5, window_seconds=30)
        for _ in range(3):
            limiter.wait_if_needed()
        assert limiter.get_request_count() == 3
    
    def test_tracks_requests(self):
        limiter = RateLimiter(requests_per_window=5, window_seconds=30)
        limiter.wait_if_needed()
        limiter.wait_if_needed()
        assert limiter.get_request_count() == 2
    
    @patch('time.sleep')
    @patch('time.time')
    def test_sleeps_at_limit(self, mock_time, mock_sleep):
        # Simulate time progression
        current_time = 1000.0
        mock_time.side_effect = lambda: current_time
        
        limiter = RateLimiter(requests_per_window=2, window_seconds=30)
        limiter._request_times = [999.0, 999.5]  # 2 requests in window
        
        # This should trigger a sleep
        limiter.wait_if_needed()
        
        # Should have called sleep
        assert mock_sleep.called


# ============================================================================
# Tests: NVD Sync Service
# ============================================================================

class TestNVDSyncService:
    """Tests pour NVDSyncService."""
    
    def test_is_web_cve_accepts_xss(self, sample_cve_xss):
        service = NVDSyncService()
        assert service.is_web_cve(sample_cve_xss) is True
    
    def test_is_web_cve_accepts_sqli(self, sample_cve_sqli):
        service = NVDSyncService()
        assert service.is_web_cve(sample_cve_sqli) is True
    
    def test_is_web_cve_rejects_buffer_overflow(self, sample_cve_buffer_overflow):
        service = NVDSyncService()
        assert service.is_web_cve(sample_cve_buffer_overflow) is False
    
    def test_passes_cvss_filter_high(self, sample_cve_sqli):
        service = NVDSyncService(min_cvss=5.0)
        assert service.passes_cvss_filter(sample_cve_sqli) is True
    
    def test_passes_cvss_filter_rejects_low(self, sample_cve_low_cvss):
        service = NVDSyncService(min_cvss=5.0)
        assert service.passes_cvss_filter(sample_cve_low_cvss) is False
    
    def test_cve_to_chunk(self, sample_cve_xss):
        service = NVDSyncService()
        chunk = service.cve_to_chunk(sample_cve_xss)
        
        assert chunk is not None
        assert chunk.id == "nvd:CVE-2024-12345"
        assert "XSS vulnerability" in chunk.text
        assert chunk.metadata["source"] == "nvd"
        assert chunk.metadata["vuln_type"] == "xss"
        assert "CWE-79" in chunk.metadata["tags"]
    
    def test_cve_to_chunk_sqli(self, sample_cve_sqli):
        service = NVDSyncService()
        chunk = service.cve_to_chunk(sample_cve_sqli)
        
        assert chunk.metadata["vuln_type"] == "sqli"
        assert chunk.metadata["cvss"] == 9.8
        assert chunk.metadata["severity"] == "critical"
    
    def test_get_stats(self):
        service = NVDSyncService()
        stats = service.get_stats()
        assert "fetched" in stats
        assert "filtered_cwe" in stats
        assert "indexed" in stats


# ============================================================================
# Tests: NVD Ingestor
# ============================================================================

class TestNVDIngestor:
    """Tests pour NVDIngestor."""
    
    def setup_method(self):
        """Ensure NVD ingestor is registered (may be cleared by other tests)."""
        if "nvd" not in IngestorRegistry._ingestors:
            IngestorRegistry.register("nvd")(NVDIngestor)
    
    def test_ingestor_registration(self):
        """NVDIngestor doit être enregistré."""
        assert "nvd" in IngestorRegistry.list_available()
    
    def test_ingestor_creation(self):
        ingestor = NVDIngestor()
        assert ingestor.source_type == "api"
    
    def test_sync_does_nothing(self, caplog):
        """sync() ne doit rien faire (cron uniquement)."""
        import logging
        caplog.set_level(logging.INFO)
        
        ingestor = NVDIngestor()
        ingestor.sync()
        
        assert "skipped" in caplog.text.lower()
    
    def test_get_stats(self):
        ingestor = NVDIngestor()
        stats = ingestor.get_stats()
        assert "chunks_ready" in stats


# ============================================================================
# Tests: Helper Functions
# ============================================================================

class TestIsPipelineActive:
    """Tests pour is_pipeline_active()."""
    
    def test_false_if_no_pid_file(self, tmp_path):
        result = is_pipeline_active(tmp_path / "nonexistent.pid")
        assert result is False
    
    def test_false_if_invalid_pid(self, tmp_path):
        pid_file = tmp_path / "pipeline.pid"
        pid_file.write_text("invalid")
        result = is_pipeline_active(pid_file)
        assert result is False
    
    def test_false_if_process_not_exists(self, tmp_path):
        pid_file = tmp_path / "pipeline.pid"
        pid_file.write_text("999999999")  # PID that doesn't exist
        result = is_pipeline_active(pid_file)
        assert result is False


# ============================================================================
# Tests: CWE Filtering Coverage
# ============================================================================

class TestCweWebFiltering:
    """Tests pour la couverture du filtrage CWE."""
    
    @pytest.mark.parametrize("cwe,expected", [
        ("CWE-79", True),   # XSS
        ("CWE-89", True),   # SQLi
        ("CWE-918", True),  # SSRF
        ("CWE-611", True),  # XXE
        ("CWE-352", True),  # CSRF
        ("CWE-22", True),   # Path Traversal
        ("CWE-120", False), # Buffer Overflow
        ("CWE-119", False), # Memory Corruption
        ("CWE-476", False), # NULL Pointer
    ])
    def test_cwe_filtering(self, cwe, expected):
        """Vérifie le filtrage CWE web vs non-web."""
        service = NVDSyncService()
        cve_data = {
            "cve": {
                "id": "CVE-TEST",
                "weaknesses": [
                    {"description": [{"lang": "en", "value": cwe}]}
                ]
            }
        }
        assert service.is_web_cve(cve_data) == expected


# ============================================================================
# Tests: Integration Mocks
# ============================================================================

class TestNVDApiClientMock:
    """Tests avec mock de l'API NVD."""
    
    @patch.object(NVDApiClient, 'fetch_cves')
    def test_fetch_all_cves_pagination(self, mock_fetch):
        """Test de la pagination."""
        # First page
        mock_fetch.side_effect = [
            {
                "totalResults": 3,
                "vulnerabilities": [
                    {"cve": {"id": "CVE-1"}},
                    {"cve": {"id": "CVE-2"}},
                ],
            },
            {
                "totalResults": 3,
                "vulnerabilities": [
                    {"cve": {"id": "CVE-3"}},
                ],
            },
        ]
        
        with NVDApiClient() as client:
            cves = list(client.fetch_all_cves())
        
        assert len(cves) == 3


class TestSyncWithMock:
    """Tests de sync avec mock."""
    
    @patch.object(NVDApiClient, 'fetch_all_cves')
    def test_sync_filters_correctly(self, mock_fetch, sample_cve_xss, sample_cve_buffer_overflow):
        mock_fetch.return_value = iter([sample_cve_xss, sample_cve_buffer_overflow])
        
        service = NVDSyncService()
        chunks = service.sync_recent(days=1)
        
        # Only XSS should pass (buffer overflow filtered)
        assert len(chunks) == 1
        assert "XSS" in chunks[0].text


# ============================================================================
# Tests: Import Verification
# ============================================================================

class TestNVDImports:
    """Tests de vérification des imports."""
    
    def setup_method(self):
        """Ensure NVD ingestor is registered (may be cleared by other tests)."""
        if "nvd" not in IngestorRegistry._ingestors:
            IngestorRegistry.register("nvd")(NVDIngestor)
    
    def test_import_nvd_module(self):
        from ghost_hunter.core.rag.ingestors import nvd
        assert hasattr(nvd, 'NVDSyncService')
        assert hasattr(nvd, 'NVDIngestor')
    
    def test_import_from_registry(self):
        ingestor_class = IngestorRegistry.get("nvd")
        assert ingestor_class is NVDIngestor

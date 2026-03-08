"""
Tests for HackerOne Disclosures Ingestor
========================================
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from datetime import datetime
import tempfile
import csv

from ghost_hunter.core.rag.ingestors.disclosures import (
    HackerOneDisclosureIngestor,
    DisclosureReport,
    normalize_vuln_type,
    infer_vuln_type_from_title,
    extract_report_id,
    parse_bounty,
    H1_VULN_TYPE_MAPPING,
    TITLE_KEYWORDS_MAPPING,
)
from ghost_hunter.core.rag.ingestors.base import IngestorConfig, SyncError


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_data_dir():
    """Crée un répertoire temporaire pour les tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_csv_content():
    """Contenu CSV de test."""
    return '''title,program,link,upvotes,bounty,vuln_type
"XSS in search field",Shopify,hackerone.com/reports/123456,150,$1000,xss
"SQL Injection in login",Uber,hackerone.com/reports/234567,200,"$5,000",sql injection
"SSRF via webhook",GitHub,hackerone.com/reports/345678,100,$2500,ssrf
"IDOR in user profile",Twitter,hackerone.com/reports/456789,50,$500,idor
"Low upvotes report",Test,hackerone.com/reports/567890,5,$100,xss
"No vuln type",Unknown,hackerone.com/reports/678901,10,$200,
'''


@pytest.fixture
def ingestor_config(temp_data_dir):
    """Configuration de test."""
    return IngestorConfig(
        name="disclosures",
        enabled=True,
        weight=1.0,
        params={
            "data_dir": str(temp_data_dir),
            "min_upvotes": 0,
            "max_reports": None,
            "enrich": False,
        }
    )


@pytest.fixture
def ingestor(ingestor_config):
    """Ingestor configuré pour les tests."""
    return HackerOneDisclosureIngestor(ingestor_config)


# =============================================================================
# Tests normalize_vuln_type
# =============================================================================

class TestNormalizeVulnType:
    """Tests pour normalize_vuln_type."""
    
    def test_xss_direct(self):
        """Test mapping direct XSS."""
        assert normalize_vuln_type("xss") == "xss"
        assert normalize_vuln_type("XSS") == "xss"
    
    def test_xss_full_name(self):
        """Test XSS avec nom complet."""
        assert normalize_vuln_type("cross-site scripting") == "xss"
        assert normalize_vuln_type("Cross-Site Scripting") == "xss"
    
    def test_sqli_variations(self):
        """Test SQL Injection variations."""
        assert normalize_vuln_type("sql injection") == "sqli"
        assert normalize_vuln_type("sqli") == "sqli"
        assert normalize_vuln_type("SQL") == "sqli"
        assert normalize_vuln_type("blind sql injection") == "sqli"
    
    def test_ssrf(self):
        """Test SSRF mapping."""
        assert normalize_vuln_type("ssrf") == "ssrf"
        assert normalize_vuln_type("server-side request forgery") == "ssrf"
    
    def test_idor_variations(self):
        """Test IDOR variations."""
        assert normalize_vuln_type("idor") == "idor"
        assert normalize_vuln_type("insecure direct object reference") == "idor"
        assert normalize_vuln_type("bola") == "idor"
    
    def test_rce_variations(self):
        """Test RCE variations."""
        assert normalize_vuln_type("rce") == "rce"
        assert normalize_vuln_type("remote code execution") == "rce"
        assert normalize_vuln_type("command injection") == "rce"
    
    def test_empty_string_with_title(self):
        """Test avec vuln_type vide mais title informatif."""
        result = normalize_vuln_type("", "XSS vulnerability in search")
        assert result == "xss"
    
    def test_unknown_type(self):
        """Test type inconnu."""
        result = normalize_vuln_type("random_unknown_type")
        assert result == "unknown"
    
    def test_partial_match(self):
        """Test matching partiel."""
        assert normalize_vuln_type("stored xss vulnerability") == "xss"
        assert normalize_vuln_type("sql injection attack") == "sqli"


# =============================================================================
# Tests infer_vuln_type_from_title
# =============================================================================

class TestInferVulnTypeFromTitle:
    """Tests pour infer_vuln_type_from_title."""
    
    def test_xss_in_title(self):
        """Test XSS dans le titre."""
        assert infer_vuln_type_from_title("Stored XSS in comments") == "xss"
        assert infer_vuln_type_from_title("Cross-site scripting vulnerability") == "xss"
    
    def test_sqli_in_title(self):
        """Test SQL Injection dans le titre."""
        assert infer_vuln_type_from_title("SQL Injection in login page") == "sqli"
        assert infer_vuln_type_from_title("SQLi vulnerability") == "sqli"
    
    def test_ssrf_in_title(self):
        """Test SSRF dans le titre."""
        assert infer_vuln_type_from_title("SSRF via webhook") == "ssrf"
    
    def test_idor_in_title(self):
        """Test IDOR dans le titre."""
        assert infer_vuln_type_from_title("IDOR in user profile") == "idor"
        assert infer_vuln_type_from_title("Insecure direct object reference") == "idor"
    
    def test_rce_in_title(self):
        """Test RCE dans le titre."""
        assert infer_vuln_type_from_title("Remote code execution via upload") == "rce"
        assert infer_vuln_type_from_title("Command injection in admin panel") == "rce"
    
    def test_auth_bypass_in_title(self):
        """Test auth bypass dans le titre."""
        assert infer_vuln_type_from_title("2FA bypass vulnerability") == "auth_bypass"
        assert infer_vuln_type_from_title("Authentication bypass via token") == "auth_bypass"
    
    def test_info_disclosure_in_title(self):
        """Test information disclosure dans le titre."""
        assert infer_vuln_type_from_title("Information disclosure via API") == "info_disclosure"
    
    def test_empty_title(self):
        """Test titre vide."""
        assert infer_vuln_type_from_title("") == "unknown"
        assert infer_vuln_type_from_title(None) == "unknown"
    
    def test_no_match(self):
        """Test titre sans correspondance."""
        assert infer_vuln_type_from_title("Random bug report") == "unknown"


# =============================================================================
# Tests extract_report_id
# =============================================================================

class TestExtractReportId:
    """Tests pour extract_report_id."""
    
    def test_standard_link(self):
        """Test lien standard."""
        assert extract_report_id("hackerone.com/reports/123456") == "123456"
    
    def test_full_url(self):
        """Test URL complète."""
        assert extract_report_id("https://hackerone.com/reports/789012") == "789012"
    
    def test_no_report_id(self):
        """Test sans ID."""
        assert extract_report_id("hackerone.com/programs/shopify") == ""
    
    def test_empty_string(self):
        """Test chaîne vide."""
        assert extract_report_id("") == ""


# =============================================================================
# Tests parse_bounty
# =============================================================================

class TestParseBounty:
    """Tests pour parse_bounty."""
    
    def test_simple_number(self):
        """Test nombre simple."""
        assert parse_bounty("1000") == 1000.0
    
    def test_with_dollar_sign(self):
        """Test avec symbole dollar."""
        assert parse_bounty("$1000") == 1000.0
    
    def test_with_comma(self):
        """Test avec virgule."""
        assert parse_bounty("$1,000") == 1000.0
        assert parse_bounty("$10,000") == 10000.0
    
    def test_with_quotes(self):
        """Test avec guillemets."""
        assert parse_bounty('"$5,000"') == 5000.0
    
    def test_empty_string(self):
        """Test chaîne vide."""
        assert parse_bounty("") == 0.0
        assert parse_bounty(None) == 0.0
    
    def test_zero(self):
        """Test zéro."""
        assert parse_bounty("0") == 0.0
        assert parse_bounty("$0") == 0.0
    
    def test_invalid_string(self):
        """Test chaîne invalide."""
        assert parse_bounty("invalid") == 0.0


# =============================================================================
# Tests DisclosureReport
# =============================================================================

class TestDisclosureReport:
    """Tests pour DisclosureReport."""
    
    def test_basic_creation(self):
        """Test création basique."""
        report = DisclosureReport(
            report_id="123456",
            title="XSS in search",
            program="Shopify",
            link="hackerone.com/reports/123456",
            upvotes=100,
            bounty=1000.0,
            vuln_type="xss"
        )
        assert report.report_id == "123456"
        assert report.normalized_vuln_type == "xss"
    
    def test_normalized_vuln_type_from_raw(self):
        """Test normalisation automatique du vuln_type."""
        report = DisclosureReport(
            report_id="234567",
            title="SQL Injection",
            program="Uber",
            link="hackerone.com/reports/234567",
            upvotes=200,
            bounty=5000.0,
            vuln_type="sql injection"
        )
        assert report.normalized_vuln_type == "sqli"
    
    def test_normalized_from_title_when_empty_type(self):
        """Test inférence depuis le titre quand type vide."""
        report = DisclosureReport(
            report_id="345678",
            title="SSRF vulnerability via webhook",
            program="GitHub",
            link="hackerone.com/reports/345678",
            upvotes=100,
            bounty=2500.0,
            vuln_type=""
        )
        assert report.normalized_vuln_type == "ssrf"


# =============================================================================
# Tests HackerOneDisclosureIngestor
# =============================================================================

class TestHackerOneDisclosureIngestor:
    """Tests pour HackerOneDisclosureIngestor."""
    
    def test_initialization(self, ingestor, temp_data_dir):
        """Test initialisation de l'ingestor."""
        assert ingestor.name == "disclosures"
        assert ingestor.data_dir == temp_data_dir
        assert ingestor.min_upvotes == 0
        assert ingestor.enrich is False
    
    def test_init_with_min_upvotes(self, temp_data_dir):
        """Test avec min_upvotes."""
        config = IngestorConfig(
            name="disclosures",
            params={"data_dir": str(temp_data_dir), "min_upvotes": 50}
        )
        ingestor = HackerOneDisclosureIngestor(config)
        assert ingestor.min_upvotes == 50
    
    def test_init_with_vuln_types_filter(self, temp_data_dir):
        """Test avec filtre vuln_types."""
        config = IngestorConfig(
            name="disclosures",
            params={
                "data_dir": str(temp_data_dir),
                "vuln_types": ["xss", "sqli", "ssrf"]
            }
        )
        ingestor = HackerOneDisclosureIngestor(config)
        assert ingestor.vuln_types_filter == {"xss", "sqli", "ssrf"}


class TestHackerOneDisclosureIngestorSync:
    """Tests pour sync()."""
    
    @patch("ghost_hunter.core.rag.ingestors.disclosures.requests")
    def test_sync_success(self, mock_requests, ingestor, sample_csv_content):
        """Test sync réussie."""
        mock_response = Mock()
        mock_response.text = sample_csv_content
        mock_response.content = sample_csv_content.encode()
        mock_response.raise_for_status = Mock()
        mock_requests.get.return_value = mock_response
        
        ingestor.sync()
        
        assert ingestor.csv_path.exists()
        assert ingestor._last_sync is not None
    
    @patch("ghost_hunter.core.rag.ingestors.disclosures.requests")
    def test_sync_http_error(self, mock_requests, ingestor):
        """Test erreur HTTP."""
        mock_requests.get.side_effect = Exception("Connection error")
        
        with pytest.raises(SyncError):
            ingestor.sync()
    
    @patch("ghost_hunter.core.rag.ingestors.disclosures.requests", None)
    def test_sync_without_requests(self, temp_data_dir):
        """Test sans lib requests."""
        config = IngestorConfig(
            name="disclosures",
            params={"data_dir": str(temp_data_dir)}
        )
        ingestor = HackerOneDisclosureIngestor(config)
        
        with pytest.raises(SyncError, match="requests library not installed"):
            ingestor.sync()


class TestHackerOneDisclosureIngestorLoadReports:
    """Tests pour _load_reports()."""
    
    def test_load_reports_success(self, ingestor, sample_csv_content):
        """Test chargement réussi."""
        ingestor.csv_path.parent.mkdir(parents=True, exist_ok=True)
        ingestor.csv_path.write_text(sample_csv_content)
        
        reports = ingestor._load_reports()
        
        assert len(reports) == 6
        assert reports[0].title == "XSS in search field"
        assert reports[0].program == "Shopify"
    
    def test_load_reports_with_min_upvotes(self, temp_data_dir, sample_csv_content):
        """Test avec filtre min_upvotes."""
        config = IngestorConfig(
            name="disclosures",
            params={"data_dir": str(temp_data_dir), "min_upvotes": 100}
        )
        ingestor = HackerOneDisclosureIngestor(config)
        
        ingestor.csv_path.parent.mkdir(parents=True, exist_ok=True)
        ingestor.csv_path.write_text(sample_csv_content)
        
        reports = ingestor._load_reports()
        
        # Seuls ceux avec >=100 upvotes
        assert all(r.upvotes >= 100 for r in reports)
    
    def test_load_reports_with_vuln_filter(self, temp_data_dir, sample_csv_content):
        """Test avec filtre vuln_types."""
        config = IngestorConfig(
            name="disclosures",
            params={
                "data_dir": str(temp_data_dir),
                "vuln_types": ["xss"]
            }
        )
        ingestor = HackerOneDisclosureIngestor(config)
        
        ingestor.csv_path.parent.mkdir(parents=True, exist_ok=True)
        ingestor.csv_path.write_text(sample_csv_content)
        
        reports = ingestor._load_reports()
        
        # Seuls XSS reports
        assert all(r.normalized_vuln_type == "xss" for r in reports)
    
    def test_load_reports_with_max_reports(self, temp_data_dir, sample_csv_content):
        """Test avec limite max_reports."""
        config = IngestorConfig(
            name="disclosures",
            params={"data_dir": str(temp_data_dir), "max_reports": 2}
        )
        ingestor = HackerOneDisclosureIngestor(config)
        
        ingestor.csv_path.parent.mkdir(parents=True, exist_ok=True)
        ingestor.csv_path.write_text(sample_csv_content)
        
        reports = ingestor._load_reports()
        
        assert len(reports) == 2
    
    def test_load_reports_no_csv(self, ingestor):
        """Test sans fichier CSV."""
        reports = ingestor._load_reports()
        assert reports == []


class TestHackerOneDisclosureIngestorIngest:
    """Tests pour ingest()."""
    
    def test_ingest_generates_chunks(self, ingestor, sample_csv_content):
        """Test génération de chunks."""
        ingestor.csv_path.parent.mkdir(parents=True, exist_ok=True)
        ingestor.csv_path.write_text(sample_csv_content)
        
        chunks = list(ingestor.ingest())
        
        assert len(chunks) > 0
        
        # Vérifier structure du premier chunk
        chunk = chunks[0]
        assert chunk.id.startswith("h1_disclosure_")
        assert "XSS in search field" in chunk.text
        assert chunk.metadata["source"] == "h1_disclosure"
        assert chunk.metadata["vuln_type"] == "xss"
        assert chunk.metadata["program"] == "Shopify"
    
    def test_ingest_chunk_metadata(self, ingestor, sample_csv_content):
        """Test metadata des chunks."""
        ingestor.csv_path.parent.mkdir(parents=True, exist_ok=True)
        ingestor.csv_path.write_text(sample_csv_content)
        
        chunks = list(ingestor.ingest())
        chunk = chunks[0]
        
        assert "indexed_at" in chunk.metadata
        assert "report_id" in chunk.metadata
        assert "bounty" in chunk.metadata
        assert "upvotes" in chunk.metadata
        assert "link" in chunk.metadata


class TestHackerOneDisclosureIngestorCreateChunk:
    """Tests pour _create_chunk()."""
    
    def test_create_chunk_basic(self, ingestor):
        """Test création chunk basique."""
        report = DisclosureReport(
            report_id="123456",
            title="XSS in search",
            program="Shopify",
            link="hackerone.com/reports/123456",
            upvotes=100,
            bounty=1000.0,
            vuln_type="xss"
        )
        
        chunk = ingestor._create_chunk(report)
        
        assert chunk is not None
        assert chunk.id == "h1_disclosure_123456"
        assert "XSS in search" in chunk.text
        assert "$1,000" in chunk.text
        assert chunk.metadata["vuln_type"] == "xss"
    
    def test_create_chunk_with_summary(self, ingestor):
        """Test chunk avec summary."""
        report = DisclosureReport(
            report_id="234567",
            title="SQL Injection",
            program="Uber",
            link="hackerone.com/reports/234567",
            upvotes=200,
            bounty=5000.0,
            vuln_type="sqli",
            summary="The application is vulnerable to SQL injection..."
        )
        
        chunk = ingestor._create_chunk(report)
        
        assert "## Summary" in chunk.text
        assert "SQL injection" in chunk.text
    
    def test_create_chunk_empty_title(self, ingestor):
        """Test avec titre vide."""
        report = DisclosureReport(
            report_id="345678",
            title="",
            program="Test",
            link="hackerone.com/reports/345678",
            upvotes=10,
            bounty=0.0,
            vuln_type=""
        )
        
        chunk = ingestor._create_chunk(report)
        
        assert chunk is None


class TestHackerOneDisclosureIngestorGetStats:
    """Tests pour get_stats()."""
    
    def test_get_stats_empty(self, ingestor):
        """Test stats sans données."""
        stats = ingestor.get_stats()
        
        assert stats["chunks_count"] == 0
        assert stats["last_sync"] is None
        assert stats["size_bytes"] == 0
    
    def test_get_stats_with_data(self, ingestor, sample_csv_content):
        """Test stats avec données."""
        ingestor.csv_path.parent.mkdir(parents=True, exist_ok=True)
        ingestor.csv_path.write_text(sample_csv_content)
        ingestor._last_sync = datetime.now()
        
        stats = ingestor.get_stats()
        
        assert stats["chunks_count"] > 0
        assert stats["size_bytes"] > 0
        assert stats["last_sync"] is not None
        assert "vuln_type_distribution" in stats
        assert "top_programs" in stats


class TestHackerOneDisclosureIngestorEnrich:
    """Tests pour _enrich_report()."""
    
    def test_enrich_disabled(self, ingestor):
        """Test enrichissement désactivé."""
        report = DisclosureReport(
            report_id="123456",
            title="Test",
            program="Test",
            link="hackerone.com/reports/123456",
            upvotes=10,
            bounty=100.0,
            vuln_type="xss"
        )
        
        result = ingestor._enrich_report(report)
        
        # Pas de changement car enrich=False
        assert result.summary is None
    
    @patch("ghost_hunter.core.rag.ingestors.disclosures.requests")
    def test_enrich_enabled(self, mock_requests, temp_data_dir):
        """Test enrichissement activé."""
        config = IngestorConfig(
            name="disclosures",
            params={"data_dir": str(temp_data_dir), "enrich": True}
        )
        ingestor = HackerOneDisclosureIngestor(config)
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerability_information": "Detailed description...",
            "severity_rating": "high"
        }
        mock_requests.get.return_value = mock_response
        
        report = DisclosureReport(
            report_id="123456",
            title="Test",
            program="Test",
            link="hackerone.com/reports/123456",
            upvotes=10,
            bounty=100.0,
            vuln_type="xss"
        )
        
        result = ingestor._enrich_report(report)
        
        assert result.summary == "Detailed description..."
        assert result.severity == "high"
    
    @patch("ghost_hunter.core.rag.ingestors.disclosures.requests")
    def test_enrich_api_error(self, mock_requests, temp_data_dir):
        """Test erreur API enrichissement."""
        config = IngestorConfig(
            name="disclosures",
            params={"data_dir": str(temp_data_dir), "enrich": True}
        )
        ingestor = HackerOneDisclosureIngestor(config)
        
        mock_requests.get.side_effect = Exception("API Error")
        
        report = DisclosureReport(
            report_id="123456",
            title="Test",
            program="Test",
            link="hackerone.com/reports/123456",
            upvotes=10,
            bounty=100.0,
            vuln_type="xss"
        )
        
        # Ne doit pas lever d'exception
        result = ingestor._enrich_report(report)
        assert result.summary is None


# =============================================================================
# Tests Registry Integration
# =============================================================================

class TestRegistryIntegration:
    """Tests intégration avec le registry."""
    
    def test_ingestor_registered(self):
        """Test que l'ingestor est enregistré."""
        from ghost_hunter.core.rag.ingestors.registry import IngestorRegistry
        
        available = IngestorRegistry.list_available()
        assert "disclosures" in available


# =============================================================================
# Tests Mapping Coverage
# =============================================================================

class TestMappingCoverage:
    """Tests de couverture des mappings."""
    
    def test_all_h1_mappings_return_valid_type(self):
        """Test que tous les mappings H1 retournent un type valide."""
        valid_types = {
            "xss", "sqli", "ssrf", "xxe", "ssti", "idor", "lfi", "rce",
            "csrf", "auth_bypass", "open_redirect", "file_upload",
            "deserialization", "race_condition", "info_disclosure",
            "business_logic", "cache_poisoning", "cors", "clickjacking",
            "graphql", "api", "subdomain_takeover", "dos", "unknown"
        }
        
        for raw_type, normalized in H1_VULN_TYPE_MAPPING.items():
            assert normalized in valid_types, f"Invalid type: {normalized} for {raw_type}"
    
    def test_all_title_keywords_return_valid_type(self):
        """Test que tous les keywords titre retournent un type valide."""
        valid_types = {
            "xss", "sqli", "ssrf", "xxe", "ssti", "idor", "lfi", "rce",
            "csrf", "auth_bypass", "open_redirect", "file_upload",
            "race_condition", "info_disclosure", "cache_poisoning",
            "cors", "graphql", "subdomain_takeover", "unknown"
        }
        
        for keyword, vuln_type in TITLE_KEYWORDS_MAPPING.items():
            assert vuln_type in valid_types, f"Invalid type: {vuln_type} for {keyword}"

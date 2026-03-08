"""
Tests for Ghost-Hunter HackTricks Ingestor (Phase 2)
====================================================
Tests pour l'ingestor HackTricks.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tempfile
import shutil


class TestExtractVulnType:
    """Tests pour extract_vuln_type()."""
    
    def test_xss_detection(self):
        """Détecte XSS dans le path."""
        from ghost_hunter.core.rag.ingestors.hacktricks import extract_vuln_type
        
        assert extract_vuln_type(Path("pentesting-web/xss/README.md")) == "xss"
        assert extract_vuln_type(Path("pentesting-web/cross-site-scripting/dom.md")) == "xss"
        assert extract_vuln_type(Path("xss-attacks/reflected-xss.md")) == "xss"
    
    def test_sqli_detection(self):
        """Détecte SQLi dans le path."""
        from ghost_hunter.core.rag.ingestors.hacktricks import extract_vuln_type
        
        assert extract_vuln_type(Path("sql-injection/mysql.md")) == "sqli"
        assert extract_vuln_type(Path("pentesting-web/sqli/blind.md")) == "sqli"
        assert extract_vuln_type(Path("nosql-injection/mongodb.md")) == "sqli"
    
    def test_ssrf_detection(self):
        """Détecte SSRF dans le path."""
        from ghost_hunter.core.rag.ingestors.hacktricks import extract_vuln_type
        
        assert extract_vuln_type(Path("ssrf/cloud.md")) == "ssrf"
        assert extract_vuln_type(Path("server-side-request-forgery/aws.md")) == "ssrf"
    
    def test_ssti_detection(self):
        """Détecte SSTI dans le path."""
        from ghost_hunter.core.rag.ingestors.hacktricks import extract_vuln_type
        
        assert extract_vuln_type(Path("ssti/jinja2.md")) == "ssti"
        assert extract_vuln_type(Path("template-injection/freemarker.md")) == "ssti"
    
    def test_idor_detection(self):
        """Détecte IDOR dans le path."""
        from ghost_hunter.core.rag.ingestors.hacktricks import extract_vuln_type
        
        assert extract_vuln_type(Path("idor/api.md")) == "idor"
        assert extract_vuln_type(Path("bola/graphql.md")) == "idor"
    
    def test_rce_detection(self):
        """Détecte RCE dans le path."""
        from ghost_hunter.core.rag.ingestors.hacktricks import extract_vuln_type
        
        assert extract_vuln_type(Path("command-injection/linux.md")) == "rce"
        assert extract_vuln_type(Path("rce/nodejs.md")) == "rce"
    
    def test_lfi_detection(self):
        """Détecte LFI dans le path."""
        from ghost_hunter.core.rag.ingestors.hacktricks import extract_vuln_type
        
        assert extract_vuln_type(Path("file-inclusion/lfi.md")) == "lfi"
        assert extract_vuln_type(Path("path-traversal/windows.md")) == "lfi"
    
    def test_unknown_for_generic_path(self):
        """Retourne unknown pour les paths génériques."""
        from ghost_hunter.core.rag.ingestors.hacktricks import extract_vuln_type
        
        assert extract_vuln_type(Path("misc/random.md")) == "unknown"
        assert extract_vuln_type(Path("introduction/setup.md")) == "unknown"
    
    def test_auth_bypass_detection(self):
        """Détecte auth_bypass dans le path."""
        from ghost_hunter.core.rag.ingestors.hacktricks import extract_vuln_type
        
        assert extract_vuln_type(Path("authentication/bypass.md")) == "auth_bypass"
        assert extract_vuln_type(Path("jwt/attacks.md")) == "auth_bypass"
        assert extract_vuln_type(Path("oauth/vulnerabilities.md")) == "auth_bypass"


class TestShouldIgnore:
    """Tests pour should_ignore()."""
    
    def test_ignores_readme(self):
        """Ignore les README."""
        from ghost_hunter.core.rag.ingestors.hacktricks import should_ignore
        
        assert should_ignore(Path("README.md")) == True
        assert should_ignore(Path("some/dir/README.md")) == True
    
    def test_ignores_gitbook(self):
        """Ignore les fichiers .gitbook."""
        from ghost_hunter.core.rag.ingestors.hacktricks import should_ignore
        
        assert should_ignore(Path(".gitbook/assets/image.png")) == True
    
    def test_ignores_assets(self):
        """Ignore les dossiers assets."""
        from ghost_hunter.core.rag.ingestors.hacktricks import should_ignore
        
        assert should_ignore(Path("some/dir/assets/image.png")) == True
    
    def test_allows_normal_md(self):
        """Autorise les fichiers .md normaux."""
        from ghost_hunter.core.rag.ingestors.hacktricks import should_ignore
        
        assert should_ignore(Path("xss/dom-xss.md")) == False
        assert should_ignore(Path("pentesting-web/sqli/mysql.md")) == False


class TestHackTricksIngestor:
    """Tests pour HackTricksIngestor."""
    
    def test_ingestor_registration(self):
        """L'ingestor est enregistré dans le registry."""
        from ghost_hunter.core.rag.ingestors.registry import IngestorRegistry
        # Import pour trigger l'enregistrement
        from ghost_hunter.core.rag.ingestors import hacktricks
        
        assert "hacktricks" in IngestorRegistry.list_available()
    
    def test_ingestor_creation(self):
        """L'ingestor peut être créé."""
        from ghost_hunter.core.rag.ingestors.hacktricks import HackTricksIngestor
        from ghost_hunter.core.rag.ingestors.base import IngestorConfig
        
        config = IngestorConfig(name="hacktricks")
        ingestor = HackTricksIngestor(config)
        
        assert ingestor.name == "hacktricks"
        assert ingestor.source_type == "git"
    
    def test_ingestor_custom_dest(self):
        """L'ingestor accepte un chemin custom."""
        from ghost_hunter.core.rag.ingestors.hacktricks import HackTricksIngestor
        from ghost_hunter.core.rag.ingestors.base import IngestorConfig
        
        config = IngestorConfig(name="hacktricks")
        custom_path = Path("/tmp/test_hacktricks")
        ingestor = HackTricksIngestor(config, dest_path=custom_path)
        
        assert ingestor.dest_path == custom_path
    
    def test_get_stats(self):
        """get_stats() retourne les bonnes clés."""
        from ghost_hunter.core.rag.ingestors.hacktricks import HackTricksIngestor
        from ghost_hunter.core.rag.ingestors.base import IngestorConfig
        
        config = IngestorConfig(name="hacktricks")
        ingestor = HackTricksIngestor(config)
        
        stats = ingestor.get_stats()
        assert "source" in stats
        assert stats["source"] == "hacktricks"
        assert "chunks_count" in stats
        assert "size_mb" in stats


class TestHackTricksIngestorWithMockRepo:
    """Tests avec un repo mocké."""
    
    @pytest.fixture
    def mock_repo(self, tmp_path):
        """Crée un repo mocké avec quelques fichiers."""
        repo = tmp_path / "hacktricks"
        web = repo / "pentesting-web"
        
        # Créer la structure
        (web / "xss").mkdir(parents=True)
        (web / "sql-injection").mkdir(parents=True)
        (web / "ssrf").mkdir(parents=True)
        
        # Créer des fichiers
        (web / "xss" / "dom-xss.md").write_text("""
# DOM XSS

DOM-based Cross-Site Scripting (DOM XSS) is a type of XSS vulnerability where the 
attack payload is executed as a result of modifying the DOM environment in the 
victim's browser. This can happen when JavaScript takes data from an attacker-controllable 
source and passes it to a sink that supports dynamic code execution.

## Detecting DOM XSS

Look for sources like:
- document.URL
- document.location
- document.referrer
- window.name

And sinks like:
- eval()
- document.write()
- innerHTML

```javascript
// Vulnerable code example
var pos = document.URL.indexOf("name=") + 5;
document.write(document.URL.substring(pos, document.URL.length));
```
""")
        
        (web / "sql-injection" / "mysql.md").write_text("""
# MySQL Injection

MySQL SQL injection techniques and payloads for penetration testing.

## Basic Payloads

These are the most common payloads used for testing SQL injection vulnerabilities
in MySQL databases. Always start with simple tests before moving to more complex ones.

```sql
' OR 1=1 --
' OR '1'='1
' UNION SELECT NULL, NULL, NULL --
```

## Information Gathering

After confirming injection, extract database information:

```sql
' UNION SELECT version(), user(), database() --
```
""")
        
        (web / "ssrf" / "cloud.md").write_text("""
# Cloud SSRF

Server-Side Request Forgery attacks targeting cloud infrastructure metadata endpoints.
This is particularly dangerous in cloud environments like AWS, GCP, and Azure.

## AWS Metadata

The AWS Instance Metadata Service (IMDS) provides information about running instances.
Version 1 is particularly vulnerable to SSRF attacks.

```bash
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## GCP Metadata

Google Cloud Platform uses a different endpoint structure:

```bash
http://metadata.google.internal/computeMetadata/v1/
```
""")
        
        # README à ignorer
        (web / "README.md").write_text("# HackTricks Web")
        
        return repo
    
    def test_ingest_generates_chunks(self, mock_repo):
        """ingest() génère des chunks depuis le repo mocké."""
        from ghost_hunter.core.rag.ingestors.hacktricks import HackTricksIngestor
        from ghost_hunter.core.rag.ingestors.base import IngestorConfig
        
        config = IngestorConfig(name="hacktricks")
        ingestor = HackTricksIngestor(config, dest_path=mock_repo)
        
        chunks = list(ingestor.ingest())
        
        # On devrait avoir des chunks
        assert len(chunks) > 0
        
        # Vérifier les sources
        assert all(c.source == "hacktricks" for c in chunks)
    
    def test_ingest_extracts_vuln_types(self, mock_repo):
        """Les chunks ont le bon vuln_type."""
        from ghost_hunter.core.rag.ingestors.hacktricks import HackTricksIngestor
        from ghost_hunter.core.rag.ingestors.base import IngestorConfig
        
        config = IngestorConfig(name="hacktricks")
        ingestor = HackTricksIngestor(config, dest_path=mock_repo)
        
        chunks = list(ingestor.ingest())
        vuln_types = set(c.vuln_type for c in chunks)
        
        # On devrait avoir xss, sqli, ssrf
        assert "xss" in vuln_types
        assert "sqli" in vuln_types
        assert "ssrf" in vuln_types
    
    def test_ingest_ignores_readme(self, mock_repo):
        """README.md est ignoré."""
        from ghost_hunter.core.rag.ingestors.hacktricks import HackTricksIngestor
        from ghost_hunter.core.rag.ingestors.base import IngestorConfig
        
        config = IngestorConfig(name="hacktricks")
        ingestor = HackTricksIngestor(config, dest_path=mock_repo)
        
        chunks = list(ingestor.ingest())
        
        # Aucun chunk ne devrait venir de README
        readme_chunks = [c for c in chunks if "README" in c.metadata.get("file_path", "")]
        assert len(readme_chunks) == 0
    
    def test_ingest_has_url_metadata(self, mock_repo):
        """Les chunks ont une URL dans les metadata."""
        from ghost_hunter.core.rag.ingestors.hacktricks import HackTricksIngestor
        from ghost_hunter.core.rag.ingestors.base import IngestorConfig
        
        config = IngestorConfig(name="hacktricks")
        ingestor = HackTricksIngestor(config, dest_path=mock_repo)
        
        chunks = list(ingestor.ingest())
        
        # Vérifier qu'on a des URLs
        chunks_with_url = [c for c in chunks if "url" in c.metadata]
        assert len(chunks_with_url) > 0
        assert "hacktricks" in chunks_with_url[0].metadata["url"]
    
    def test_get_vuln_types_found(self, mock_repo):
        """get_vuln_types_found() compte correctement."""
        from ghost_hunter.core.rag.ingestors.hacktricks import HackTricksIngestor
        from ghost_hunter.core.rag.ingestors.base import IngestorConfig
        
        config = IngestorConfig(name="hacktricks")
        ingestor = HackTricksIngestor(config, dest_path=mock_repo)
        
        counts = ingestor.get_vuln_types_found()
        
        assert "xss" in counts
        assert "sqli" in counts
        assert "ssrf" in counts
        assert counts["xss"] >= 1


class TestPathVulnMapping:
    """Tests pour le mapping PATH_VULN_MAPPING."""
    
    def test_mapping_coverage(self):
        """Le mapping couvre les vulns principales."""
        from ghost_hunter.core.rag.ingestors.hacktricks import PATH_VULN_MAPPING
        
        # Vulns principales
        expected_vulns = {"xss", "sqli", "ssrf", "ssti", "idor", "rce", "lfi", "xxe", "csrf"}
        actual_vulns = set(PATH_VULN_MAPPING.values())
        
        for vuln in expected_vulns:
            assert vuln in actual_vulns, f"Missing vuln type: {vuln}"
    
    def test_mapping_no_duplicates_in_values(self):
        """Les valeurs sont normalisées."""
        from ghost_hunter.core.rag.ingestors.hacktricks import PATH_VULN_MAPPING
        
        # Toutes les valeurs doivent être lowercase et sans espaces
        for key, value in PATH_VULN_MAPPING.items():
            assert value == value.lower()
            assert " " not in value


class TestCloneHelpers:
    """Tests pour les helpers de clonage."""
    
    def test_clone_function_exists(self):
        """clone_hacktricks_sparse() existe."""
        from ghost_hunter.core.rag.ingestors.hacktricks import clone_hacktricks_sparse
        assert callable(clone_hacktricks_sparse)
    
    def test_ingest_function_exists(self):
        """ingest_hacktricks() existe."""
        from ghost_hunter.core.rag.ingestors.hacktricks import ingest_hacktricks
        assert callable(ingest_hacktricks)


class TestIngestorImports:
    """Tests d'imports."""
    
    def test_import_hacktricks_module(self):
        """Le module s'importe correctement."""
        from ghost_hunter.core.rag.ingestors import hacktricks
        assert hasattr(hacktricks, "HackTricksIngestor")
        assert hasattr(hacktricks, "extract_vuln_type")
    
    def test_import_from_registry(self):
        """L'ingestor peut être récupéré depuis le registry."""
        from ghost_hunter.core.rag.ingestors.registry import IngestorRegistry
        from ghost_hunter.core.rag.ingestors import hacktricks  # Trigger registration
        
        cls = IngestorRegistry.get("hacktricks")
        assert cls is not None
        assert cls.__name__ == "HackTricksIngestor"

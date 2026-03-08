"""
Tests pour l'ingestor de rapports personnels.

Teste:
- Parsing frontmatter YAML
- Validation des champs obligatoires
- Extraction des sections
- Poids 1.5x
- Création des chunks
"""

import pytest
from pathlib import Path
from datetime import datetime

from ghost_hunter.core.rag.ingestors.personal import (
    # Validation
    ReportValidationError,
    ReportFrontmatter,
    # Parsing
    parse_frontmatter,
    extract_sections,
    parse_report,
    validate_report,
    # Ingestor
    PersonalReportsIngestor,
    PERSONAL_REPORT_WEIGHT,
    # Helpers
    ingest_report,
    list_reports,
)
from ghost_hunter.core.rag.ingestors.registry import IngestorRegistry


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def valid_frontmatter_dict():
    """Frontmatter valide minimal."""
    return {
        "title": "IDOR in User API",
        "vuln_type": "idor",
        "target": "api.example.com",
        "date": "2025-01-07",
    }


@pytest.fixture
def full_frontmatter_dict():
    """Frontmatter avec tous les champs."""
    return {
        "title": "SQL Injection in Login",
        "vuln_type": "sqli",
        "target": "auth.example.com",
        "date": "2025-01-01",
        "severity": "critical",
        "bounty": "$1000",
        "platform": "hackerone",
        "status": "resolved",
        "tags": ["sql", "auth", "bypass"],
        "cwe": "CWE-89",
        "cvss": 9.8,
    }


@pytest.fixture
def valid_report_content():
    """Contenu complet d'un rapport valide."""
    return """---
title: "XSS in Search"
vuln_type: xss
target: "search.example.com"
date: "2025-01-07"
severity: medium
---

## Summary

Reflected XSS in the search parameter.

## PoC

```
https://search.example.com/?q=<script>alert(1)</script>
```

## Learnings

Always encode user input before reflection.
"""


@pytest.fixture
def mock_reports_dir(tmp_path):
    """Crée un dossier avec des rapports de test."""
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    
    # Rapport valide 1
    (reports_dir / "xss_report.md").write_text("""---
title: "XSS in Comments"
vuln_type: xss
target: "blog.example.com"
date: "2025-01-01"
severity: high
---

## Summary

Stored XSS in blog comments allows attackers to execute JavaScript.

## PoC

To reproduce this vulnerability, follow these steps:
1. Go to the blog post comments section
2. Submit a comment containing `<script>alert(document.cookie)</script>`
3. The script executes when any user views the page
4. Attacker can steal session cookies and hijack accounts
5. This affects all users visiting the blog

## Learnings

Always sanitize user-generated content before rendering in HTML.
""")
    
    # Rapport valide 2
    (reports_dir / "sqli_report.md").write_text("""---
title: "SQLi in Admin Panel"
vuln_type: sqli
target: "admin.example.com"
date: "2025-01-02"
severity: critical
bounty: "$5000"
---

## Summary

SQL injection in admin search.

## PoC

Input: `' OR 1=1--`
""")
    
    # Template (doit être ignoré)
    (reports_dir / "TEMPLATE.md").write_text("""---
title: "Template"
vuln_type: xss
target: "example.com"
date: "2025-01-01"
---
Template content.
""")
    
    # README (doit être ignoré)
    (reports_dir / "README.md").write_text("# Reports\nThis folder contains reports.")
    
    return reports_dir


# ============================================================================
# Tests: ReportFrontmatter
# ============================================================================

class TestReportFrontmatter:
    """Tests pour ReportFrontmatter."""
    
    def test_from_dict_minimal(self, valid_frontmatter_dict):
        fm = ReportFrontmatter.from_dict(valid_frontmatter_dict)
        assert fm.title == "IDOR in User API"
        assert fm.vuln_type == "idor"
        assert fm.target == "api.example.com"
        assert fm.severity == "medium"  # default
    
    def test_from_dict_full(self, full_frontmatter_dict):
        fm = ReportFrontmatter.from_dict(full_frontmatter_dict)
        assert fm.title == "SQL Injection in Login"
        assert fm.vuln_type == "sqli"
        assert fm.severity == "critical"
        assert fm.bounty == "$1000"
        assert fm.platform == "hackerone"
        assert "sql" in fm.tags
    
    def test_missing_title_raises(self):
        with pytest.raises(ReportValidationError) as exc:
            ReportFrontmatter.from_dict({
                "vuln_type": "xss",
                "target": "example.com",
                "date": "2025-01-01",
            })
        assert "title" in str(exc.value)
    
    def test_missing_vuln_type_raises(self):
        with pytest.raises(ReportValidationError) as exc:
            ReportFrontmatter.from_dict({
                "title": "Test",
                "target": "example.com",
                "date": "2025-01-01",
            })
        assert "vuln_type" in str(exc.value)
    
    def test_invalid_vuln_type_raises(self):
        with pytest.raises(ReportValidationError) as exc:
            ReportFrontmatter.from_dict({
                "title": "Test",
                "vuln_type": "invalid_type",
                "target": "example.com",
                "date": "2025-01-01",
            })
        assert "Invalid vuln_type" in str(exc.value)
    
    def test_invalid_severity_raises(self):
        with pytest.raises(ReportValidationError) as exc:
            ReportFrontmatter.from_dict({
                "title": "Test",
                "vuln_type": "xss",
                "target": "example.com",
                "date": "2025-01-01",
                "severity": "super_critical",
            })
        assert "Invalid severity" in str(exc.value)
    
    def test_vuln_type_case_insensitive(self):
        fm = ReportFrontmatter.from_dict({
            "title": "Test",
            "vuln_type": "XSS",
            "target": "example.com",
            "date": "2025-01-01",
        })
        assert fm.vuln_type == "xss"


# ============================================================================
# Tests: Parsing Functions
# ============================================================================

class TestParseFrontmatter:
    """Tests pour parse_frontmatter()."""
    
    def test_extracts_yaml(self):
        content = """---
title: Test
vuln_type: xss
---
Content here.
"""
        fm, remaining = parse_frontmatter(content)
        assert fm["title"] == "Test"
        assert fm["vuln_type"] == "xss"
        assert "Content here" in remaining
    
    def test_returns_none_if_no_frontmatter(self):
        content = "Just content, no frontmatter."
        fm, remaining = parse_frontmatter(content)
        assert fm is None
        assert remaining == content
    
    def test_invalid_yaml_raises(self):
        content = """---
title: [unclosed
---
Content.
"""
        with pytest.raises(ReportValidationError):
            parse_frontmatter(content)


class TestExtractSections:
    """Tests pour extract_sections()."""
    
    def test_extracts_sections(self):
        content = """
## Summary

This is the summary.

## PoC

This is the PoC.

## Learnings

These are learnings.
"""
        sections = extract_sections(content)
        assert "summary" in sections
        assert "poc" in sections
        assert "learnings" in sections
        assert "This is the summary" in sections["summary"]
    
    def test_handles_intro_without_header(self):
        content = """Some intro text.

## Summary

The summary.
"""
        sections = extract_sections(content)
        assert "intro" in sections
        assert "Some intro text" in sections["intro"]


class TestParseReport:
    """Tests pour parse_report()."""
    
    def test_parses_valid_report(self, tmp_path, valid_report_content):
        report_file = tmp_path / "report.md"
        report_file.write_text(valid_report_content)
        
        fm, sections = parse_report(report_file)
        
        assert fm.title == "XSS in Search"
        assert fm.vuln_type == "xss"
        assert "summary" in sections
        assert "poc" in sections
    
    def test_raises_if_file_not_found(self, tmp_path):
        with pytest.raises(ReportValidationError) as exc:
            parse_report(tmp_path / "nonexistent.md")
        assert "not found" in str(exc.value)
    
    def test_raises_if_not_markdown(self, tmp_path):
        txt_file = tmp_path / "report.txt"
        txt_file.write_text("content")
        
        with pytest.raises(ReportValidationError) as exc:
            parse_report(txt_file)
        assert "markdown" in str(exc.value).lower()


class TestValidateReport:
    """Tests pour validate_report()."""
    
    def test_returns_empty_for_valid(self, tmp_path, valid_report_content):
        report_file = tmp_path / "report.md"
        report_file.write_text(valid_report_content)
        
        errors = validate_report(report_file)
        # May have warnings but no errors
        assert not any("Error:" in e for e in errors)
    
    def test_returns_error_for_missing_frontmatter(self, tmp_path):
        report_file = tmp_path / "report.md"
        report_file.write_text("No frontmatter here.")
        
        errors = validate_report(report_file)
        assert any("Error:" in e for e in errors)


# ============================================================================
# Tests: PersonalReportsIngestor
# ============================================================================

class TestPersonalReportsIngestor:
    """Tests pour PersonalReportsIngestor."""
    
    def setup_method(self):
        """Ensure personal ingestor is registered (may be cleared by other tests)."""
        if "personal" not in IngestorRegistry._ingestors:
            IngestorRegistry.register("personal")(PersonalReportsIngestor)
    
    def test_ingestor_registration(self):
        """Ingestor doit être enregistré."""
        assert "personal" in IngestorRegistry.list_available()
    
    def test_ingestor_creation(self, mock_reports_dir):
        ingestor = PersonalReportsIngestor(reports_dir=mock_reports_dir)
        assert ingestor.source_type == "local"
        assert ingestor.weight == PERSONAL_REPORT_WEIGHT
    
    def test_ingest_generates_chunks(self, mock_reports_dir):
        ingestor = PersonalReportsIngestor(reports_dir=mock_reports_dir)
        chunks = list(ingestor.ingest())
        
        # 2 rapports valides, au moins 1 chunk chacun
        assert len(chunks) >= 2
    
    def test_chunks_have_weight(self, mock_reports_dir):
        ingestor = PersonalReportsIngestor(reports_dir=mock_reports_dir)
        chunks = list(ingestor.ingest())
        
        for chunk in chunks:
            assert chunk.metadata.get("weight", 1.0) >= PERSONAL_REPORT_WEIGHT
    
    def test_ignores_template(self, mock_reports_dir):
        ingestor = PersonalReportsIngestor(reports_dir=mock_reports_dir)
        chunks = list(ingestor.ingest())
        
        # Aucun chunk ne doit venir du template
        for chunk in chunks:
            assert "TEMPLATE" not in chunk.id
    
    def test_ignores_readme(self, mock_reports_dir):
        ingestor = PersonalReportsIngestor(reports_dir=mock_reports_dir)
        chunks = list(ingestor.ingest())
        
        for chunk in chunks:
            assert "README" not in chunk.id
    
    def test_stats_tracking(self, mock_reports_dir):
        ingestor = PersonalReportsIngestor(reports_dir=mock_reports_dir)
        list(ingestor.ingest())  # Consume generator
        
        stats = ingestor.get_stats()
        assert stats["files_found"] == 2  # Excludes TEMPLATE and README
        assert stats["files_valid"] == 2
        assert stats["chunks_created"] > 0
    
    def test_ingest_single(self, mock_reports_dir):
        ingestor = PersonalReportsIngestor(reports_dir=mock_reports_dir)
        report_file = mock_reports_dir / "xss_report.md"
        
        chunks = ingestor.ingest_single(report_file)
        
        assert len(chunks) >= 1
        assert chunks[0].metadata["vuln_type"] == "xss"


# ============================================================================
# Tests: Chunk Content
# ============================================================================

class TestChunkContent:
    """Tests pour le contenu des chunks générés."""
    
    def test_main_chunk_has_metadata(self, mock_reports_dir):
        ingestor = PersonalReportsIngestor(reports_dir=mock_reports_dir)
        chunks = list(ingestor.ingest())
        
        # Trouver un chunk principal
        main_chunks = [c for c in chunks if ":main" in c.id]
        assert len(main_chunks) > 0
        
        chunk = main_chunks[0]
        assert chunk.metadata["source"] == "personal"
        assert chunk.metadata["type"] == "report"
        assert "vuln_type" in chunk.metadata
        assert "target" in chunk.metadata
    
    def test_poc_chunk_extracted(self, mock_reports_dir):
        ingestor = PersonalReportsIngestor(reports_dir=mock_reports_dir)
        chunks = list(ingestor.ingest())
        
        poc_chunks = [c for c in chunks if ":poc" in c.id]
        # Au moins un rapport a un PoC
        assert len(poc_chunks) >= 1
    
    def test_learnings_chunk_has_extra_boost(self, mock_reports_dir):
        ingestor = PersonalReportsIngestor(reports_dir=mock_reports_dir)
        chunks = list(ingestor.ingest())
        
        learnings_chunks = [c for c in chunks if ":learnings" in c.id]
        for chunk in learnings_chunks:
            # Learnings ont 1.2x boost supplémentaire
            assert chunk.metadata["weight"] > PERSONAL_REPORT_WEIGHT


# ============================================================================
# Tests: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Tests pour les cas limites."""
    
    def test_empty_reports_dir(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        
        ingestor = PersonalReportsIngestor(reports_dir=empty_dir)
        chunks = list(ingestor.ingest())
        
        assert len(chunks) == 0
    
    def test_nonexistent_reports_dir(self, tmp_path):
        ingestor = PersonalReportsIngestor(reports_dir=tmp_path / "nonexistent")
        chunks = list(ingestor.ingest())
        
        assert len(chunks) == 0
    
    def test_report_with_minimal_content(self, tmp_path):
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        
        (reports_dir / "minimal.md").write_text("""---
title: Minimal
vuln_type: xss
target: test.com
date: "2025-01-01"
---
Just a line.
""")
        
        ingestor = PersonalReportsIngestor(reports_dir=reports_dir)
        chunks = list(ingestor.ingest())
        
        assert len(chunks) >= 1


# ============================================================================
# Tests: Helper Functions
# ============================================================================

class TestHelperFunctions:
    """Tests pour les fonctions helper."""
    
    def test_ingest_report_function(self, tmp_path, valid_report_content):
        report_file = tmp_path / "report.md"
        report_file.write_text(valid_report_content)
        
        chunks = ingest_report(report_file)
        assert len(chunks) >= 1
    
    def test_list_reports_function(self, mock_reports_dir):
        reports = list_reports(mock_reports_dir)
        
        # Should find 2 reports (exclude TEMPLATE and README)
        assert len(reports) == 2
        
        # Check filenames
        names = [r.name for r in reports]
        assert "xss_report.md" in names
        assert "sqli_report.md" in names
        assert "TEMPLATE.md" not in names


# ============================================================================
# Tests: Import Verification
# ============================================================================

class TestPersonalImports:
    """Tests de vérification des imports."""
    
    def setup_method(self):
        """Ensure personal ingestor is registered (may be cleared by other tests)."""
        if "personal" not in IngestorRegistry._ingestors:
            IngestorRegistry.register("personal")(PersonalReportsIngestor)
    
    def test_import_personal_module(self):
        from ghost_hunter.core.rag.ingestors import personal
        assert hasattr(personal, 'PersonalReportsIngestor')
        assert hasattr(personal, 'parse_report')
        assert hasattr(personal, 'ReportValidationError')
    
    def test_import_from_registry(self):
        ingestor_class = IngestorRegistry.get("personal")
        assert ingestor_class is PersonalReportsIngestor
    
    def test_weight_constant_exported(self):
        from ghost_hunter.core.rag.ingestors.personal import PERSONAL_REPORT_WEIGHT
        assert PERSONAL_REPORT_WEIGHT == 1.5

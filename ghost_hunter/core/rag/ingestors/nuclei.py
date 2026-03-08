"""
Ghost-Hunter Nuclei Templates Ingestor
======================================
Ingests Nuclei templates from the knowledge base.
"""

import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

import yaml

from .base import BaseIngestor, Chunk

logger = logging.getLogger(__name__)


class NucleiTemplatesIngestor(BaseIngestor):
    """
    Ingestor for Nuclei templates.
    
    Reads YAML templates from the nuclei-templates directory
    and creates searchable chunks.
    """
    
    source_type = "local"
    
    def __init__(self, knowledge_dir: Optional[Path] = None):
        """
        Initialize the ingestor.
        
        Args:
            knowledge_dir: Path to knowledge directory (default: knowledge/)
        """
        if knowledge_dir is None:
            knowledge_dir = Path(__file__).parent.parent.parent.parent.parent / "knowledge"
        
        self.knowledge_dir = knowledge_dir
        self.templates_dir = knowledge_dir / "nuclei-templates"
        self._stats = {"total": 0, "processed": 0, "errors": 0}
    
    def sync(self) -> None:
        """
        Sync is not needed for local files.
        Templates should be cloned with setup_knowledge.sh
        """
        if not self.templates_dir.exists():
            logger.warning(f"Nuclei templates not found at {self.templates_dir}")
            logger.warning("Run: ./knowledge/setup_knowledge.sh")
    
    def ingest(self) -> Generator[Chunk, None, None]:
        """
        Yield chunks from Nuclei templates.
        
        Each template becomes a chunk with:
        - Template metadata (id, name, severity, tags)
        - Request patterns and matchers
        """
        if not self.templates_dir.exists():
            logger.warning(f"Templates dir not found: {self.templates_dir}")
            return
        
        # Focus on most relevant directories for web vulns
        target_dirs = [
            "http/cves",
            "http/vulnerabilities", 
            "http/misconfiguration",
            "http/exposures",
            "http/takeovers",
            "http/default-logins",
            "http/fuzzing",
            "javascript/cves",
            "code",
        ]
        
        for target_dir in target_dirs:
            dir_path = self.templates_dir / target_dir
            if not dir_path.exists():
                continue
            
            for yaml_file in dir_path.rglob("*.yaml"):
                self._stats["total"] += 1
                
                try:
                    chunk = self._process_template(yaml_file)
                    if chunk:
                        self._stats["processed"] += 1
                        yield chunk
                except Exception as e:
                    self._stats["errors"] += 1
                    logger.debug(f"Error processing {yaml_file}: {e}")
    
    def _process_template(self, yaml_path: Path) -> Optional[Chunk]:
        """Process a single Nuclei template file."""
        try:
            with open(yaml_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError:
            return None
        
        if not data or not isinstance(data, dict):
            return None
        
        # Extract info section
        info = data.get("info", {})
        template_id = data.get("id", yaml_path.stem)
        name = info.get("name", template_id)
        severity = info.get("severity", "info")
        description = info.get("description", "")
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        
        # Determine vuln type from tags or path
        vuln_type = self._determine_vuln_type(tags, yaml_path, info)
        
        # Build content text
        content_parts = [
            f"# Nuclei Template: {name}",
            f"ID: {template_id}",
            f"Severity: {severity}",
            f"Tags: {', '.join(tags[:10]) if tags else 'none'}",
        ]
        
        if description:
            content_parts.append(f"\n## Description\n{description}")
        
        # Add request patterns (useful for understanding attack vectors)
        requests = data.get("http", data.get("requests", []))
        if requests and isinstance(requests, list):
            content_parts.append("\n## HTTP Requests")
            for i, req in enumerate(requests[:3], 1):
                if isinstance(req, dict):
                    method = req.get("method", "GET")
                    path = req.get("path", [])
                    if isinstance(path, list):
                        path = path[0] if path else "/"
                    raw = req.get("raw", [])
                    
                    content_parts.append(f"\n### Request {i}")
                    content_parts.append(f"Method: {method}")
                    if path:
                        content_parts.append(f"Path: {path}")
                    if raw and isinstance(raw, list):
                        content_parts.append(f"Raw:\n```\n{raw[0][:500]}\n```")
        
        # Add matchers (useful for detection patterns)
        for req in requests[:1] if isinstance(requests, list) else []:
            if isinstance(req, dict):
                matchers = req.get("matchers", [])
                if matchers:
                    content_parts.append("\n## Detection Matchers")
                    for matcher in matchers[:5]:
                        if isinstance(matcher, dict):
                            mtype = matcher.get("type", "unknown")
                            words = matcher.get("words", [])
                            regex = matcher.get("regex", [])
                            status = matcher.get("status", [])
                            
                            if words:
                                content_parts.append(f"- Words ({mtype}): {', '.join(str(w) for w in words[:5])}")
                            if regex:
                                content_parts.append(f"- Regex: {regex[0][:100] if regex else ''}")
                            if status:
                                content_parts.append(f"- Status: {status}")
        
        content = "\n".join(content_parts)
        
        # Create chunk ID
        chunk_id = hashlib.md5(f"nuclei_{template_id}".encode()).hexdigest()[:16]
        
        return Chunk(
            id=chunk_id,
            text=content,
            metadata={
                "source": f"nuclei_{yaml_path.parent.name}",
                "type": "nuclei_template",
                "vuln_type": vuln_type,
                "indexed_at": datetime.now().isoformat(),
                "template_id": template_id,
                "severity": severity,
                "tags": tags[:10] if tags else [],
                "file_path": str(yaml_path.relative_to(self.templates_dir))
            }
        )
    
    def _determine_vuln_type(self, tags: list, path: Path, info: dict) -> str:
        """Determine vulnerability type from tags and path."""
        path_str = str(path).lower()
        tags_lower = [t.lower() for t in tags]
        
        # Priority mapping
        vuln_mappings = [
            (["sqli", "sql-injection"], "sqli"),
            (["xss", "cross-site-scripting"], "xss"),
            (["ssrf"], "ssrf"),
            (["rce", "remote-code-execution"], "rce"),
            (["lfi", "local-file-inclusion", "file-inclusion"], "lfi"),
            (["rfi", "remote-file-inclusion"], "rfi"),
            (["xxe", "xml-external-entity"], "xxe"),
            (["ssti", "template-injection"], "ssti"),
            (["idor", "insecure-direct-object"], "idor"),
            (["csrf", "cross-site-request-forgery"], "csrf"),
            (["auth-bypass", "authentication-bypass"], "auth_bypass"),
            (["injection"], "injection"),
            (["cve"], "cve"),
            (["takeover", "subdomain-takeover"], "takeover"),
            (["exposure", "information-disclosure"], "info_disclosure"),
            (["misconfiguration", "misconfig"], "misconfiguration"),
            (["default-login", "default-credentials"], "default_creds"),
        ]
        
        for keywords, vuln_type in vuln_mappings:
            for kw in keywords:
                if kw in tags_lower or kw in path_str:
                    return vuln_type
        
        # Fallback based on directory
        if "cves" in path_str:
            return "cve"
        if "vulnerabilities" in path_str:
            return "vulnerability"
        if "misconfiguration" in path_str:
            return "misconfiguration"
        if "exposures" in path_str:
            return "info_disclosure"
        
        return "other"
    
    def get_stats(self) -> dict:
        """Return ingestion statistics."""
        return self._stats.copy()

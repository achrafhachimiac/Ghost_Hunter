#!/usr/bin/env python3
"""
Complete RAG ingestion - adds all missing sources.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from datetime import datetime
from ghost_hunter.core.rag.vector_store import VectorStoreManager
from ghost_hunter.core.rag.contracts import Chunk
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
KNOWLEDGE_DIR = ROOT_DIR / 'knowledge'
EVASION_DIR = ROOT_DIR / 'ghost_hunter' / 'core' / 'evasion' / 'data'


def guess_vuln_type(text: str) -> str:
    """Guess vulnerability type from text."""
    text = text.lower()
    mapping = {
        'sql': 'sqli', 'sqli': 'sqli', 'mysql': 'sqli', 'postgres': 'sqli', 'oracle': 'sqli',
        'xss': 'xss', 'cross-site-scripting': 'xss', 'script': 'xss',
        'ssrf': 'ssrf', 'server-side-request': 'ssrf',
        'xxe': 'xxe', 'xml': 'xxe',
        'ssti': 'ssti', 'template': 'ssti', 'jinja': 'ssti', 'twig': 'ssti',
        'idor': 'idor', 'bola': 'idor', 'insecure-direct': 'idor',
        'lfi': 'lfi', 'rfi': 'lfi', 'file-inclusion': 'lfi', 'path-traversal': 'lfi', 'traversal': 'lfi',
        'rce': 'cmdi', 'command': 'cmdi', 'cmdi': 'cmdi', 'exec': 'cmdi', 'shell': 'cmdi',
        'deserialization': 'deserialization', 'pickle': 'deserialization', 'unserialize': 'deserialization',
        'auth': 'authentication', 'jwt': 'authentication', 'oauth': 'authentication', 'session': 'authentication', 'login': 'authentication',
        'cors': 'cors', 'csrf': 'csrf', 'clickjack': 'clickjacking',
        'upload': 'file_upload', 'api': 'api', 'graphql': 'graphql', 'websocket': 'websocket',
        'redirect': 'open_redirect', 'race': 'race_condition', 'cache': 'cache_poisoning',
        'crlf': 'crlf', 'header': 'crlf', 'smuggl': 'http_smuggling',
    }
    for pattern, vuln in mapping.items():
        if pattern in text:
            return vuln
    return 'general'


def ingest_waf_patterns_full(store: VectorStoreManager) -> int:
    """Ingest ALL WAF evasion patterns (5961 patterns)."""
    patterns_file = EVASION_DIR / 'waf_patterns.yaml'
    if not patterns_file.exists():
        print("  ⚠️ WAF patterns file not found")
        return 0
    
    print("  Loading WAF patterns...")
    with open(patterns_file) as f:
        data = yaml.safe_load(f)
    
    patterns = data.get('patterns', [])
    print(f"  Found {len(patterns)} patterns")
    
    # Group by vuln_type for better chunks
    by_vuln = {}
    for p in patterns:
        vtype = p.get('vuln_type', 'general')
        if vtype not in by_vuln:
            by_vuln[vtype] = []
        by_vuln[vtype].append(p)
    
    chunks = []
    for vtype, vpatterns in by_vuln.items():
        # Create multiple chunks per vuln type (max 50 patterns per chunk)
        for i in range(0, len(vpatterns), 50):
            batch = vpatterns[i:i+50]
            
            # Format patterns
            pattern_lines = []
            for p in batch:
                pattern_lines.append(f"- `{p.get('pattern', '')[:80]}` (severity: {p.get('severity', 'medium')})")
            
            content = f"""# F5 WAF Detection Patterns - {vtype.upper()} (Part {i//50 + 1})

These patterns are blocked by F5 BigIP ASM WAF. Avoid or transform payloads matching these:

{chr(10).join(pattern_lines)}

## Evasion Tips for {vtype.upper()}
When testing {vtype}, if your payload matches these patterns, apply transforms:
- URL encoding (single/double)
- Case variation
- Comment insertion
- Alternative syntax
"""
            chunk = Chunk(
                id=f"waf_patterns_{vtype}_{i//50}",
                text=content,
                metadata={
                    'source': 'waf_patterns',
                    'type': 'waf_detection',
                    'vuln_type': vtype,
                    'pattern_count': len(batch),
                    'indexed_at': datetime.now().isoformat()
                }
            )
            chunks.append(chunk)
    
    if chunks:
        # Batch upsert
        batch_size = 50
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i+batch_size]
            store.upsert(batch)
            print(f"    WAF patterns: {min(i+batch_size, len(chunks))}/{len(chunks)}", end='\r')
        print()
    
    return len(chunks)


def ingest_nuclei_templates(store: VectorStoreManager) -> int:
    """Ingest Nuclei templates."""
    nuclei_dir = KNOWLEDGE_DIR / 'nuclei-templates'
    if not nuclei_dir.exists():
        print("  ⚠️ Nuclei templates not found")
        return 0
    
    yaml_files = list(nuclei_dir.rglob('*.yaml'))
    print(f"  Found {len(yaml_files)} template files")
    
    chunks = []
    for i, yaml_file in enumerate(yaml_files):
        try:
            content = yaml_file.read_text(errors='ignore')
            if len(content) < 50:
                continue
            
            # Parse YAML for metadata
            try:
                data = yaml.safe_load(content)
                if not isinstance(data, dict):
                    continue
                
                info = data.get('info', {})
                name = info.get('name', yaml_file.stem)
                severity = info.get('severity', 'unknown')
                tags = info.get('tags', [])
                if isinstance(tags, str):
                    tags = tags.split(',')
                
                # Guess vuln type from tags
                vuln_type = 'general'
                for tag in tags:
                    vt = guess_vuln_type(tag)
                    if vt != 'general':
                        vuln_type = vt
                        break
                
                # Create chunk
                chunk_text = f"""# Nuclei Template: {name}

**Severity:** {severity}
**Tags:** {', '.join(tags[:10]) if tags else 'none'}

```yaml
{content[:3000]}
```
"""
                chunk = Chunk(
                    id=f"nuclei_{yaml_file.stem}_{i}",
                    text=chunk_text,
                    metadata={
                        'source': f'nuclei/{yaml_file.parent.name}/{yaml_file.name}',
                        'type': 'nuclei_template',
                        'vuln_type': vuln_type,
                        'severity': severity,
                        'indexed_at': datetime.now().isoformat()
                    }
                )
                chunks.append(chunk)
                
            except yaml.YAMLError:
                continue
                
        except Exception as e:
            continue
        
        if i % 100 == 0:
            print(f"    Processing: {i}/{len(yaml_files)}", end='\r')
    
    print()
    
    if chunks:
        batch_size = 50
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i+batch_size]
            store.upsert(batch)
            print(f"    Nuclei: {min(i+batch_size, len(chunks))}/{len(chunks)}", end='\r')
        print()
    
    return len(chunks)


def ingest_cheatsheets(store: VectorStoreManager) -> int:
    """Ingest cheatsheets (PayloadsAllTheThings style)."""
    cs_dir = KNOWLEDGE_DIR / 'cheatsheets'
    if not cs_dir.exists():
        print("  ⚠️ Cheatsheets not found")
        return 0
    
    md_files = list(cs_dir.rglob('*.md'))
    print(f"  Found {len(md_files)} cheatsheet files")
    
    chunks = []
    seen_ids = set()
    
    for i, md_file in enumerate(md_files):
        # Skip common non-content files
        if md_file.name in ['README.md', 'CONTRIBUTING.md', 'SUMMARY.md', '_sidebar.md']:
            continue
        
        try:
            content = md_file.read_text(errors='ignore')
            if len(content) < 100:
                continue
            
            # Truncate very long files
            if len(content) > 8000:
                content = content[:8000] + "\n\n... (truncated)"
            
            vuln_type = guess_vuln_type(md_file.stem + ' ' + str(md_file.parent))
            
            # Generate unique ID
            base_id = f"cheatsheet_{md_file.stem}"
            chunk_id = base_id
            counter = 0
            while chunk_id in seen_ids:
                counter += 1
                chunk_id = f"{base_id}_{counter}"
            seen_ids.add(chunk_id)
            
            chunk = Chunk(
                id=chunk_id,
                text=content,
                metadata={
                    'source': f'cheatsheets/{md_file.relative_to(cs_dir)}',
                    'type': 'cheatsheet',
                    'vuln_type': vuln_type,
                    'indexed_at': datetime.now().isoformat()
                }
            )
            chunks.append(chunk)
            
        except Exception as e:
            continue
    
    if chunks:
        batch_size = 50
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i+batch_size]
            store.upsert(batch)
            print(f"    Cheatsheets: {min(i+batch_size, len(chunks))}/{len(chunks)}", end='\r')
        print()
    
    return len(chunks)


def ingest_payloads(store: VectorStoreManager) -> int:
    """Ingest payload collections."""
    payloads_dir = KNOWLEDGE_DIR / 'payloads'
    if not payloads_dir.exists():
        print("  ⚠️ Payloads not found")
        return 0
    
    chunks = []
    
    # Find all payload files (txt, lst, etc.)
    payload_files = list(payloads_dir.rglob('*.txt')) + list(payloads_dir.rglob('*.lst'))
    print(f"  Found {len(payload_files)} payload files")
    
    for pf in payload_files:
        try:
            content = pf.read_text(errors='ignore')
            if not content.strip():
                continue
            
            payloads = content.strip().split('\n')
            
            # Take sample of payloads (max 200 per file)
            if len(payloads) > 200:
                payloads = payloads[:100] + ['...'] + payloads[-100:]
            
            vuln_type = guess_vuln_type(str(pf))
            
            chunk_text = f"""# Payloads: {pf.stem}

Category: {pf.parent.name}
Total payloads: {len(content.strip().split(chr(10)))}

```
{chr(10).join(payloads[:200])}
```
"""
            chunk = Chunk(
                id=f"payload_{pf.parent.name}_{pf.stem}",
                text=chunk_text,
                metadata={
                    'source': f'payloads/{pf.relative_to(payloads_dir)}',
                    'type': 'payload',
                    'vuln_type': vuln_type,
                    'payload_count': len(content.strip().split('\n')),
                    'indexed_at': datetime.now().isoformat()
                }
            )
            chunks.append(chunk)
            
        except Exception:
            continue
    
    if chunks:
        store.upsert(chunks)
    
    return len(chunks)


def main():
    print("=" * 60)
    print("👻 Ghost-Hunter Complete RAG Ingestion")
    print("=" * 60)
    print()
    
    store = VectorStoreManager()
    initial_count = store.count()
    print(f"Current chunks in store: {initial_count}")
    print()
    
    # 1. WAF Patterns (full)
    print("🛡️  [1/4] Ingesting WAF Evasion Patterns (full)...")
    waf_count = ingest_waf_patterns_full(store)
    print(f"  ✅ Added {waf_count} WAF chunks")
    
    # 2. Nuclei Templates
    print("\n🔬 [2/4] Ingesting Nuclei Templates...")
    nuclei_count = ingest_nuclei_templates(store)
    print(f"  ✅ Added {nuclei_count} Nuclei chunks")
    
    # 3. Cheatsheets
    print("\n📝 [3/4] Ingesting Cheatsheets...")
    cs_count = ingest_cheatsheets(store)
    print(f"  ✅ Added {cs_count} cheatsheet chunks")
    
    # 4. Payloads
    print("\n💉 [4/4] Ingesting Payloads...")
    payload_count = ingest_payloads(store)
    print(f"  ✅ Added {payload_count} payload chunks")
    
    # Summary
    final_count = store.count()
    print()
    print("=" * 60)
    print("✅ RAG Ingestion Complete!")
    print("=" * 60)
    print(f"""
📊 Summary:
   Initial:     {initial_count} chunks
   WAF:        +{waf_count} chunks
   Nuclei:     +{nuclei_count} chunks  
   Cheatsheets:+{cs_count} chunks
   Payloads:   +{payload_count} chunks
   ─────────────────────
   TOTAL:       {final_count} chunks
""")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Full RAG ingestion script.
Ingests all available knowledge sources into the vector store.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from datetime import datetime
from ghost_hunter.core.rag.vector_store import VectorStoreManager
from ghost_hunter.core.rag.contracts import Chunk
from ghost_hunter.core.rag.ingestors.base import IngestorConfig

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / 'knowledge'


def ingest_hacktricks(store: VectorStoreManager) -> int:
    """Ingest HackTricks markdown files."""
    hacktricks_dir = KNOWLEDGE_DIR / 'hacktricks'
    if not hacktricks_dir.exists():
        print("  ⚠️ HackTricks not found, skipping")
        return 0
    
    md_files = list(hacktricks_dir.rglob('*.md'))
    print(f"  Found {len(md_files)} markdown files")
    
    chunks = []
    for i, md_file in enumerate(md_files):
        # Skip non-relevant files
        rel_path = md_file.relative_to(hacktricks_dir)
        if any(skip in str(rel_path) for skip in ['README.md', 'SUMMARY.md', '.gitbook', '_sidebar']):
            continue
        
        try:
            content = md_file.read_text(errors='ignore')
            if len(content) < 100:  # Skip tiny files
                continue
            
            # Truncate very long files
            if len(content) > 10000:
                content = content[:10000] + "\n... (truncated)"
            
            # Guess vuln type from path
            vuln_type = guess_vuln_type(str(rel_path))
            
            chunk = Chunk(
                id=f"hacktricks_{rel_path.stem}_{i}",
                text=content,
                metadata={
                    'source': f'hacktricks/{rel_path}',
                    'type': 'technique',
                    'vuln_type': vuln_type,
                    'indexed_at': datetime.now().isoformat()
                }
            )
            chunks.append(chunk)
            
        except Exception as e:
            print(f"    Error reading {md_file}: {e}")
    
    if chunks:
        # Batch upsert
        batch_size = 50
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i+batch_size]
            store.upsert(batch)
            print(f"    Upserted {min(i+batch_size, len(chunks))}/{len(chunks)}", end='\r')
        print()
    
    return len(chunks)


def ingest_payloads(store: VectorStoreManager) -> int:
    """Ingest payload files."""
    payloads_dir = KNOWLEDGE_DIR / 'payloads'
    if not payloads_dir.exists():
        print("  ⚠️ Payloads not found, skipping")
        return 0
    
    chunks = []
    for subdir in payloads_dir.iterdir():
        if not subdir.is_dir():
            continue
        
        vuln_type = guess_vuln_type(subdir.name)
        
        # Read payload files in this category
        for payload_file in subdir.glob('*.txt'):
            try:
                content = payload_file.read_text(errors='ignore')
                if not content.strip():
                    continue
                
                # Take first N payloads
                payloads = content.strip().split('\n')[:100]
                
                chunk = Chunk(
                    id=f"payload_{subdir.name}_{payload_file.stem}",
                    text=f"# {subdir.name.upper()} Payloads\n\n```\n" + '\n'.join(payloads) + "\n```",
                    metadata={
                        'source': f'payloads/{subdir.name}/{payload_file.name}',
                        'type': 'payload',
                        'vuln_type': vuln_type,
                        'indexed_at': datetime.now().isoformat()
                    }
                )
                chunks.append(chunk)
            except Exception as e:
                print(f"    Error: {e}")
    
    if chunks:
        store.upsert(chunks)
    
    return len(chunks)


def ingest_cheatsheets(store: VectorStoreManager) -> int:
    """Ingest cheatsheets."""
    cheatsheets_dir = KNOWLEDGE_DIR / 'cheatsheets'
    if not cheatsheets_dir.exists():
        print("  ⚠️ Cheatsheets not found, skipping")
        return 0
    
    chunks = []
    for md_file in cheatsheets_dir.rglob('*.md'):
        try:
            content = md_file.read_text(errors='ignore')
            if len(content) < 100:
                continue
            
            if len(content) > 8000:
                content = content[:8000] + "\n... (truncated)"
            
            vuln_type = guess_vuln_type(md_file.stem)
            
            chunk = Chunk(
                id=f"cheatsheet_{md_file.stem}",
                text=content,
                metadata={
                    'source': f'cheatsheets/{md_file.name}',
                    'type': 'cheatsheet',
                    'vuln_type': vuln_type,
                    'indexed_at': datetime.now().isoformat()
                }
            )
            chunks.append(chunk)
        except Exception as e:
            print(f"    Error: {e}")
    
    if chunks:
        store.upsert(chunks)
    
    return len(chunks)


def guess_vuln_type(text: str) -> str:
    """Guess vulnerability type from filename/path."""
    text = text.lower()
    
    mapping = {
        'sql': 'sqli',
        'sqli': 'sqli',
        'xss': 'xss',
        'cross-site': 'xss',
        'ssrf': 'ssrf',
        'xxe': 'xxe',
        'ssti': 'ssti',
        'template': 'ssti',
        'idor': 'idor',
        'lfi': 'lfi',
        'rfi': 'lfi',
        'file-inclusion': 'lfi',
        'path-traversal': 'lfi',
        'rce': 'cmdi',
        'command': 'cmdi',
        'cmdi': 'cmdi',
        'injection': 'injection',
        'auth': 'authentication',
        'jwt': 'authentication',
        'oauth': 'authentication',
        'session': 'authentication',
        'cors': 'cors',
        'csrf': 'csrf',
        'deserialization': 'deserialization',
        'upload': 'file_upload',
        'api': 'api',
        'graphql': 'graphql',
        'websocket': 'websocket',
    }
    
    for pattern, vuln in mapping.items():
        if pattern in text:
            return vuln
    
    return 'general'


def main():
    print("=" * 60)
    print("👻 Ghost-Hunter Full RAG Ingestion")
    print("=" * 60)
    print()
    
    store = VectorStoreManager()
    initial_count = store.count()
    print(f"Initial chunks in store: {initial_count}")
    print()
    
    # 1. HackTricks
    print("📚 [1/3] Ingesting HackTricks...")
    ht_count = ingest_hacktricks(store)
    print(f"  ✅ Added {ht_count} chunks")
    
    # 2. Payloads
    print("\n💉 [2/3] Ingesting Payloads...")
    payload_count = ingest_payloads(store)
    print(f"  ✅ Added {payload_count} chunks")
    
    # 3. Cheatsheets
    print("\n📝 [3/3] Ingesting Cheatsheets...")
    cs_count = ingest_cheatsheets(store)
    print(f"  ✅ Added {cs_count} chunks")
    
    # Summary
    final_count = store.count()
    print()
    print("=" * 60)
    print(f"✅ RAG Ingestion Complete!")
    print(f"   Total chunks: {final_count}")
    print(f"   Added: {final_count - initial_count}")
    print("=" * 60)


if __name__ == '__main__':
    main()

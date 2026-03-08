#!/usr/bin/env python3
"""Quick ingestion script for RAG."""
from ghost_hunter.core.rag.vector_store import VectorStoreManager
from ghost_hunter.core.rag.contracts import Chunk
import yaml
from pathlib import Path
from datetime import datetime

def main():
    store = VectorStoreManager()
    chunks = []

    # Ingest patterns
    pattern_dir = Path('knowledge/patterns')
    for f in pattern_dir.glob('*.yaml'):
        print(f'Loading {f.name}...')
        with open(f) as fp:
            data = yaml.safe_load(fp)
            vuln_type = f.stem
            for i, pattern in enumerate(data.get('patterns', [])):
                chunk = Chunk(
                    id=f'pattern_{f.stem}_{i}',
                    text=str(pattern),
                    metadata={
                        'source': f'patterns/{f.name}',
                        'type': 'technique',
                        'vuln_type': vuln_type,
                        'indexed_at': datetime.now().isoformat()
                    }
                )
                chunks.append(chunk)

    print(f'Upserting {len(chunks)} chunks...')
    store.upsert(chunks)
    print(f'Store count: {store.count()}')
    print('✅ Ingestion done!')

if __name__ == '__main__':
    main()

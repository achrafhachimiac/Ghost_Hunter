#!/usr/bin/env python3
"""
Ingest HackerOne Reports from GitHub repo into RAG
Source: https://github.com/reddelexc/hackerone-reports

This script ingests:
1. The CSV with 14,350+ reports (structured data)
2. The TOP files by bug type (curated best examples)
"""

import sys
import csv
import hashlib
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from ghost_hunter.core.rag.vector_store import VectorStoreManager
from ghost_hunter.core.rag.contracts import Chunk

REPORTS_DIR = Path(__file__).parent.parent / "knowledge" / "bug-bounty-reports"


def make_chunk(content: str, metadata: dict) -> Chunk:
    """Create a Chunk with auto-generated ID and required fields"""
    chunk_id = hashlib.md5(content[:500].encode()).hexdigest()[:16]
    metadata["indexed_at"] = datetime.now().isoformat()
    return Chunk(id=chunk_id, text=content, metadata=metadata)


def ingest_csv_reports(store: VectorStoreManager) -> int:
    """Ingest reports from data.csv - grouped by vulnerability type"""
    csv_path = REPORTS_DIR / "data.csv"
    if not csv_path.exists():
        print(f"CSV not found: {csv_path}")
        return 0
    
    # Group reports by vulnerability type
    vuln_groups: dict[str, list[dict]] = {}
    
    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            vuln_type = row.get('vuln_type', 'Unknown').strip()
            if vuln_type and vuln_type != 'Unknown':
                if vuln_type not in vuln_groups:
                    vuln_groups[vuln_type] = []
                vuln_groups[vuln_type].append(row)
    
    print(f"Found {len(vuln_groups)} vulnerability types")
    
    chunks_added = 0
    
    for vuln_type, reports in vuln_groups.items():
        # Sort by bounty (highest first) then by upvotes
        reports.sort(key=lambda x: (
            float(x.get('bounty', 0) or 0),
            int(x.get('upvotes', 0) or 0)
        ), reverse=True)
        
        # Take top 50 reports per vuln type (most valuable)
        top_reports = reports[:50]
        
        # Create chunk content
        content_lines = [
            f"# HackerOne Reports: {vuln_type}",
            f"Total reports: {len(reports)} | Top {len(top_reports)} shown",
            "",
            "## Real-World Examples",
            ""
        ]
        
        for i, report in enumerate(top_reports, 1):
            title = report.get('title', 'No title')
            program = report.get('program', 'Unknown')
            link = report.get('link', '')
            upvotes = report.get('upvotes', 0)
            bounty = report.get('bounty', 0)
            
            # Format bounty
            try:
                bounty_val = float(bounty) if bounty else 0
                bounty_str = f"${bounty_val:,.0f}" if bounty_val > 0 else "N/A"
            except:
                bounty_str = "N/A"
            
            content_lines.append(f"{i}. **{title}**")
            content_lines.append(f"   - Program: {program}")
            content_lines.append(f"   - Bounty: {bounty_str} | Upvotes: {upvotes}")
            content_lines.append(f"   - Link: https://{link}")
            content_lines.append("")
        
        content = "\n".join(content_lines)
        
        # Add to vector store using upsert with Chunk
        chunk = make_chunk(content, {
            "source": f"hackerone_reports_{vuln_type.lower().replace(' ', '_')}",
            "type": "h1_reports",
            "vuln_type": vuln_type,
            "report_count": len(reports),
            "top_count": len(top_reports)
        })
        store.upsert([chunk])
        chunks_added += 1
        print(f"  ✓ {vuln_type}: {len(reports)} reports")
    
    return chunks_added


def ingest_top_files(store: VectorStoreManager) -> int:
    """Ingest the curated TOP*.md files by bug type"""
    tops_dir = REPORTS_DIR / "tops_by_bug_type"
    if not tops_dir.exists():
        print(f"Tops dir not found: {tops_dir}")
        return 0
    
    chunks_added = 0
    
    for md_file in tops_dir.glob("TOP*.md"):
        vuln_type = md_file.stem.replace("TOP", "").lower()
        
        content = md_file.read_text(encoding='utf-8', errors='ignore')
        
        # Parse the markdown to extract key info
        lines = content.strip().split('\n')
        
        # Add context header
        enhanced_content = f"""# Top HackerOne Reports: {vuln_type.upper()}

These are the most upvoted and valuable {vuln_type} vulnerability reports from HackerOne.
Use these as reference for:
- Attack patterns and techniques
- Vulnerable code patterns
- Proof of concept examples
- Impact descriptions

---

{content}
"""
        
        chunk = make_chunk(enhanced_content, {
            "source": f"h1_top_{vuln_type}",
            "type": "h1_top_reports",
            "vuln_type": vuln_type,
            "curated": True
        })
        store.upsert([chunk])
        chunks_added += 1
        print(f"  ✓ TOP {vuln_type.upper()}: curated list")
    
    # Also ingest TOP100 files
    tops_100_dir = REPORTS_DIR / "tops_100"
    if tops_100_dir.exists():
        for md_file in tops_100_dir.glob("*.md"):
            list_type = md_file.stem
            content = md_file.read_text(encoding='utf-8', errors='ignore')
            
            enhanced_content = f"""# HackerOne {list_type}

The top 100 reports by {'bounty paid' if 'PAID' in list_type else 'upvotes'}.

---

{content}
"""
            
            chunk = make_chunk(enhanced_content, {
                "source": f"h1_{list_type.lower()}",
                "type": "h1_top100",
                "vuln_type": "mixed",
                "list_type": list_type
            })
            store.upsert([chunk])
            chunks_added += 1
            print(f"  ✓ {list_type}: top 100 list")
    
    return chunks_added


def main():
    print("=" * 60)
    print("HackerOne Reports Ingestion")
    print("=" * 60)
    print()
    
    if not REPORTS_DIR.exists():
        print(f"ERROR: Reports dir not found: {REPORTS_DIR}")
        print("Run: cd knowledge && git clone --depth 1 https://github.com/reddelexc/hackerone-reports.git bug-bounty-reports")
        return
    
    store = VectorStoreManager()
    initial_count = store.count()
    print(f"Initial RAG chunks: {initial_count}")
    print()
    
    # 1. Ingest CSV reports (grouped by vuln type)
    print("1. Ingesting CSV reports by vulnerability type...")
    csv_chunks = ingest_csv_reports(store)
    print(f"   Added {csv_chunks} chunks from CSV")
    print()
    
    # 2. Ingest curated TOP files
    print("2. Ingesting curated TOP files...")
    top_chunks = ingest_top_files(store)
    print(f"   Added {top_chunks} chunks from TOP files")
    print()
    
    # Summary
    final_count = store.count()
    print("=" * 60)
    print(f"DONE!")
    print(f"  CSV chunks: {csv_chunks}")
    print(f"  TOP chunks: {top_chunks}")
    print(f"  Total new: {csv_chunks + top_chunks}")
    print(f"  RAG total: {initial_count} → {final_count}")
    print("=" * 60)


if __name__ == "__main__":
    main()

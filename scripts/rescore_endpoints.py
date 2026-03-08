#!/usr/bin/env python3
"""
Script pour recalculer les scores heuristiques de tous les endpoints existants dans Redis.
Utile quand les endpoints ont été ajoutés sans score ou après modification des règles.
"""
import json
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import redis

from ghost_hunter.core.interceptor.heuristics import HeuristicsEngine
from ghost_hunter.core.contracts import FilteredRequest, InterceptedRequest


def calculate_score(endpoint_data: dict, engine: HeuristicsEngine) -> tuple[int, list]:
    """Calcule le score d'un endpoint en utilisant le vrai HeuristicsEngine."""
    
    # Reconstruire un InterceptedRequest minimal
    req = InterceptedRequest(
        method=endpoint_data.get("method", "GET"),
        host=endpoint_data.get("host", "unknown"),
        path=endpoint_data.get("path_template", "/"),
        query_params=endpoint_data.get("example_query_params", {}),
        headers=endpoint_data.get("example_headers", {}),
        cookies=endpoint_data.get("example_cookies", {}),
        body=endpoint_data.get("example_body", ""),
        body_json=endpoint_data.get("example_body_json"),
        timestamp=endpoint_data.get("first_seen", 0),
        response_status=endpoint_data.get("example_response_status"),
        response_headers=endpoint_data.get("example_response_headers", {}),
        response_body=endpoint_data.get("example_response_body", "")
    )
    
    filtered = FilteredRequest(
        request=req,
        in_scope=True,
        scope_match=endpoint_data.get("host", "manual")
    )
    
    # Scorer avec le vrai engine
    scored = engine.score(filtered)
    
    return scored.score, list(scored.potential_vulns)


def main():
    """Recalcule tous les scores."""
    r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    engine = HeuristicsEngine()
    
    print("🔄 Recalcul des scores heuristiques avec le VRAI HeuristicsEngine...")
    
    endpoints = r.hgetall("ghost:endpoints")
    
    if not endpoints:
        print("❌ Aucun endpoint trouvé dans Redis")
        return
    
    updated = 0
    errors = 0
    for hash_key, data_str in endpoints.items():
        try:
            data = json.loads(data_str)
            old_score = data.get("heuristic_score", 0)
            
            new_score, vulns = calculate_score(data, engine)
            
            if new_score != old_score or set(vulns) != set(data.get("potential_vulns", [])):
                data["heuristic_score"] = new_score
                data["potential_vulns"] = vulns
                
                r.hset("ghost:endpoints", hash_key, json.dumps(data))
                updated += 1
                
                path_short = data['path_template'][:55]
                print(f"  {'🔥' if new_score > 10 else '✅'} {data['method']:7} {path_short:55} | {old_score:3} → {new_score:3} | {vulns[:3]}")
        
        except json.JSONDecodeError:
            print(f"  ❌ JSON error: {hash_key}")
            errors += 1
        except Exception as e:
            print(f"  ❌ Error: {e}")
            errors += 1
    
    print(f"\n✅ {updated} endpoints mis à jour sur {len(endpoints)} total ({errors} erreurs)")


if __name__ == "__main__":
    main()

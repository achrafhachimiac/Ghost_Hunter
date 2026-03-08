#!/usr/bin/env python3
"""Test du fix RAG pour StrategistV2."""

from ghost_hunter.core.brain.strategist_v2.engine import StrategistV2Engine
from ghost_hunter.core.brain.strategist_v2.contracts import OriginalContext
from ghost_hunter.core.contracts import ScoredRequest, FilteredRequest, InterceptedRequest

# Créer une requête de test
intercepted = InterceptedRequest(
    method='GET',
    url='https://api.example.com/api/v1/customers/profile',
    host='api.example.com',
    path='/api/v1/customers/profile',
    headers={'Authorization': 'Bearer token123', 'Content-Type': 'application/json'},
    body='{"customer_id": 456}',
    cookies={},
)

filtered = FilteredRequest(
    request=intercepted,
    in_scope=True,
    is_api=True,
    is_static=False,
    scope_match='api.example.com',
)

scored = ScoredRequest(
    request=filtered,
    score=75,
    interesting_params=['customer_id'],
    potential_vulns=['IDOR']
)

engine = StrategistV2Engine()

print('=== Testing StrategistV2 Round 1 with RAG ===')

# Créer le contexte original
original_context = OriginalContext(
    method='GET',
    url='https://api.example.com/api/v1/customers/profile',
    headers={'Authorization': 'Bearer token123', 'Content-Type': 'application/json'},
    body='{"customer_id": 456}',
    interesting_params=['customer_id'],
    vuln_class='IDOR',
    triage_reasoning='Customer ID parameter can be manipulated for IDOR',
)

endpoint_hash = 'test-endpoint-123'

# Générer le plan
plan = engine.generate_next_round(
    endpoint_hash=endpoint_hash,
    original_context=original_context,
    num_payloads=5
)

print(f'Plan vuln_class: {plan.vuln_class}')
print(f'Reasoning: {plan.reasoning[:200]}...' if plan.reasoning else 'No reasoning')
print(f'Payloads ({len(plan.payloads)}):')
for i, p in enumerate(plan.payloads[:5]):
    print(f'  {i+1}. {p.payload}')
    print(f'     injection_point: {p.injection_point}')
    print(f'     encoding: {p.encoding}')
print(f'\nDebug prompt (first 500 chars):\n{plan.debug_prompt[:500]}...')


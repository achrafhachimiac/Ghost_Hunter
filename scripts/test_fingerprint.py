#!/usr/bin/env python3
"""Test script pour vérifier le fingerprinting."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ghost_hunter.core.intelligence import get_fingerprinter
from ghost_hunter.core.contracts import InterceptedRequest

fingerprinter = get_fingerprinter()

# Simuler une requête avec une réponse Cloudflare
fake_request = InterceptedRequest(
    method='GET',
    url='https://test-cf.example.com/api/test',
    host='test-cf.example.com',
    path='/api/test',
    headers={
        'Cookie': '__cf_bm=abc123; cf_clearance=xyz; session_id=test',
        'User-Agent': 'Mozilla/5.0'
    },
    response_status=200,
    response_headers={
        'cf-ray': '12345-LAX',
        'cf-cache-status': 'HIT',
        'content-security-policy': "default-src self",
        'strict-transport-security': 'max-age=31536000',
        'x-frame-options': 'DENY'
    },
    response_body='<html><!-- Ray ID: 12345 --></html>'
)

# Analyser
profile = fingerprinter.analyze_request(fake_request)

print('=== RÉSULTAT DU FINGERPRINTING ===')
print(f'Domain: {profile.target}')
print(f'Requests analyzed: {profile.total_requests_analyzed}')
print(f'\nWAF: {profile.waf.name if profile.waf else "Non détecté"}')
print(f'CDN: {profile.cdn.name if profile.cdn else "Non détecté"}')
print(f'Anti-bot: {profile.anti_bot.name if profile.anti_bot else "Non détecté"}')
print(f'\nSecurity Headers:')
for h, v in profile.security_headers.items():
    status = "✅" if v else "❌"
    print(f'  {h}: {status}')
print(f'\nAll signals:')
for sig in profile.all_signals[-10:]:
    print(f'  - {sig}')

# Test avec les profils analysés
print('\n\n=== ANALYZED PROFILES ===')
all_profiles = fingerprinter.get_all_profiles()
for domain, p in all_profiles.items():
    print(f'\n{domain}:')
    print(f'  Requests: {p.total_requests_analyzed}')
    print(f'  WAF: {p.waf.name if p.waf else "Non détecté"}')
    print(f'  CDN: {p.cdn.name if p.cdn else "Non détecté"}')
    print(f'  Anti-bot: {p.anti_bot.name if p.anti_bot else "Non détecté"}')
    print(f'  Backend: {p.backend_framework.name if p.backend_framework else "Non détecté"}')
    print(f'  Security headers: {sum(1 for v in p.security_headers.values() if v)}/{len(p.security_headers)}')

"""
Formatters pour les prompts du Strategist V2.

Fonctions utilitaires pour formater les différentes parties du prompt.
~200 lignes max selon les règles du projet.
"""

from typing import Dict, List, Optional
from ..contracts import AttemptResult, SecurityProfile


def format_headers(headers: Dict[str, str], max_headers: int = 10) -> str:
    """
    Formate les headers HTTP en table markdown.
    
    Args:
        headers: Dictionnaire des headers
        max_headers: Nombre max de headers à afficher
        
    Returns:
        String formaté en markdown table
    """
    if not headers:
        return "_No headers_"
    
    lines = ["| Header | Value |", "|--------|-------|"]
    
    # Priorité aux headers sensibles
    priority_headers = [
        "Authorization", "Cookie", "X-API-Key", "X-Auth-Token",
        "Content-Type", "Accept", "Origin", "Referer"
    ]
    
    # Trier: headers prioritaires en premier
    sorted_headers = []
    for key in priority_headers:
        if key in headers:
            sorted_headers.append((key, headers[key]))
    
    for key, value in headers.items():
        if key not in priority_headers:
            sorted_headers.append((key, value))
    
    # Limiter et formater
    for key, value in sorted_headers[:max_headers]:
        # Masquer les valeurs sensibles partiellement
        display_value = _mask_sensitive_value(key, value)
        lines.append(f"| `{key}` | `{display_value}` |")
    
    if len(headers) > max_headers:
        lines.append(f"| _...and {len(headers) - max_headers} more_ | |")
    
    return "\n".join(lines)


def _mask_sensitive_value(key: str, value: str) -> str:
    """Masque partiellement les valeurs sensibles."""
    sensitive_keys = ["authorization", "cookie", "x-api-key", "x-auth-token"]
    
    if key.lower() in sensitive_keys and len(value) > 20:
        return value[:10] + "..." + value[-5:]
    
    # Tronquer les valeurs trop longues
    if len(value) > 50:
        return value[:47] + "..."
    
    return value


def format_body(body: Optional[str], max_length: int = 500) -> str:
    """
    Formate le body de la requête.
    
    Args:
        body: Body de la requête (peut être JSON)
        max_length: Longueur max à afficher
        
    Returns:
        String formaté en code block
    """
    if not body:
        return "_No body_"
    
    if len(body) > max_length:
        return f"```\n{body[:max_length]}\n... (truncated, {len(body)} total chars)\n```"
    
    return f"```\n{body}\n```"


def format_test(test: AttemptResult, index: int) -> str:
    """
    Formate un résultat de test en markdown.
    
    Args:
        test: Résultat du test
        index: Index du test (1-based)
        
    Returns:
        String formaté en markdown
    """
    waf_status = "❌ BLOCKED" if test.waf_blocked else "✅ PASSED"
    interesting_status = "🎯 YES" if test.is_interesting else "No"
    
    lines = [
        f"### Test {index}",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Payload (original) | `{_truncate(test.payload_original, 60)}` |",
        f"| Payload (sent) | `{_truncate(test.payload_sent, 60)}` |",
        f"| Encoding | {test.encoding} |",
        f"| Injection point | `{test.injection_point}` |",
        f"| Response status | {test.status_code} |",
        f"| Response time | {test.response_time_ms:.0f}ms |",
        f"| Response length | {test.response_length} bytes |",
        f"| WAF Status | {waf_status} |",
    ]
    
    if test.waf_blocked:
        lines.append(f"| WAF Provider | {test.waf_provider or 'Unknown'} |")
        if test.waf_signature:
            lines.append(f"| WAF Signature | `{_truncate(test.waf_signature, 40)}` |")
    
    lines.append(f"| Interesting | {interesting_status} |")
    
    if test.diff_indicators:
        lines.append(f"| Diff indicators | {', '.join(test.diff_indicators)} |")
    
    # Response snippet
    if test.response_snippet:
        lines.extend([
            "",
            "**Response snippet:**",
            f"```",
            _truncate(test.response_snippet, 200),
            "```",
        ])
    
    return "\n".join(lines)


def _truncate(text: str, max_length: int) -> str:
    """Tronque un texte avec ellipsis."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def format_list(items: List[str], bullet: str = "-", max_items: int = 10) -> str:
    """
    Formate une liste en markdown.
    
    Args:
        items: Liste d'items
        bullet: Caractère pour les bullets
        max_items: Nombre max d'items
        
    Returns:
        String formaté
    """
    if not items:
        return "_None_"
    
    lines = [f"{bullet} {item}" for item in items[:max_items]]
    
    if len(items) > max_items:
        lines.append(f"{bullet} _...and {len(items) - max_items} more_")
    
    return "\n".join(lines)


def format_encoding_stats(stats: Dict[str, Dict[str, int]]) -> str:
    """
    Formate les stats d'encoding en table markdown.
    
    Args:
        stats: Dict {encoding: {blocked: N, passed: N}}
        
    Returns:
        String formaté en markdown table
    """
    if not stats:
        return "_No encoding stats_"
    
    lines = [
        "| Encoding | Blocked | Passed | Success Rate |",
        "|----------|---------|--------|--------------|"
    ]
    
    for encoding, data in sorted(stats.items()):
        blocked = data.get("blocked", 0)
        passed = data.get("passed", 0)
        total = blocked + passed
        
        if total > 0:
            rate = (passed / total) * 100
            rate_str = f"{rate:.0f}%"
        else:
            rate_str = "N/A"
        
        lines.append(f"| {encoding} | {blocked} | {passed} | {rate_str} |")
    
    return "\n".join(lines)


def format_security_profile(profile: SecurityProfile) -> str:
    """
    Formate le profil de sécurité en markdown.
    
    Args:
        profile: SecurityProfile détecté
        
    Returns:
        String formaté
    """
    lines = []
    
    if profile.waf:
        lines.append(f"🛡️ **WAF:** {profile.waf}")
    
    if profile.cdn:
        lines.append(f"🌐 **CDN:** {profile.cdn}")
    
    if profile.rate_limit:
        lines.append("⏱️ **Rate Limiting:** Detected")
    
    if profile.anti_bot:
        lines.append(f"🤖 **Anti-Bot:** {profile.anti_bot}")
    
    if not lines:
        return "_No security measures detected_"
    
    return "\n".join(lines)


def format_round_summary(
    round_number: int,
    blocked: int,
    passed: int,
    interesting: int,
    total: int
) -> str:
    """
    Formate le résumé d'un round.
    
    Args:
        round_number: Numéro du round
        blocked: Nombre de tests bloqués
        passed: Nombre de tests passés
        interesting: Nombre de résultats intéressants
        total: Total de tests
        
    Returns:
        String formaté
    """
    if total == 0:
        return f"### Round {round_number}: No tests executed"
    
    block_rate = (blocked / total) * 100
    
    lines = [
        f"### Round {round_number} Summary",
        "",
        f"- Total tests: {total}",
        f"- Blocked by WAF: {blocked} ({block_rate:.0f}%)",
        f"- Passed WAF: {passed}",
        f"- Interesting results: {interesting}",
    ]
    
    return "\n".join(lines)

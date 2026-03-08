"""
Strategist Parser Module
========================
Extraction JSON et validation des injection points.
"""

import json
import re
import logging
from typing import Optional, Set

from ghost_hunter.core.contracts import TriageDecision

logger = logging.getLogger(__name__)


def collect_nested_keys(obj: dict, keys: Set[str], prefix: str = "") -> None:
    """
    Recursively collect all keys from nested JSON object for IDOR detection.
    
    Args:
        obj: JSON object to traverse
        keys: Set to collect keys into (modified in place)
        prefix: Current key prefix for nested keys
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            keys.add(key)
            if isinstance(value, dict):
                collect_nested_keys(value, keys, f"{prefix}{key}.")
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        collect_nested_keys(item, keys, f"{prefix}{key}[].")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                collect_nested_keys(item, keys, prefix)


def extract_json(text: str) -> Optional[dict]:
    """
    Extrait le JSON d'une réponse texte de l'IA.
    
    Essaie plusieurs stratégies:
    1. Parse direct
    2. Extraction depuis bloc ```json
    3. Extraction depuis bloc ```
    4. Recherche du premier { au dernier }
    
    Args:
        text: Réponse texte de l'IA
        
    Returns:
        dict parsé ou None si échec
    """
    # Log la réponse brute pour debug
    logger.debug(f"🤖 Raw AI response (first 500 chars): {text[:500]}")
    
    try:
        result = json.loads(text)
        logger.info(f"✅ Parsed JSON directly")
        return result
    except Exception as e:
        logger.debug(f"Direct JSON parse failed: {e}")
    
    json_patterns = [
        r'```json\s*(.*?)\s*```',
        r'```\s*(.*?)\s*```',
    ]
    
    for pattern in json_patterns:
        matches = re.findall(pattern, text, re.DOTALL)
        for match in matches:
            try:
                result = json.loads(match.strip())
                logger.info(f"✅ Parsed JSON from code block")
                return result
            except:
                continue
    
    # Dernier recours: trouver le premier { et dernier }
    try:
        start = text.index('{')
        end = text.rindex('}') + 1
        result = json.loads(text[start:end])
        logger.info(f"✅ Parsed JSON by finding braces")
        return result
    except Exception as e:
        logger.warning(f"❌ Could not extract JSON from AI response: {e}")
        logger.warning(f"   Response preview: {text[:200]}")
        return None


def validate_injection_points(ai_points: list, triage: TriageDecision) -> list:
    """
    Valide et corrige les injection points générés par l'IA.
    
    Problème: L'IA invente parfois des noms comme "appointment_id" alors que
    le vrai placeholder dans l'URL est "{token}".
    
    Cette fonction:
    1. Vérifie si chaque point existe réellement dans la requête
    2. Si non, tente de mapper vers les vrais placeholders du path
    3. Ajoute les placeholders du path template si manquants
    
    Args:
        ai_points: Liste des points suggérés par l'IA
        triage: Décision du triage avec la requête originale
        
    Returns:
        Liste des points d'injection validés
    """
    req = triage.request.request.request
    validated = []
    
    # Collecter les sources valides d'injection
    valid_sources: Set[str] = set()
    
    # Query params
    valid_sources.update(req.query_params.keys())
    
    # Body JSON keys (nested support)
    if req.body_json:
        valid_sources.update(req.body_json.keys())
        # Also add nested keys for IDOR detection
        collect_nested_keys(req.body_json, valid_sources)
    
    # Body URL-encoded form fields (POST forms)
    if req.body and not req.body_json:
        content_type = req.headers.get('content-type', req.headers.get('Content-Type', ''))
        if 'x-www-form-urlencoded' in content_type.lower():
            try:
                from urllib.parse import parse_qs, unquote
                form_fields = parse_qs(req.body, keep_blank_values=True)
                for key in form_fields.keys():
                    # Handle Rails-style array params: field[0][id] → field, id
                    clean_key = unquote(key)
                    valid_sources.add(clean_key)
                    # Extract nested parts: visit_motive_categories_attributes[][id] → id
                    if '[' in clean_key:
                        # Get base name before first [
                        base_name = clean_key.split('[')[0]
                        valid_sources.add(base_name)
                        # Get nested field names inside []
                        nested = re.findall(r'\[([^\]]+)\]', clean_key)
                        for n in nested:
                            if n:  # Skip empty [] 
                                valid_sources.add(n)
                logger.debug(f"📝 Parsed form fields: {list(valid_sources)[:20]}")
            except Exception as e:
                logger.warning(f"Failed to parse form body: {e}")
    
    # Headers (lowercase) - EXCLUDE Cookie and Authorization headers (not injection targets)
    excluded_headers = {'cookie', 'authorization', 'x-csrf-token'}
    valid_sources.update(h.lower() for h in req.headers.keys() if h.lower() not in excluded_headers)
    
    # IMPORTANT: Cookies are NEVER valid IDOR injection targets
    # Cookies contain session/tracking data, NOT business object identifiers
    # Examples of cookies that should NOT be injection points:
    #   - _cfuvid, altid, JSESSIONID (tracking/session)
    #   - application session cookies
    # DO NOT add cookies to valid_sources for IDOR testing
    
    # Path placeholders from template
    path_template = None
    if hasattr(req, 'get_endpoint_template') and callable(req.get_endpoint_template):
        path_template = req.get_endpoint_template()
    
    path_placeholders = []
    if path_template:
        path_placeholders = re.findall(r'\{([^}]+)\}', path_template)
        for ph in path_placeholders:
            valid_sources.add(f"{{{ph}}}")  # {token}
            # Also find composite format: resource/{placeholder}
            match = re.search(rf'([a-zA-Z_]+)/\{{{ph}\}}', path_template)
            if match:
                valid_sources.add(f"{match.group(1)}/{{{ph}}}")  # appointments/{token}
    
    logger.debug(f"🔍 Valid injection sources: {valid_sources}")
    
    # Valider chaque point suggéré par l'IA
    for point in ai_points:
        if not point:
            continue
            
        # Cas 1: Le point existe directement
        if point in valid_sources or point.lower() in valid_sources:
            validated.append(point)
            logger.debug(f"✅ Injection point '{point}' validated (direct match)")
            continue
        
        # Cas 2: L'IA a inventé un nom comme "appointment_id" - mapper au placeholder
        # Si le nom contient "_id" ou "id", essayer de le mapper à un placeholder du path
        point_lower = point.lower()
        mapped = False
        if ('_id' in point_lower or point_lower.endswith('id')) and path_placeholders:
            # Chercher un placeholder correspondant
            for ph in path_placeholders:
                ph_lower = ph.lower()
                # Match si: appointment_id → {token} (appointments dans le path)
                # ou user_id → {id}, etc.
                
                # Trouver le segment de ressource avant le placeholder
                match = re.search(rf'([a-zA-Z_]+)/\{{{ph}\}}', path_template)
                if match:
                    resource = match.group(1)  # "appointments"
                    resource_singular = resource.rstrip('s')  # "appointment"
                    
                    # Si le nom inventé par l'IA correspond à la ressource
                    if resource_singular in point_lower or resource in point_lower:
                        composite = f"{resource}/{{{ph}}}"
                        if composite not in validated:
                            validated.append(composite)
                            logger.info(f"🔄 Mapped AI point '{point}' → '{composite}'")
                        mapped = True
                        break
                    # Fallback: si l'IA point contient "id" et le placeholder contient "id"
                    elif 'id' in point_lower and 'id' in ph_lower:
                        composite = f"{resource}/{{{ph}}}"
                        if composite not in validated:
                            validated.append(composite)
                            logger.info(f"🔄 Mapped AI point '{point}' → '{composite}' (id fallback)")
                        mapped = True
                        break
                else:
                    # Simple placeholder comme {id}
                    simple = f"{{{ph}}}"
                    if simple not in validated:
                        validated.append(simple)
                        logger.info(f"🔄 Mapped AI point '{point}' → '{simple}'")
                    mapped = True
                    break
            
            # Si toujours pas mappé mais on a des placeholders, prendre le premier
            if not mapped and path_placeholders:
                ph = path_placeholders[0]
                match = re.search(rf'([a-zA-Z_]+)/\{{{ph}\}}', path_template)
                if match:
                    composite = f"{match.group(1)}/{{{ph}}}"
                    if composite not in validated:
                        validated.append(composite)
                        logger.info(f"🔄 Mapped AI point '{point}' → '{composite}' (first placeholder)")
                else:
                    simple = f"{{{ph}}}"
                    if simple not in validated:
                        validated.append(simple)
                        logger.info(f"🔄 Mapped AI point '{point}' → '{simple}' (first placeholder)")
                mapped = True
            
            if mapped:
                continue
        
        # Cas 3: Pour les form fields avec ID - chercher des champs similaires
        # L'IA peut suggérer "id" ou "speciality_id" - on cherche dans valid_sources
        if 'id' in point_lower:
            for source in valid_sources:
                source_lower = source.lower()
                # Match si le source contient le même pattern id
                if point_lower == source_lower:
                    validated.append(source)
                    logger.info(f"🔄 Matched AI point '{point}' → '{source}' (case-insensitive)")
                    mapped = True
                    break
                # Match partiel: "id" matches "speciality_id", "visit_id", etc.
                elif point_lower in source_lower or source_lower.endswith(point_lower):
                    validated.append(source)
                    logger.info(f"🔄 Matched AI point '{point}' → '{source}' (partial match)")
                    mapped = True
                    break
            if mapped:
                continue
        
        # Cas 4: Point non trouvé - log warning mais ne pas ajouter
        logger.warning(f"⚠️ Injection point '{point}' not found in request - skipping")
    
    # FALLBACK: S'assurer qu'on a au moins les path placeholders si IDOR suggéré
    if not validated and path_placeholders:
        for ph in path_placeholders:
            match = re.search(rf'([a-zA-Z_]+)/\{{{ph}\}}', path_template)
            if match:
                validated.append(f"{match.group(1)}/{{{ph}}}")
            else:
                validated.append(f"{{{ph}}}")
        logger.info(f"📍 Added path placeholders as fallback: {validated}")
    
    # FALLBACK 2: Pour les form fields avec ID potentiel (IDOR)
    # Si pas de validation et on a des form fields avec "id" dedans
    # ONLY use body params, NOT cookies or headers
    if not validated:
        # Build set of body-only sources (form fields + JSON keys)
        body_sources: Set[str] = set()
        if req.body_json:
            body_sources.update(req.body_json.keys())
            collect_nested_keys(req.body_json, body_sources)
        elif req.body:
            content_type = req.headers.get('content-type', req.headers.get('Content-Type', ''))
            if 'x-www-form-urlencoded' in content_type.lower():
                try:
                    from urllib.parse import parse_qs, unquote
                    form_fields = parse_qs(req.body, keep_blank_values=True)
                    for key in form_fields.keys():
                        clean_key = unquote(key)
                        body_sources.add(clean_key)
                        # Extract nested parts for Rails-style params
                        if '[' in clean_key:
                            base_name = clean_key.split('[')[0]
                            body_sources.add(base_name)
                            nested = re.findall(r'\[([^\]]+)\]', clean_key)
                            for n in nested:
                                if n:
                                    body_sources.add(n)
                except Exception:
                    pass
        
        id_fields = [s for s in body_sources if 'id' in s.lower() and s not in validated]
        if id_fields:
            # Prendre les 3 champs les plus intéressants (prefer full field names)
            # Sort by length (longer = more specific = better)
            id_fields.sort(key=lambda x: len(x), reverse=True)
            for field in id_fields[:3]:
                validated.append(field)
            logger.info(f"📍 Added ID-containing BODY fields as fallback: {validated}")
    
    return validated

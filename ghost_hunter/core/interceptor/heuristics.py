"""
Ghost-Hunter Heuristics Engine
==============================
Score les requêtes selon leur potentiel de vulnérabilité.
Version "Hunter" - Pensé comme un pentester.
"""

from typing import List, Dict, Tuple
import re
import json

from ghost_hunter.core.contracts import (
    FilteredRequest, ScoredRequest, HeuristicSignal, Priority
)


class HeuristicsEngine:
    """Moteur de scoring heuristique - Version Hunter's Dictionary."""
    
    # ═══════════════════════════════════════════════════════════════
    # RÈGLES PARAMÈTRES - "The Hunter's Dictionary"
    # ═══════════════════════════════════════════════════════════════
    PARAM_RULES: List[Tuple[str, int, str, List[str]]] = [
        
        # ═══════════════════════════════════════════════════════════════
        # 1. 🆔 GENERIC IDs - Priority #1 (IDOR enumeration targets)
        # ═══════════════════════════════════════════════════════════════
        # ─── Exact Generic IDs ───
        (r'^(id|pk|uid|uuid|guid|oid|ref|slug|identifier)$', 15, "Generic ID - prime IDOR target", ["IDOR", "BOLA"]),
        
        # ─── Suffix Match (*_id, *Id, *_uid, *_ref) - catches everything! ───
        (r'_id$', 15, "Suffix _id - IDOR target", ["IDOR", "BOLA"]),
        (r'_ids$', 15, "Suffix _ids (array) - IDOR target", ["IDOR", "BOLA"]),
        (r'Id$', 15, "Suffix Id (camelCase) - IDOR target", ["IDOR", "BOLA"]),
        (r'Ids$', 15, "Suffix Ids (camelCase array) - IDOR target", ["IDOR", "BOLA"]),
        (r'_uid$', 15, "Suffix _uid - IDOR target", ["IDOR", "BOLA"]),
        (r'_ref$', 12, "Suffix _ref - IDOR target", ["IDOR"]),
        (r'_uuid$', 12, "Suffix _uuid - IDOR target", ["IDOR"]),
        
        # ═══════════════════════════════════════════════════════════════
        # 2. 🆔 IDOR / BOLA - Specific Entity IDs
        # ═══════════════════════════════════════════════════════════════
        # ─── User/Account ───
        (r'^(user|userid|user_id|account|account_id|acct_id|member_id)$', 15, "User/Account ID - IDOR!", ["IDOR", "BOLA"]),
        (r'^(customer_id|client_id|customer|client)$', 15, "Customer ID - IDOR!", ["IDOR", "BOLA"]),
        (r'^(profile_id|profile_ref|profile)$', 14, "Profile ID - IDOR!", ["IDOR"]),
        
        # ─── Organization / Multi-tenant apps ───
        (r'^(org_id|organization_id|org|organization)$', 14, "Org ID - multi-tenant IDOR!", ["IDOR", "BOLA"]),
        (r'^org_ids$', 14, "Org IDs array - multi-tenant IDOR!", ["IDOR", "BOLA"]),
        (r'^(company_id|company|team_id|team|group_id|group)$', 14, "Company/Team ID - IDOR!", ["IDOR"]),
        (r'^(tenant_id|tenant|workspace_id|workspace)$', 14, "Tenant ID - IDOR!", ["IDOR"]),
        
        # ─── Medical/Healthcare platforms ───
        (r'^(patient_id|patient|doctor_id|doctor|practitioner_id|practitioner)$', 16, "Medical ID - sensitive IDOR!", ["IDOR", "BOLA", "Data Leak"]),
        (r'^agenda_ids?$', 15, "Agenda ID - healthcare IDOR!", ["IDOR", "BOLA"]),
        (r'^appointment_ids?$', 15, "Appointment ID - healthcare IDOR!", ["IDOR", "BOLA"]),
        (r'^(onboardee|doctor_app|consultation)_?ids?$', 12, "Healthcare entity ID", ["IDOR"]),
        
        # ─── Transactions/Business ───
        (r'^(order_id|order|transaction_id|transaction)$', 14, "Order/Transaction ID - IDOR!", ["IDOR"]),
        (r'^(invoice_id|invoice|bill_id|bill|receipt_id|receipt)$', 14, "Invoice ID - financial IDOR!", ["IDOR"]),
        (r'^(booking_id|booking|reservation_id|reservation|appointment_id|appointment)$', 14, "Booking ID - IDOR!", ["IDOR"]),
        (r'^(payment_id|payment|subscription_id)$', 14, "Payment ID - financial!", ["IDOR"]),
        
        # ─── Documents/Files ───
        (r'^(document_id|document|doc_id|doc)$', 12, "Document ID - IDOR!", ["IDOR"]),
        (r'^(file_id|file|attachment_id|attachment)$', 12, "File ID - IDOR!", ["IDOR", "LFI"]),
        (r'^(image_id|photo_id|asset_id|media_id)$', 10, "Media ID - IDOR!", ["IDOR"]),
        
        # ═══════════════════════════════════════════════════════════════
        # 3. 🔐 MASS ASSIGNMENT / PRIVILEGE ESCALATION
        # ═══════════════════════════════════════════════════════════════
        # ─── Admin/Role (Critical!) ───
        (r'^(admin|is_admin|admin_user|superuser|super_user)$', 18, "Admin flag - PrivEsc!", ["Mass Assignment", "PrivEsc"]),
        (r'^(role|roles|role_id|user_role)$', 16, "Role param - PrivEsc!", ["Mass Assignment", "PrivEsc"]),
        (r'^(group|groups|group_id)$', 14, "Group param - PrivEsc!", ["Mass Assignment", "PrivEsc"]),
        (r'^(moderator|mod|staff|is_staff)$', 14, "Staff flag - PrivEsc!", ["Mass Assignment", "PrivEsc"]),
        
        # ─── Permissions ───
        (r'^(permission|permissions|perms|scope|scopes)$', 16, "Permissions - PrivEsc!", ["Mass Assignment", "PrivEsc"]),
        (r'^(privilege|privileges|access|access_level)$', 14, "Access level - PrivEsc!", ["Mass Assignment", "PrivEsc"]),
        (r'^(can_|allow_|is_allowed)', 12, "Permission prefix - PrivEsc!", ["Mass Assignment"]),
        
        # ─── Account State ───
        (r'^(status|state|account_status)$', 12, "Status param - state manipulation", ["Mass Assignment"]),
        (r'^(active|is_active|enabled|disabled)$', 12, "Active flag - state manipulation", ["Mass Assignment"]),
        (r'^(verified|is_verified|confirmed|is_confirmed)$', 14, "Verified flag - bypass verification!", ["Mass Assignment"]),
        (r'^(blocked|banned|suspended|locked)$', 12, "Block status - unblock yourself!", ["Mass Assignment"]),
        (r'^(approved|is_approved|pending)$', 12, "Approval status", ["Mass Assignment"]),
        
        # ─── Plan/Subscription ───
        (r'^(plan|tier|level|subscription|premium|pro)$', 14, "Plan/tier - upgrade for free!", ["Mass Assignment", "Business Logic"]),
        (r'^(trial|is_trial|trial_end)$', 10, "Trial flag - extend trial!", ["Mass Assignment"]),
        (r'^(type|user_type|account_type|membership)$', 12, "Type param - PrivEsc", ["Mass Assignment"]),
        
        # ─── Financial (DANGER!) ───
        (r'^(credit|credits|balance|wallet)$', 16, "Balance param - add credits!", ["Mass Assignment", "Business Logic"]),
        (r'^(price|amount|total|subtotal)$', 14, "Price param - manipulation!", ["Business Logic", "Price Manipulation"]),
        (r'^(discount|discount_percent|coupon|promo)$', 14, "Discount param - free stuff!", ["Business Logic"]),
        (r'^(quantity|qty|count)$', 10, "Quantity - manipulation", ["Business Logic"]),
        
        # ─── Auth bypass ───
        (r'^(password|passwd|pwd|new_password)$', 12, "Password field", ["Mass Assignment"]),
        (r'^(reset_token|reset_code|verification_code)$', 14, "Reset token - account takeover!", ["Account Takeover"]),
        
        # ═══════════════════════════════════════════════════════════════
        # 4. 🌐 SSRF / OPEN REDIRECT / RCE
        # ═══════════════════════════════════════════════════════════════
        # ─── URL parameters ───
        (r'^(url|uri|link|href|src|source)$', 14, "URL param - SSRF/Redirect!", ["SSRF", "Open Redirect"]),
        (r'^(path|file|filename|filepath|file_path|file_name)$', 14, "File path - LFI!", ["LFI", "Path Traversal"]),
        (r'^(dir|directory|folder|location)$', 12, "Directory param - LFI!", ["LFI", "Path Traversal"]),
        
        # ─── Redirect ───
        (r'^(redirect|redirect_to|redirect_uri|redirect_url)$', 14, "Redirect - Open Redirect!", ["Open Redirect"]),
        (r'^(return|return_to|return_url|returnUrl)$', 14, "Return URL - Open Redirect!", ["Open Redirect"]),
        (r'^(next|goto|continue|destination|target)$', 12, "Navigation param - Open Redirect!", ["Open Redirect"]),
        (r'^(callback|callback_url|webhook|webhook_url)$', 16, "Webhook - SSRF!", ["SSRF"]),
        (r'^(notify_url|postback_url|ipn_url)$', 14, "Notification URL - SSRF!", ["SSRF"]),
        
        # ─── Image/Resource URLs (SSRF) ───
        (r'^(image_url|avatar_url|picture_url|photo_url|icon_url)$', 12, "Image URL - SSRF!", ["SSRF"]),
        (r'^(endpoint|api_url|base_url|server|host)$', 14, "Server param - SSRF!", ["SSRF"]),
        (r'^(proxy|proxy_url|forward|forward_to)$', 14, "Proxy param - SSRF!", ["SSRF"]),
        
        # ─── Command Execution (RCE!) ───
        (r'^(cmd|command|exec|execute|run|shell)$', 18, "Command param - RCE!", ["CMDi", "RCE"]),
        (r'^(process|script|program|binary)$', 14, "Process param - RCE!", ["CMDi", "RCE"]),
        (r'^(ping|host|ip|address|domain|dns)$', 12, "Network param - CMDi/SSRF!", ["CMDi", "SSRF"]),
        
        # ─── Template (SSTI) ───
        (r'^(template|tpl|view|layout|partial|render)$', 14, "Template param - SSTI!", ["SSTI"]),
        (r'^(include|require|import|load)$', 12, "Include param - LFI/SSTI!", ["LFI", "SSTI"]),
        
        # ─── Upload ───
        (r'^(upload|upload_url|import|import_url)$', 12, "Upload param - file upload!", ["File Upload"]),
        
        # ═══════════════════════════════════════════════════════════════
        # 5. 🧠 BUSINESS LOGIC / DATA EXPOSURE
        # ═══════════════════════════════════════════════════════════════
        # ─── Database/Query params ───
        (r'^(table|schema|collection|entity|object|model)$', 14, "DB reference - NoSQLi/SQLi!", ["SQLi", "NoSQLi"]),
        (r'^(column|columns|fields|select|attributes|props)$', 12, "Column selection - data exposure!", ["SQLi", "Data Leak"]),
        (r'^(query|search|q|keyword|filter|filters|find)$', 10, "Search param - Injection!", ["SQLi", "NoSQLi"]),
        (r'^(where|having|group_by|group)$', 14, "SQL clause - SQLi!", ["SQLi"]),
        (r'^(sort|order|orderby|order_by|sort_by|direction)$', 10, "Sort param - SQLi ORDER BY!", ["SQLi"]),
        (r'^(limit|offset|skip|take|count)$', 8, "Pagination - DoS/Data exposure!", ["Data Leak"]),
        
        # ─── Export/Report (IDOR goldmine) ───
        (r'^(export|report|download|format)$', 12, "Export param - IDOR file access!", ["IDOR", "Data Leak"]),
        (r'^(view|mode|context|scope)$', 8, "View mode - data exposure!", ["Data Leak"]),
        
        # ═══════════════════════════════════════════════════════════════
        # 6. 🛠️ DEBUG / CONFIGURATION (Dev mistakes)
        # ═══════════════════════════════════════════════════════════════
        (r'^(debug|test|testing|mock|verbose)$', 14, "Debug param - info leak!", ["Info Disclosure"]),
        (r'^(config|configuration|env|environment|setting|settings|setup)$', 14, "Config param - info leak!", ["Info Disclosure"]),
        (r'^(version|build|revision|commit)$', 8, "Version param - info leak!", ["Info Disclosure"]),
        (r'^(trace|log|logging|logs)$', 10, "Log param - info leak!", ["Info Disclosure"]),
        (r'^(internal|private|hidden|secret)$', 12, "Internal param - hidden feature!", ["Info Disclosure"]),
        
        # ─── Authentication / Session ───
        (r'^(token|access_token|refresh_token|api_key|apikey|api_secret)$', 12, "Token param - sensitive!", ["Token Leak"]),
        (r'^(session|session_id|sid|jsessionid)$', 10, "Session param", ["Session"]),
        (r'^(email|mail|username|login)$', 6, "Auth identifier - enumeration!", ["Account Enum"]),
        (r'^(otp|code|verification_code|pin)$', 12, "OTP - account takeover!", ["Account Takeover"]),
        
        # ─── XML/Serialization ───
        (r'^(xml|xml_data|xmlbody|xml_content)$', 14, "XML param - XXE!", ["XXE"]),
        (r'^(data|payload|object|serialized|pickle)$', 10, "Serialization param - RCE!", ["Deserialization"]),
        (r'^(json|jsonp|jsondata)$', 6, "JSON param", []),
        
        # ═══════════════════════════════════════════════════════════════
        # 7. 🗑️ KILL LIST - Noise to ignore (saves AI tokens)
        # ═══════════════════════════════════════════════════════════════
        # ─── Tracking / Analytics (Marketing) ───
        (r'^(utm_source|utm_medium|utm_campaign|utm_term|utm_content)$', -20, "UTM tracking - noise", []),
        (r'^(fbclid|gclid|dclid|msclkid|yclid)$', -20, "Ad click ID - noise", []),
        (r'^(_ga|_gid|_gat|gtm_|ga_|__utm)$', -20, "Google Analytics - noise", []),
        (r'^(analytics_|tracking_|pixel_)', -15, "Tracking param - noise", []),
        
        # ─── Cache Busters / UI ───
        (r'^(_|__|\$|jQuery\d*)$', -15, "jQuery cache buster - noise", []),
        (r'^(timestamp|ts|t|_t|nonce|rand|random|cachebust|cb|nc)$', -10, "Cache buster - noise", []),
        (r'^(viewport|width|height|dpr|density)$', -10, "UI resize - noise", []),
        (r'^(utf8|encoding|charset)$', -10, "Encoding param - noise", []),
        
        # ─── Localization (low value) ───
        (r'^(locale|lang|language|lng|i18n)$', -8, "Localization - noise", []),
        (r'^(currency|timezone|tz|region|country)$', -5, "Localization - noise", []),
        
        # ─── Format / Output (usually not vuln) ───
        (r'^(format|output|accept|content_type|mime)$', -5, "Format param - noise", []),
        (r'^(pretty|indent|minify|compress)$', -5, "Formatting - noise", []),
        
        # ─── Pagination (low priority, but keep if combined) ───
        (r'^(page|per_page|page_size)$', -2, "Pagination - low value alone", []),
    ]
    
    # ═══════════════════════════════════════════════════════════════
    # RÈGLES ENDPOINTS - Basées sur les targets Bug Bounty
    # ═══════════════════════════════════════════════════════════════
    ENDPOINT_RULES: List[Tuple[str, int, str, List[str]]] = [
        # ─── High Value Targets ───
        (r'/admin', 15, "Admin endpoint - AuthZ bypass!", ["AuthZ Bypass", "IDOR"]),
        (r'/api/internal', 15, "Internal API - not for users!", ["AuthZ Bypass"]),
        (r'/api/v[0-9]+/admin', 15, "Admin API", ["AuthZ Bypass"]),
        (r'/debug', 12, "Debug endpoint - info leak", ["Info Disclosure"]),
        (r'/console', 12, "Console endpoint", ["RCE", "Info Disclosure"]),
        (r'/graphql', 10, "GraphQL - introspection/IDOR", ["GraphQL", "IDOR"]),
        (r'/actuator', 12, "Spring Actuator - info leak!", ["Info Disclosure", "RCE"]),
        
        # ─── User/Account Operations (IDOR heaven) ───
        (r'/users?/[^/]+', 10, "User endpoint with ID", ["IDOR"]),
        (r'/accounts?/[^/]+', 10, "Account endpoint with ID", ["IDOR"]),
        (r'/profiles?/[^/]+', 10, "Profile endpoint with ID", ["IDOR"]),
        (r'/patients?', 12, "Patient endpoint (medical) - sensitive!", ["IDOR", "Data Leak"]),
        (r'/doctors?', 10, "Doctor endpoint", ["IDOR"]),
        (r'/appointments?', 10, "Appointment endpoint", ["IDOR"]),
        (r'/bookings?', 10, "Booking endpoint", ["IDOR"]),
        (r'/orders?/[^/]+', 10, "Order with ID", ["IDOR"]),
        (r'/invoices?', 10, "Invoice endpoint", ["IDOR"]),
        
        # ─── Money/Business Logic ───
        (r'/payment', 12, "Payment endpoint - Business Logic!", ["Business Logic", "Price Manipulation"]),
        (r'/checkout', 12, "Checkout - Race Condition!", ["Race Condition", "Business Logic"]),
        (r'/transfer', 14, "Transfer endpoint - critical!", ["Business Logic", "Race Condition"]),
        (r'/billing', 10, "Billing endpoint", ["Business Logic"]),
        (r'/subscription', 10, "Subscription - plan bypass?", ["Business Logic"]),
        (r'/coupon', 10, "Coupon - reuse/manipulation", ["Business Logic"]),
        (r'/discount', 10, "Discount endpoint", ["Business Logic"]),
        
        # ─── File Operations ───
        (r'/upload', 12, "Upload endpoint - file upload!", ["File Upload", "RCE"]),
        (r'/import', 10, "Import endpoint", ["File Upload", "XXE"]),
        (r'/export', 10, "Export endpoint - IDOR!", ["IDOR", "Info Disclosure"]),
        (r'/download', 10, "Download endpoint - LFI!", ["LFI", "IDOR"]),
        (r'/file', 10, "File endpoint", ["LFI", "IDOR"]),
        (r'/attachment', 8, "Attachment endpoint", ["LFI", "IDOR"]),
        
        # ─── Auth Endpoints ───
        (r'/login', 6, "Login - brute force", ["Brute Force"]),
        (r'/register', 8, "Registration - mass assignment", ["Mass Assignment"]),
        (r'/signup', 8, "Signup", ["Mass Assignment"]),
        (r'/password.*reset', 10, "Password reset - token leak!", ["Account Takeover", "Token Leak"]),
        (r'/forgot', 8, "Forgot password", ["Account Takeover"]),
        (r'/verify', 8, "Verification endpoint", ["Token Leak"]),
        (r'/oauth', 8, "OAuth endpoint", ["OAuth Misconfiguration"]),
        (r'/callback', 8, "Callback - SSRF/OAuth", ["SSRF", "OAuth"]),
        (r'/token', 8, "Token endpoint", ["Token Leak"]),
        (r'/api[_-]?key', 10, "API Key endpoint", ["Key Leak"]),
        
        # ─── Configuration/Settings ───
        (r'/config', 10, "Config endpoint - settings leak?", ["Info Disclosure"]),
        (r'/settings', 8, "Settings endpoint", ["Mass Assignment"]),
        (r'/preferences', 6, "Preferences", ["Mass Assignment"]),
        
        # ─── Reporting/Logs ───
        (r'/reports?', 8, "Report endpoint - IDOR", ["IDOR"]),
        (r'/logs?', 8, "Logs endpoint - info leak", ["Info Disclosure"]),
        (r'/audit', 8, "Audit logs", ["Info Disclosure"]),
        
        # ═══════════════════════════════════════════════════════════════
        # KILL LIST - Static Files & Endpoints
        # ═══════════════════════════════════════════════════════════════
        # ─── Health/Status endpoints ───
        (r'^/(health|healthz|healthcheck)', -20, "Health check", []),
        (r'^/(ping|pong|ready|readyz|alive|livez)$', -20, "Liveness check", []),
        (r'^/status$', -15, "Status endpoint", []),
        (r'/metrics$', -15, "Metrics endpoint", []),
        (r'/__', -15, "Internal endpoint", []),
        
        # ─── Static content directories ───
        (r'^/(static|assets|public|dist|build|bundle)/', -25, "Static directory", []),
        (r'^/(images?|img|media|uploads?/images?)/', -20, "Image directory", []),
        (r'^/(fonts?|webfonts)/', -25, "Font directory", []),
        (r'^/(css|styles?|stylesheets?)/', -25, "CSS directory", []),
        (r'^/(vendor|node_modules|bower_components)/', -25, "Vendor libs", []),
        
        # ─── Static files by extension ───
        (r'\.(css|less|scss|sass)$', -25, "Stylesheet", []),
        (r'\.(woff2?|ttf|otf|eot)$', -25, "Font file", []),
        (r'\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff?)$', -25, "Image file", []),
        (r'\.(map|map\.js)$', -25, "Source map", []),
        (r'\.(mp3|mp4|webm|ogg|wav|avi|mov)$', -25, "Media file", []),
        (r'\.(pdf|doc|docx|xls|xlsx)$', -10, "Document (might have IDOR)", []),
        
        # ─── JS files - EXCEPTION: config/env files might have secrets ───
        (r'/(jquery|bootstrap|react|angular|vue|lodash|moment)[^/]*\.js$', -25, "Library JS - noise", []),
        (r'\.(chunk|vendor|polyfill|runtime)\.js$', -25, "Bundle chunk - noise", []),
        # NOTE: main.js, app.js, config.js, env.js are NOT killed - might have secrets!
        
        # ─── Other noise ───
        (r'/favicon\.ico$', -25, "Favicon", []),
        (r'/robots\.txt$', -20, "Robots.txt", []),
        (r'/sitemap\.xml$', -15, "Sitemap", []),
        (r'/manifest\.json$', -15, "PWA manifest", []),
        (r'/service-worker\.js$', -10, "Service worker", []),
    ]
    
    # ═══════════════════════════════════════════════════════════════
    # SCORES MÉTHODES HTTP
    # ═══════════════════════════════════════════════════════════════
    METHOD_SCORES: Dict[str, int] = {
        "PUT": 8,      # Modification = plus intéressant
        "DELETE": 10,  # Suppression = très intéressant (IDOR delete)
        "PATCH": 8,    # Modification partielle
        "POST": 5,     # Création/Action
        "GET": 0,      # Lecture
        "OPTIONS": -10,
        "HEAD": -10,
    }
    
    # ═══════════════════════════════════════════════════════════════
    # PATTERNS BODY - Analyse du contenu JSON/Form
    # ═══════════════════════════════════════════════════════════════
    SENSITIVE_BODY_KEYS = {
        # IDOR
        "user_id": 12, "account_id": 12, "patient_id": 15, "doctor_id": 12,
        "owner_id": 12, "target_id": 12, "recipient_id": 12,
        # PrivEsc
        "role": 15, "is_admin": 18, "admin": 18, "permissions": 15,
        "status": 8, "verified": 10, "approved": 10,
        # Business Logic
        "price": 12, "amount": 12, "total": 10, "discount": 10,
        "quantity": 8, "qty": 8,
        # Sensitive
        "password": 10, "secret": 10, "token": 10,
    }
    
    def __init__(self, score_threshold: int = 15):
        """
        Args:
            score_threshold: Score minimum pour être considéré intéressant
        """
        self.score_threshold = score_threshold
    
    def score(self, request: FilteredRequest) -> ScoredRequest:
        """
        Calcule le score de suspicion d'une requête.
        Version Hunter - analyse body, response, patterns métier.
        
        Returns:
            ScoredRequest avec score et signaux
        """
        signals: List[HeuristicSignal] = []
        total_score = 0
        interesting_params: List[str] = []
        potential_vulns: set = set()
        
        req = request.request
        
        # ═══════════════════════════════════════════════════════════════
        # 1. ANALYSE DES PARAMÈTRES (Query + Body JSON + Form)
        # ═══════════════════════════════════════════════════════════════
        all_params = list(req.query_params.keys())
        
        # Body JSON
        if req.body_json and isinstance(req.body_json, dict):
            all_params.extend(req.body_json.keys())
            # Analyse récursive des clés imbriquées
            all_params.extend(self._extract_nested_keys(req.body_json))
        
        # Body Form-urlencoded (parse from raw body)
        if req.body and not req.body_json:
            form_keys = self._parse_form_keys(req.body)
            all_params.extend(form_keys)
        
        # Scorer chaque paramètre
        seen_params = set()
        for param in all_params:
            if param in seen_params:
                continue
            seen_params.add(param)
            
            # Nettoyer le param: enlever [] (Rails/PHP array notation)
            param_clean = re.sub(r'\[\]$', '', param)
            param_lower = param_clean.lower()
            for pattern, score, reason, vulns in self.PARAM_RULES:
                if re.match(pattern, param_lower, re.IGNORECASE):
                    signals.append(HeuristicSignal(
                        name=f"param:{param}",
                        score=score,
                        reason=reason
                    ))
                    total_score += score
                    if score > 0:
                        interesting_params.append(param)
                        potential_vulns.update(vulns)
                    break
        
        # ═══════════════════════════════════════════════════════════════
        # 2. ANALYSE DU BODY EN PROFONDEUR (Valeurs sensibles)
        # ═══════════════════════════════════════════════════════════════
        body_score, body_signals = self._analyze_body_values(req.body_json, req.body)
        total_score += body_score
        signals.extend(body_signals)
        for sig in body_signals:
            if sig.score > 0:
                potential_vulns.update(["IDOR", "Business Logic"])
        
        # ═══════════════════════════════════════════════════════════════
        # 3. ANALYSE DE L'ENDPOINT
        # ═══════════════════════════════════════════════════════════════
        path = req.path.lower()
        for pattern, score, reason, vulns in self.ENDPOINT_RULES:
            if re.search(pattern, path, re.IGNORECASE):
                signals.append(HeuristicSignal(
                    name=f"endpoint:{pattern}",
                    score=score,
                    reason=reason
                ))
                total_score += score
                potential_vulns.update(vulns)
        
        # Bonus: endpoint avec ID dans le path + EXTRACTION des IDs
        path_ids = self._extract_path_ids(req.path)
        if path_ids:
            signals.append(HeuristicSignal(
                name="path_has_id",
                score=12,  # Augmenté car on a extrait les IDs
                reason=f"Path contains {len(path_ids)} ID(s): {', '.join(path_ids[:3])} - IDOR target!"
            ))
            total_score += 12
            potential_vulns.add("IDOR")
            # IMPORTANT: Ajouter les IDs du path aux interesting_params avec préfixe
            for pid in path_ids:
                interesting_params.append(f"path:{pid}")
        
        # ═══════════════════════════════════════════════════════════════
        # 4. ANALYSE DE LA MÉTHODE HTTP
        # ═══════════════════════════════════════════════════════════════
        method_score = self.METHOD_SCORES.get(req.method.upper(), 0)
        if method_score != 0:
            signals.append(HeuristicSignal(
                name=f"method:{req.method}",
                score=method_score,
                reason=f"HTTP {req.method} method"
            ))
            total_score += method_score
        
        # ═══════════════════════════════════════════════════════════════
        # 5. BONUS CONTEXTUELS
        # ═══════════════════════════════════════════════════════════════
        
        # Authentification
        has_auth = False
        for header in req.headers.keys():
            if header.lower() in ['authorization', 'x-auth-token', 'x-api-key']:
                has_auth = True
                break
        
        if has_auth:
            signals.append(HeuristicSignal(
                name="has_auth",
                score=5,
                reason="Authenticated request - test with other user's token!"
            ))
            total_score += 5
        
        # JSON API
        content_type = req.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            signals.append(HeuristicSignal(
                name="json_api",
                score=3,
                reason="JSON API - structured data"
            ))
            total_score += 3
        
        # XML (XXE potential)
        if "xml" in content_type or (req.body and req.body.strip().startswith('<?xml')):
            signals.append(HeuristicSignal(
                name="xml_body",
                score=12,
                reason="XML body - XXE potential!"
            ))
            total_score += 12
            potential_vulns.add("XXE")
        
        # ═══════════════════════════════════════════════════════════════
        # FINALISATION
        # ═══════════════════════════════════════════════════════════════
        # Limiter le score entre 0 et 100
        total_score = max(0, min(100, total_score))
        
        # Build score breakdown for AI prompt (top contributing signals)
        score_breakdown = self._build_score_breakdown(signals, potential_vulns)
        
        # Créer le résultat
        result = ScoredRequest(
            request=request,
            score=total_score,
            signals=signals,
            interesting_params=list(set(interesting_params)),
            potential_vulns=list(potential_vulns),
            score_breakdown=score_breakdown
        )
        result.compute_priority()
        
        return result
    
    def _build_score_breakdown(self, signals: List[HeuristicSignal], potential_vulns: set) -> str:
        """Build human-readable score breakdown for AI prompt."""
        if not signals:
            return "No significant signals detected"
        
        # Sort by absolute score value (highest impact first)
        sorted_signals = sorted(signals, key=lambda s: abs(s.score), reverse=True)
        
        # Take top 5 contributing signals
        top_signals = sorted_signals[:5]
        
        breakdown_lines = []
        for sig in top_signals:
            sign = "+" if sig.score > 0 else ""
            breakdown_lines.append(f"  {sign}{sig.score}: {sig.reason}")
        
        # Add vuln reasoning if any
        if potential_vulns:
            vulns_str = ", ".join(potential_vulns)
            breakdown_lines.append(f"  → Flagged for: {vulns_str}")
        
        return "\n".join(breakdown_lines)
    
    def _extract_nested_keys(self, obj: dict, prefix: str = "", depth: int = 0) -> List[str]:
        """Extrait les clés de manière récursive (max 3 niveaux)."""
        if depth > 3:
            return []
        
        keys = []
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            keys.append(k)  # Just the key name
            if isinstance(v, dict):
                keys.extend(self._extract_nested_keys(v, full_key, depth + 1))
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                keys.extend(self._extract_nested_keys(v[0], full_key, depth + 1))
        return keys
    
    def _parse_form_keys(self, body: str) -> List[str]:
        """Parse form-urlencoded body pour extraire les clés."""
        keys = []
        if not body:
            return keys
        
        try:
            # Split by & and extract key names
            for pair in body.split('&'):
                if '=' in pair:
                    key = pair.split('=')[0]
                    # URL decode common patterns
                    key = key.replace('%5B', '[').replace('%5D', ']')
                    # Extract base key (before [])
                    base_key = key.split('[')[0]
                    keys.append(base_key)
                    # Also add the full key for array patterns
                    if '[' in key:
                        # visit_motive_categories_attributes[][id] -> id
                        inner = re.findall(r'\[([^\]]+)\]', key)
                        keys.extend([i for i in inner if i and not i.isdigit()])
        except:
            pass
        
        return keys
    
    def _analyze_body_values(self, body_json: dict, raw_body: str) -> Tuple[int, List[HeuristicSignal]]:
        """Analyse les VALEURS du body (pas juste les clés)."""
        score = 0
        signals = []
        
        if not body_json and not raw_body:
            return 0, []
        
        # Analyse JSON
        if body_json and isinstance(body_json, dict):
            for key, value in body_json.items():
                key_lower = key.lower()
                
                # Check sensitive keys with numeric values (IDOR gold!)
                if key_lower in self.SENSITIVE_BODY_KEYS:
                    key_score = self.SENSITIVE_BODY_KEYS[key_lower]
                    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
                        # Numeric ID = very interesting for IDOR
                        signals.append(HeuristicSignal(
                            name=f"body:{key}={value}",
                            score=key_score,
                            reason=f"Numeric {key} in body - test IDOR!"
                        ))
                        score += key_score
                    elif value in ['true', 'false', True, False]:
                        # Boolean sensitive field
                        signals.append(HeuristicSignal(
                            name=f"body:{key}={value}",
                            score=key_score,
                            reason=f"Boolean {key} - test Mass Assignment!"
                        ))
                        score += key_score
        
        return score, signals

    def _extract_path_ids(self, path: str) -> List[str]:
        """
        Extrait tous les IDs trouvés dans le path URL.
        
        Patterns détectés:
        - /u750918835/ → u750918835 (letter-prefixed account format)
        - /users/12345/ → 12345 (numeric ID)
        - /a1b2c3d4-e5f6-... → UUID
        - /abc123xyz/ → alphanum ID between slashes
        
        Returns:
            List des IDs extraits avec leur format
        """
        ids = []
        path_parts = path.split('/')
        
        for part in path_parts:
            if not part:
                continue
            
            # Pattern 1: letter-prefixed account IDs like u750918835
            if re.match(r'^[uU]\d{6,}$', part):
                ids.append(part)
                continue
                
            # Pattern 2: Pure numeric IDs (4+ digits to avoid ports/versions)
            if re.match(r'^\d{4,}$', part):
                ids.append(part)
                continue
            
            # Pattern 3: UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
            if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', part, re.IGNORECASE):
                ids.append(part)
                continue
            
            # Pattern 4: Short UUID / hash-like (8-32 hex chars, not a word)
            if re.match(r'^[a-f0-9]{8,32}$', part, re.IGNORECASE) and not re.match(r'^[a-z]+$', part):
                ids.append(part)
                continue
            
            # Pattern 5: Alphanumeric ID (letters + digits mixed, 6+ chars)
            # Catches: acc_12345, org_abc123, etc.
            if re.match(r'^[a-zA-Z]+[_-]?[a-zA-Z0-9]{4,}$', part):
                ids.append(part)
                continue
            
            # Pattern 6: Base64-like IDs (contains mix of upper/lower/digits, 20+ chars)
            if len(part) >= 20 and re.match(r'^[a-zA-Z0-9_-]+$', part):
                ids.append(part)
                continue
        
        return ids
    def is_interesting(self, scored: ScoredRequest) -> bool:
        """Détermine si la requête mérite une analyse IA."""
        return scored.score >= self.score_threshold

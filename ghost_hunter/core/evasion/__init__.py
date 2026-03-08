"""
Ghost-Hunter Evasion Module
============================
Techniques d'évasion pour éviter la détection.
"""

from ghost_hunter.core.evasion.user_agent import (
    UserAgentRotator,
    UserAgentProfile,
    get_ua_rotator,
    get_random_user_agent,
    get_browser_headers,
    BrowserType,
    OSType
)

from ghost_hunter.core.evasion.residential_proxy import (
    GonzoProxyClient,
    ResidentialProxyManager,
    ProxyCredentials,
    get_proxy_manager,
    get_residential_proxy
)

from ghost_hunter.core.evasion.checker import WAFChecker
from ghost_hunter.core.evasion.transforms import (
    apply_transform,
    apply_transforms_chain,
    get_available_transforms,
    get_all_mutations,
)
from ghost_hunter.core.evasion.mutator import PayloadMutator


__all__ = [
    # WAF Evasion
    "WAFChecker",
    "PayloadMutator",
    "apply_transform",
    "apply_transforms_chain",
    "get_available_transforms",
    "get_all_mutations",
    # User-Agent
    "UserAgentRotator",
    "UserAgentProfile", 
    "get_ua_rotator",
    "get_random_user_agent",
    "get_browser_headers",
    "BrowserType",
    "OSType",
    # Residential Proxy
    "GonzoProxyClient",
    "ResidentialProxyManager",
    "ProxyCredentials",
    "get_proxy_manager",
    "get_residential_proxy",
    # WAF Evasion
    "WAFChecker",
]

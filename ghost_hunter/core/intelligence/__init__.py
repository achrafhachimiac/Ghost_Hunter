"""
Ghost-Hunter Intelligence Module
=================================
Collecte et gestion de l'intelligence pour l'analyse de sécurité.
"""

from ghost_hunter.core.intelligence.knowledge_loader import (
    KnowledgeLoader,
    KnowledgeEntry,
    VulnContext,
    get_knowledge_loader,
)

from ghost_hunter.core.intelligence.osint import (
    OSINTCollector,
    CrtshClient,
    ShodanClient,
    SecurityTrailsClient,
    SubdomainResult,
    HostInfo,
    DomainIntel,
    get_osint_collector,
    quick_subdomain_enum,
)

from ghost_hunter.core.intelligence.tech_profiler import (
    TechProfiler,
    TechProfile,
    Technology,
    get_tech_profiler,
    quick_fingerprint,
)

from ghost_hunter.core.intelligence.security_fingerprint import (
    SecurityFingerprinter,
    ProgramSecurityProfile,
    DetectedTechnology,
    SecuritySignal,
    get_fingerprinter,
)


__all__ = [
    # Knowledge Base
    "KnowledgeLoader",
    "KnowledgeEntry",
    "VulnContext",
    "get_knowledge_loader",
    # OSINT
    "OSINTCollector",
    "CrtshClient",
    "ShodanClient", 
    "SecurityTrailsClient",
    "SubdomainResult",
    "HostInfo",
    "DomainIntel",
    "get_osint_collector",
    "quick_subdomain_enum",
    # Tech Profiler
    "TechProfiler",
    "TechProfile",
    "Technology",
    "get_tech_profiler",
    "quick_fingerprint",
    # Security Fingerprinting
    "SecurityFingerprinter",
    "ProgramSecurityProfile",
    "DetectedTechnology",
    "SecuritySignal",
    "get_fingerprinter",
]

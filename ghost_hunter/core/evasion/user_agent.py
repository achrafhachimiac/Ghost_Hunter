"""
Ghost-Hunter User-Agent Rotation
=================================
Rotation sophistiquée de User-Agents pour l'évasion.
"""

import random
import hashlib
import time
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class BrowserType(Enum):
    """Types de navigateurs supportés."""
    CHROME = "chrome"
    FIREFOX = "firefox"
    SAFARI = "safari"
    EDGE = "edge"


class OSType(Enum):
    """Systèmes d'exploitation supportés."""
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"


@dataclass
class UserAgentProfile:
    """Profil complet d'un User-Agent."""
    user_agent: str
    browser: BrowserType
    browser_version: str
    os: OSType
    os_version: str
    accept: str
    accept_language: str
    accept_encoding: str
    sec_ch_ua: Optional[str] = None
    sec_ch_ua_platform: Optional[str] = None
    sec_ch_ua_mobile: str = "?0"


# User-Agents 2024-2025 avec fingerprints complets
USER_AGENT_PROFILES: List[UserAgentProfile] = [
    # Chrome Windows (les plus communs)
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        browser=BrowserType.CHROME,
        browser_version="120.0.0.0",
        os=OSType.WINDOWS,
        os_version="10.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9,fr;q=0.8",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"Windows"'
    ),
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        browser=BrowserType.CHROME,
        browser_version="121.0.0.0",
        os=OSType.WINDOWS,
        os_version="10.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
        sec_ch_ua_platform='"Windows"'
    ),
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        browser=BrowserType.CHROME,
        browser_version="122.0.0.0",
        os=OSType.WINDOWS,
        os_version="10.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        sec_ch_ua_platform='"Windows"'
    ),
    
    # Chrome macOS
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        browser=BrowserType.CHROME,
        browser_version="120.0.0.0",
        os=OSType.MACOS,
        os_version="10.15.7",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"macOS"'
    ),
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        browser=BrowserType.CHROME,
        browser_version="121.0.0.0",
        os=OSType.MACOS,
        os_version="10.15.7",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="fr-FR,fr;q=0.9,en;q=0.8",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
        sec_ch_ua_platform='"macOS"'
    ),
    
    # Firefox Windows
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        browser=BrowserType.FIREFOX,
        browser_version="121.0",
        os=OSType.WINDOWS,
        os_version="10.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br"
    ),
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        browser=BrowserType.FIREFOX,
        browser_version="122.0",
        os=OSType.WINDOWS,
        os_version="10.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language="fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
        accept_encoding="gzip, deflate, br"
    ),
    
    # Firefox macOS
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        browser=BrowserType.FIREFOX,
        browser_version="121.0",
        os=OSType.MACOS,
        os_version="10.15",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br"
    ),
    
    # Safari macOS
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        browser=BrowserType.SAFARI,
        browser_version="17.2",
        os=OSType.MACOS,
        os_version="10.15.7",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br"
    ),
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
        browser=BrowserType.SAFARI,
        browser_version="17.3",
        os=OSType.MACOS,
        os_version="10.15.7",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="fr-FR,fr;q=0.9",
        accept_encoding="gzip, deflate, br"
    ),
    
    # Edge Windows
    UserAgentProfile(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        browser=BrowserType.EDGE,
        browser_version="120.0.0.0",
        os=OSType.WINDOWS,
        os_version="10.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
        sec_ch_ua_platform='"Windows"'
    ),
    
    # Chrome Linux
    UserAgentProfile(
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        browser=BrowserType.CHROME,
        browser_version="120.0.0.0",
        os=OSType.LINUX,
        os_version="x86_64",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"Linux"'
    ),
    UserAgentProfile(
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        browser=BrowserType.CHROME,
        browser_version="121.0.0.0",
        os=OSType.LINUX,
        os_version="x86_64",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-GB,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
        sec_ch_ua_platform='"Linux"'
    ),
    
    # Firefox Linux
    UserAgentProfile(
        user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        browser=BrowserType.FIREFOX,
        browser_version="121.0",
        os=OSType.LINUX,
        os_version="x86_64",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br"
    ),
    UserAgentProfile(
        user_agent="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        browser=BrowserType.FIREFOX,
        browser_version="122.0",
        os=OSType.LINUX,
        os_version="x86_64",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br"
    ),
]


class UserAgentRotator:
    """
    Gestionnaire de rotation User-Agent avec fingerprints cohérents.
    
    Assure que tous les headers HTTP correspondent au User-Agent utilisé.
    """
    
    # Distribution réaliste des navigateurs (poids)
    BROWSER_WEIGHTS = {
        BrowserType.CHROME: 65,   # ~65% du marché
        BrowserType.SAFARI: 18,   # ~18%
        BrowserType.FIREFOX: 8,   # ~8%
        BrowserType.EDGE: 9       # ~9%
    }
    
    def __init__(
        self,
        mode: str = "session",
        preferred_browser: Optional[BrowserType] = None,
        preferred_os: Optional[OSType] = None
    ):
        """
        Args:
            mode: Mode de rotation
                - "session": même profil pour toute la session
                - "per_request": nouveau profil à chaque requête
                - "per_host": profil par domaine/host
            preferred_browser: Navigateur préféré (ou None pour random)
            preferred_os: OS préféré (ou None pour random)
        """
        self.mode = mode
        self.preferred_browser = preferred_browser
        self.preferred_os = preferred_os
        
        self._current_profile: Optional[UserAgentProfile] = None
        self._host_profiles: Dict[str, UserAgentProfile] = {}
        self._rotation_count = 0
    
    def _filter_profiles(self) -> List[UserAgentProfile]:
        """Filtre les profils selon les préférences."""
        profiles = USER_AGENT_PROFILES
        
        if self.preferred_browser:
            profiles = [p for p in profiles if p.browser == self.preferred_browser]
        
        if self.preferred_os:
            profiles = [p for p in profiles if p.os == self.preferred_os]
        
        return profiles if profiles else USER_AGENT_PROFILES
    
    def _weighted_random_profile(self) -> UserAgentProfile:
        """Sélectionne un profil avec distribution réaliste."""
        profiles = self._filter_profiles()
        
        if not self.preferred_browser:
            # Appliquer les poids réalistes
            weighted_profiles = []
            for profile in profiles:
                weight = self.BROWSER_WEIGHTS.get(profile.browser, 10)
                weighted_profiles.extend([profile] * weight)
            return random.choice(weighted_profiles)
        
        return random.choice(profiles)
    
    def _get_host_profile(self, host: str) -> UserAgentProfile:
        """Récupère ou crée un profil pour un host spécifique."""
        if host not in self._host_profiles:
            # Hash du host pour un choix déterministe mais "aléatoire"
            profiles = self._filter_profiles()
            idx = int(hashlib.md5(host.encode()).hexdigest(), 16) % len(profiles)
            self._host_profiles[host] = profiles[idx]
        
        return self._host_profiles[host]
    
    def get_profile(self, host: Optional[str] = None) -> UserAgentProfile:
        """
        Récupère un profil User-Agent.
        
        Args:
            host: Hostname (utilisé en mode per_host)
            
        Returns:
            UserAgentProfile complet
        """
        self._rotation_count += 1
        
        if self.mode == "session":
            if self._current_profile is None:
                self._current_profile = self._weighted_random_profile()
            return self._current_profile
        
        elif self.mode == "per_host" and host:
            return self._get_host_profile(host)
        
        else:  # per_request
            return self._weighted_random_profile()
    
    def get_headers(self, host: Optional[str] = None) -> Dict[str, str]:
        """
        Récupère tous les headers HTTP cohérents.
        
        Args:
            host: Hostname pour le mode per_host
            
        Returns:
            Dict de headers HTTP
        """
        profile = self.get_profile(host)
        
        headers = {
            "User-Agent": profile.user_agent,
            "Accept": profile.accept,
            "Accept-Language": profile.accept_language,
            "Accept-Encoding": profile.accept_encoding,
        }
        
        # Ajouter les headers Client Hints si Chrome/Edge
        if profile.sec_ch_ua:
            headers["Sec-CH-UA"] = profile.sec_ch_ua
        if profile.sec_ch_ua_platform:
            headers["Sec-CH-UA-Platform"] = profile.sec_ch_ua_platform
        if profile.sec_ch_ua_mobile:
            headers["Sec-CH-UA-Mobile"] = profile.sec_ch_ua_mobile
        
        return headers
    
    def rotate(self):
        """Force la rotation du profil."""
        self._current_profile = self._weighted_random_profile()
        self._host_profiles.clear()
    
    def get_stats(self) -> Dict:
        """Statistiques de rotation."""
        return {
            "mode": self.mode,
            "rotation_count": self._rotation_count,
            "current_browser": self._current_profile.browser.value if self._current_profile else None,
            "current_os": self._current_profile.os.value if self._current_profile else None,
            "host_profiles_count": len(self._host_profiles)
        }


# Instance globale
_rotator: Optional[UserAgentRotator] = None


def get_ua_rotator(mode: str = "session") -> UserAgentRotator:
    """Récupère le rotateur global."""
    global _rotator
    if _rotator is None:
        _rotator = UserAgentRotator(mode=mode)
    return _rotator


def get_random_user_agent() -> str:
    """Shortcut: récupère un User-Agent aléatoire."""
    return get_ua_rotator().get_profile().user_agent


def get_browser_headers(host: Optional[str] = None) -> Dict[str, str]:
    """Shortcut: récupère des headers navigateur cohérents."""
    return get_ua_rotator().get_headers(host)

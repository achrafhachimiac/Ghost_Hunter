"""
WAF Evasion Mutator Engine
==========================
Génère des mutations intelligentes pour évader les WAF.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from ghost_hunter.core.contracts import Mutation, EvasionResult
from ghost_hunter.core.evasion.transforms import (
    apply_transform,
    apply_transforms_chain,
    get_available_transforms,
    get_transform_info,
)
from ghost_hunter.core.evasion.checker import WAFChecker


@dataclass
class TransformStats:
    """Stats d'un transform."""
    attempts: int = 0
    successes: int = 0
    
    @property
    def success_rate(self) -> float:
        if self.attempts == 0:
            return 0.5  # Prior neutre
        return self.successes / self.attempts


class PayloadMutator:
    """
    Moteur de mutation intelligent.
    
    Génère des variations de payloads et teste leur évasion WAF.
    Apprend quels transforms fonctionnent le mieux.
    """
    
    # Ordre de priorité par défaut (empirique)
    DEFAULT_PRIORITY = {
        "sqli": [
            "case_swap", "inline_comment", "whitespace_substitute",
            "url_encode", "double_url_encode", "hex_encode",
            "char_function", "concat_split"
        ],
        "xss": [
            "tag_case_mix", "svg_payload", "null_bytes",
            "event_case_swap", "url_encode", "double_url_encode"
        ],
        "cmdi": [
            "variable_sub", "ifs_sub", "quote_insert",
            "wildcard", "url_encode", "base64_wrap"
        ],
    }
    
    def __init__(self, checker: Optional[WAFChecker] = None):
        """
        Initialize mutator.
        
        Args:
            checker: WAFChecker instance (créé si None)
        """
        self._checker = checker
        self._stats: Dict[str, Dict[str, TransformStats]] = defaultdict(
            lambda: defaultdict(TransformStats)
        )
    
    @property
    def checker(self) -> WAFChecker:
        """Lazy load checker."""
        if self._checker is None:
            self._checker = WAFChecker()
        return self._checker
    
    def generate_mutations(
        self,
        payload: str,
        vuln_type: str,
        transforms: Optional[List[str]] = None
    ) -> List[Mutation]:
        """
        Génère toutes les mutations possibles.
        
        Args:
            payload: Payload original
            vuln_type: Type de vulnérabilité
            transforms: Liste de transforms (ou tous si None)
            
        Returns:
            Liste de Mutations
        """
        if transforms is None:
            transforms = get_available_transforms(vuln_type)
        
        mutations = []
        for transform_name in transforms:
            mutated = apply_transform(payload, transform_name, vuln_type)
            if mutated != payload:
                mutations.append(Mutation(
                    original=payload,
                    mutated=mutated,
                    transform=transform_name,
                    blocked_by=[],
                    evades=False
                ))
        
        return mutations
    
    def check_evasion(self, payload: str, vuln_type: str) -> Mutation:
        """
        Vérifie si un payload est bloqué.
        
        Args:
            payload: Le payload à tester
            vuln_type: Type de vulnérabilité
            
        Returns:
            Mutation avec blocked_by rempli
        """
        blocked, sources, _ = self.checker.is_blocked_any(payload, vuln_type)
        
        return Mutation(
            original=payload,
            mutated=payload,
            transform="none",
            blocked_by=sources,
            evades=not blocked
        )
    
    def find_evasions(
        self,
        payload: str,
        vuln_type: str,
        max_attempts: int = 20
    ) -> List[Mutation]:
        """
        Trouve les mutations qui évadent le WAF.
        
        Args:
            payload: Payload original
            vuln_type: Type de vulnérabilité
            max_attempts: Nombre max de mutations à tester
            
        Returns:
            Liste des mutations qui évadent
        """
        mutations = self.generate_mutations(payload, vuln_type)
        evasions = []
        
        for mutation in mutations[:max_attempts]:
            blocked, sources, _ = self.checker.is_blocked_any(
                mutation.mutated, vuln_type
            )
            
            mutation.blocked_by = sources
            mutation.evades = not blocked
            
            if not blocked:
                evasions.append(mutation)
        
        return evasions
    
    def chain_transforms(
        self,
        payload: str,
        transforms: List[str],
        vuln_type: str
    ) -> str:
        """
        Applique une chaîne de transforms.
        
        Args:
            payload: Payload original
            transforms: Liste ordonnée de transforms
            vuln_type: Type de vulnérabilité
            
        Returns:
            Payload transformé
        """
        return apply_transforms_chain(payload, transforms, vuln_type)
    
    def auto_evade(
        self,
        payload: str,
        vuln_type: str,
        max_depth: int = 3
    ) -> EvasionResult:
        """
        Trouve automatiquement une évasion.
        
        Essaie d'abord les transforms simples, puis chaîne si nécessaire.
        
        Args:
            payload: Payload original
            vuln_type: Type de vulnérabilité
            max_depth: Profondeur max de chaînage
            
        Returns:
            EvasionResult avec best_mutation si trouvé
        """
        mutations: List[Mutation] = []
        best: Optional[Mutation] = None
        
        # 1. Test original
        original_blocked, original_sources, _ = self.checker.is_blocked_any(
            payload, vuln_type
        )
        
        if not original_blocked:
            # Pas bloqué, retourne directement
            return EvasionResult(
                payload=payload,
                mutations=[],
                best_mutation=None,
                all_blocked=False
            )
        
        # 2. Single transforms
        ordered = self.get_ordered_transforms(vuln_type)
        for transform in ordered:
            mutated = apply_transform(payload, transform, vuln_type)
            if mutated == payload:
                continue
            
            blocked, sources, _ = self.checker.is_blocked_any(mutated, vuln_type)
            
            mutation = Mutation(
                original=payload,
                mutated=mutated,
                transform=transform,
                blocked_by=sources,
                evades=not blocked
            )
            mutations.append(mutation)
            
            if not blocked:
                best = mutation
                self.record_result(transform, vuln_type, evaded=True)
                break
            else:
                self.record_result(transform, vuln_type, evaded=False)
        
        # 3. Chaînage si nécessaire
        if best is None and max_depth > 1:
            best = self._try_chains(payload, vuln_type, ordered, max_depth, mutations)
        
        return EvasionResult(
            payload=payload,
            mutations=mutations,
            best_mutation=best,
            all_blocked=(best is None)
        )
    
    def _try_chains(
        self,
        payload: str,
        vuln_type: str,
        transforms: List[str],
        max_depth: int,
        mutations: List[Mutation]
    ) -> Optional[Mutation]:
        """Essaie des chaînes de transforms."""
        from itertools import combinations
        
        for depth in range(2, max_depth + 1):
            for combo in combinations(transforms[:6], depth):  # Limite combos
                mutated = apply_transforms_chain(payload, list(combo), vuln_type)
                if mutated == payload:
                    continue
                
                blocked, sources, _ = self.checker.is_blocked_any(mutated, vuln_type)
                
                chain_name = " + ".join(combo)
                mutation = Mutation(
                    original=payload,
                    mutated=mutated,
                    transform=chain_name,
                    blocked_by=sources,
                    evades=not blocked
                )
                mutations.append(mutation)
                
                if not blocked:
                    return mutation
        
        return None
    
    def get_ordered_transforms(self, vuln_type: str) -> List[str]:
        """
        Retourne transforms triés par efficacité.
        
        Args:
            vuln_type: Type de vulnérabilité
            
        Returns:
            Liste ordonnée de noms de transforms
        """
        available = get_available_transforms(vuln_type)
        
        # Sort by success rate, with default priority as tiebreaker
        default_order = self.DEFAULT_PRIORITY.get(vuln_type, [])
        
        def sort_key(name: str) -> Tuple[float, int]:
            stats = self._stats[vuln_type].get(name, TransformStats())
            # Higher success rate first, then default priority
            priority = default_order.index(name) if name in default_order else 100
            return (-stats.success_rate, priority)
        
        return sorted(available, key=sort_key)
    
    def record_result(
        self,
        transform: str,
        vuln_type: str,
        evaded: bool
    ) -> None:
        """
        Enregistre le résultat d'un transform.
        
        Args:
            transform: Nom du transform
            vuln_type: Type de vulnérabilité
            evaded: True si évasion réussie
        """
        stats = self._stats[vuln_type][transform]
        stats.attempts += 1
        if evaded:
            stats.successes += 1
    
    def get_transform_stats(self, vuln_type: str) -> Dict[str, Dict]:
        """
        Retourne les statistiques des transforms.
        
        Args:
            vuln_type: Type de vulnérabilité
            
        Returns:
            Dict avec stats par transform
        """
        result = {}
        for name, stats in self._stats[vuln_type].items():
            result[name] = {
                "attempts": stats.attempts,
                "successes": stats.successes,
                "success_rate": stats.success_rate
            }
        return result

#!/usr/bin/env python3
"""
Ghost-Hunter Main Pipeline
==========================
Script principal pour lancer le pipeline complet.

Usage:
    python -m ghost_hunter.main
    
    ou avec options:
    python -m ghost_hunter.main --proxy-port 8888 --dashboard-port 1010
"""

import sys
import os
import json
import asyncio
import logging
import argparse
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional
from queue import Queue

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('data/logs/ghost_hunter.log', mode='a')
    ]
)
logger = logging.getLogger("GhostHunter")

# Imports Ghost Hunter
from ghost_hunter.core.contracts import (
    InterceptedRequest, FilteredRequest, ScoredRequest,
    TriageDecision, AttackPlan, Finding, FindingSeverity
)
from ghost_hunter.core.interceptor.scope_filter import ScopeFilter
from ghost_hunter.core.interceptor.heuristics import HeuristicsEngine
from ghost_hunter.core.interceptor.dedup import DedupEngine
from ghost_hunter.core.brain.groq_client import GroqClient
from ghost_hunter.core.brain.triage import TriageEngine
from ghost_hunter.core.brain.strategist import StrategistEngine
from ghost_hunter.core.ai_logger import get_ai_logger

# Import Nuclei Scanner
try:
    from ghost_hunter.core.scanner import get_nuclei_scanner, NucleiScanner
    NUCLEI_AVAILABLE = True
except ImportError:
    NUCLEI_AVAILABLE = False
    logger.warning("Nuclei Scanner not available")

# Import Security Fingerprinter
try:
    from ghost_hunter.core.intelligence import get_fingerprinter, SecurityFingerprinter
    FINGERPRINT_AVAILABLE = True
except ImportError:
    FINGERPRINT_AVAILABLE = False
    logger.warning("Security Fingerprinter not available")

# Import Custom HTTP Runner
try:
    from ghost_hunter.core.executor.http_runner import CustomHTTPRunner
    HTTP_RUNNER_AVAILABLE = True
except ImportError:
    HTTP_RUNNER_AVAILABLE = False
    logger.warning("Custom HTTP Runner not available")


class GhostHunterPipeline:
    """
    Pipeline principal de Ghost-Hunter.
    
    Nouveau flow avec Nuclei et Two-Tier Triage:
    
    1. Intercepter → Scope Filter → Dedup
    2. En parallèle:
       a) Nuclei scan (vulns connues, CVEs)
       b) Scoring heuristique
    3. Two-Tier AI Triage:
       - Tier 1: Quick triage sur TOUTES les requêtes (seuil bas)
       - Tier 2: Full triage avec Knowledge Base si intéressant
    4. Strategist → Executor
    """
    
    def __init__(
        self,
        config_dir: Path = Path("config"),
        data_dir: Path = Path("data"),
        use_redis: bool = False,
        ai_enabled: bool = True,
        nuclei_enabled: bool = True,
        score_threshold: int = 15,  # Abaissé de 30 à 15
        use_two_tier_triage: bool = True
    ):
        """
        Args:
            config_dir: Dossier de configuration
            data_dir: Dossier de données
            use_redis: Utiliser Redis pour la déduplication
            ai_enabled: Activer le triage/stratégie IA
            nuclei_enabled: Activer le scan Nuclei en parallèle
            score_threshold: Score minimum pour le triage IA (abaissé à 15)
            use_two_tier_triage: Utiliser le two-tier triage (quick + full)
        """
        self.config_dir = config_dir
        self.data_dir = data_dir
        self.ai_enabled = ai_enabled
        self.nuclei_enabled = nuclei_enabled and NUCLEI_AVAILABLE
        self.score_threshold = score_threshold
        self.use_two_tier_triage = use_two_tier_triage
        
        # Security Fingerprinter
        self.fingerprinter = get_fingerprinter() if FINGERPRINT_AVAILABLE else None
        
        # Charger la configuration
        self._load_config()
        
        # Initialiser les composants
        self._init_components(use_redis)
        
        # Files d'attente pour le traitement asynchrone
        self.request_queue: Queue = Queue()
        self.finding_queue: Queue = Queue()
        
        # Statistiques
        self.stats = {
            "intercepted": 0,
            "in_scope": 0,
            "deduplicated": 0,
            "unique": 0,  # Endpoints uniques (non-duplicates)
            "scored": 0,
            "quick_triaged": 0,
            "full_triaged": 0,
            "triaged": 0,
            "tested": 0,
            "findings": 0,
            "nuclei_scanned": 0,
            "nuclei_findings": 0,
            "start_time": datetime.now().timestamp()
        }
        
        # Storage pour le dashboard
        self.requests_store: dict = {}
        self.findings_store: dict = {}
        
        logger.info("🔥 Ghost-Hunter Pipeline initialisé")
    
    def _load_config(self):
        """Charge les fichiers de configuration."""
        # Scope
        scope_file = self.config_dir / "scope.json"
        if scope_file.exists():
            with open(scope_file) as f:
                self.scope_config = json.load(f)
            logger.info(f"📋 Scope chargé: {self.scope_config.get('target', {}).get('name', 'Unknown')}")
        else:
            self.scope_config = {"in_scope": [], "out_of_scope": []}
            logger.warning("⚠️ Pas de scope.json trouvé, aucun filtrage")
        
        # API Keys - Support Groq (priority) or OpenRouter (fallback)
        api_keys_file = self.config_dir / "api_keys.yaml"
        self.api_key = os.getenv("GROQ_API_KEY")  # Try env first
        
        if not self.api_key and api_keys_file.exists():
            import yaml
            with open(api_keys_file) as f:
                keys = yaml.safe_load(f)
                # Try groq key first, then openrouter as fallback
                self.api_key = keys.get("groq", {}).get("api_key") or keys.get("openrouter", {}).get("api_key")
        
        if self.api_key:
            logger.info("🔑 Clé API Groq chargée")
    
    def _init_components(self, use_redis: bool):
        """Initialise les composants du pipeline."""
        # Scope Filter
        self.scope_filter = ScopeFilter(
            in_scope=self.scope_config.get("in_scope", []),
            out_of_scope=self.scope_config.get("out_of_scope", []),
            ignore_static=True
        )
        logger.info(f"🎯 Scope Filter: {len(self.scope_config.get('in_scope', []))} patterns in-scope")
        
        # Heuristics Engine
        self.heuristics = HeuristicsEngine()
        logger.info("📊 Heuristics Engine initialisé")
        
        # Deduplication
        # DedupEngine tente Redis automatiquement, sinon fallback mémoire
        self.dedup = DedupEngine()
        dedup_stats = self.dedup.stats()
        if dedup_stats.get("backend") == "redis":
            logger.info("🔄 Déduplication Redis activée")
        else:
            logger.info("🔄 Déduplication mémoire activée (fallback)")
        
        # AI Components (si activé et clé disponible)
        self.triage_engine: Optional[TriageEngine] = None
        self.strategist: Optional[StrategistEngine] = None
        
        if self.ai_enabled and self.api_key:
            try:
                self.ai_client = GroqClient(api_key=self.api_key)
                self.triage_engine = TriageEngine(client=self.ai_client, model="llama-3.1-8b-instant", use_rag=True)
                self.strategist = StrategistEngine(client=self.ai_client, model="llama-3.3-70b-versatile", use_rag=True)
                triage_rag = bool(self.triage_engine and self.triage_engine.use_rag)
                strategist_rag = bool(self.strategist and self.strategist.use_rag)
                if triage_rag or strategist_rag:
                    logger.info("🧠 AI Triage & Strategist activés (Groq + RAG)")
                else:
                    logger.info("🧠 AI Triage & Strategist activés (Groq, sans RAG)")
            except Exception as e:
                logger.error(f"❌ Erreur init AI: {e}")
        else:
            if not self.ai_enabled:
                logger.info("🧠 AI désactivée (mode heuristique uniquement)")
            elif not self.api_key:
                logger.warning("⚠️ Pas de clé API, AI désactivée")
        
        # Nuclei Scanner (si activé)
        self.nuclei_scanner: Optional[NucleiScanner] = None
        if self.nuclei_enabled:
            try:
                self.nuclei_scanner = get_nuclei_scanner()
                if self.nuclei_scanner.is_available:
                    self.nuclei_scanner.start_background_scanner()
                    logger.info("🔬 Nuclei Scanner activé (11,912 templates)")
                else:
                    self.nuclei_scanner = None
                    logger.warning("⚠️ Nuclei non disponible")
            except Exception as e:
                logger.warning(f"⚠️ Nuclei init error: {e}")
        
        # HTTP Runner pour exécuter les plans d'attaque
        self.http_runner: Optional[CustomHTTPRunner] = None
        if HTTP_RUNNER_AVAILABLE:
            try:
                self.http_runner = CustomHTTPRunner(
                    use_proxy=True,  # Utilise GonzoProxy résidentiel
                    rotate_ua_for_attacks=True,
                )
                logger.info("🚀 Custom HTTP Runner activé (GonzoProxy: ON)")
            except Exception as e:
                logger.warning(f"⚠️ HTTP Runner init error: {e}")
    
    def process_request(self, intercepted: InterceptedRequest) -> Optional[ScoredRequest]:
        """
        Traite une requête interceptée à travers le pipeline.
        
        Args:
            intercepted: Requête brute interceptée
            
        Returns:
            ScoredRequest si intéressante, None sinon
        """
        from ghost_hunter.core.interceptor.dedup import EndpointStatus
        
        self.stats["intercepted"] += 1
        
        # 0. SECURITY FINGERPRINTING (passive, sur toutes les requêtes)
        # Détecte WAF, CDN, anti-bot via headers/cookies
        if self.fingerprinter:
            try:
                self.fingerprinter.analyze_request(intercepted)
            except Exception as e:
                logger.debug(f"Fingerprint error: {e}")
        
        # 1. Filtrage Scope
        filtered = self.scope_filter.filter(intercepted)
        if not filtered.in_scope:
            # Tracker comme out of scope
            self.dedup.check(filtered)  # Enregistre l'endpoint
            self.dedup.update_endpoint_status(
                filtered, 
                EndpointStatus.OUT_OF_SCOPE, 
                f"Not matching scope patterns"
            )
            return None
        
        # Filtrer les assets statiques
        if filtered.is_static:
            self.dedup.check(filtered)
            self.dedup.update_endpoint_status(
                filtered,
                EndpointStatus.STATIC_ASSET,
                "Static asset (js/css/images)"
            )
            return None
        
        self.stats["in_scope"] += 1
        
        # 2. Déduplication INTELLIGENTE
        dedup_result = self.dedup.check(filtered)
        if dedup_result.is_duplicate:
            # Duplicate détecté - on ne touche PAS au status existant
            # L'endpoint garde son status actuel (triaged, interesting, tested, etc.)
            self.stats["deduplicated"] += 1
            return None
        
        self.stats["unique"] += 1
        
        # 3. Scoring Heuristique
        scored = self.heuristics.score(filtered)
        self.stats["scored"] += 1
        
        # Mettre à jour le tracking avec le score
        self.dedup.update_endpoint_status(
            filtered,
            EndpointStatus.TRIAGED if scored.score >= self.score_threshold else EndpointStatus.LOW_SCORE,
            f"Score: {scored.score}" if scored.score >= self.score_threshold else f"Low score: {scored.score} < {self.score_threshold}",
            score=scored.score,
            vulns=scored.potential_vulns
        )
        
        # 4. Nuclei scan en parallèle (async, ne bloque pas)
        if self.nuclei_scanner and self.nuclei_scanner.is_available:
            url = intercepted.url
            if self.nuclei_scanner.queue_url(url):
                self.stats["nuclei_scanned"] += 1
                logger.debug(f"🔬 Nuclei queued: {url[:60]}...")
        
        # Stocker pour le dashboard
        self.requests_store[intercepted.id] = {
            "request": intercepted,
            "filtered": filtered,
            "scored": scored,
            "triage": None,
            "nuclei_findings": [],
            "status": "scored",
            "endpoint_hash": dedup_result.hash,
            "endpoint_template": dedup_result.endpoint_template,
        }
        
        # Log des requêtes intéressantes (seuil abaissé à 15)
        if scored.score >= 15:
            logger.info(
                f"⭐ [{scored.score}] {intercepted.method} {dedup_result.endpoint_template} "
                f"- {scored.potential_vulns}"
            )
        
        return scored
    
    def triage_request(self, scored: ScoredRequest) -> Optional[TriageDecision]:
        """
        Two-Tier Triage IA d'une requête scorée.
        
        Tier 1: Quick triage sur TOUTES les requêtes (score >= 5)
        Tier 2: Full triage avec Knowledge Base si quick triage positif
        
        Args:
            scored: Requête avec score heuristique
            
        Returns:
            TriageDecision si IA disponible et intéressant, None sinon
        """
        if not self.triage_engine:
            return None
        
        # Tier 1: Quick triage (très rapide, ~100 tokens)
        # Seuil très bas pour ne rien rater
        if scored.score >= 5 and self.use_two_tier_triage:
            try:
                quick_result = self.triage_engine.quick_triage(scored)
                self.stats["quick_triaged"] += 1
                
                if not quick_result.get("worth_analyzing", False):
                    logger.debug(f"⏭️ Quick triage: skip - {quick_result.get('reason', 'N/A')}")
                    return None
                
                logger.debug(f"✅ Quick triage: pass - {quick_result.get('reason', 'N/A')}")
                
            except Exception as e:
                logger.warning(f"Quick triage error: {e}, continuing to full triage")
        
        # Si pas de two-tier, utiliser l'ancien seuil
        elif scored.score < self.score_threshold:
            return None
        
        # Tier 2: Full triage avec Knowledge Base
        try:
            decision = self.triage_engine.full_triage(scored)
            self.stats["full_triaged"] += 1
            self.stats["triaged"] += 1
            
            # Mettre à jour le store
            req_id = scored.request.request.id
            if req_id in self.requests_store:
                self.requests_store[req_id]["triage"] = decision
                self.requests_store[req_id]["status"] = "triaged"
            
            if decision.interesting:
                logger.info(
                    f"🎯 INTÉRESSANT [{decision.confidence}%]: "
                    f"{scored.request.request.method} {scored.request.request.path}"
                )
            
            return decision
            
        except Exception as e:
            logger.error(f"❌ Erreur triage: {e}")
            return None
    
    def get_nuclei_findings(self) -> list:
        """Récupère les findings Nuclei."""
        if not self.nuclei_scanner:
            return []
        
        # Récupérer les nouveaux findings
        findings = self.nuclei_scanner.get_findings()
        self.stats["nuclei_findings"] = len(findings)
        
        # Convertir en findings Ghost Hunter
        for nf in findings:
            if nf.template_id not in self.findings_store:
                self.findings_store[nf.template_id] = {
                    "id": nf.template_id,
                    "source": "nuclei",
                    "name": nf.name,
                    "severity": nf.severity,
                    "url": nf.url,
                    "matched_at": nf.matched_at,
                    "description": nf.description,
                    "timestamp": nf.timestamp
                }
                logger.warning(
                    f"🚨 NUCLEI FINDING [{nf.severity.upper()}]: {nf.name} - {nf.url}"
                )
        
        return findings
    
    def create_attack_plan(self, triage: TriageDecision) -> Optional[AttackPlan]:
        """
        Crée un plan d'attaque pour une requête intéressante.
        
        Args:
            triage: Décision de triage IA
            
        Returns:
            AttackPlan si stratégiste disponible
        """
        logger.info(f"🎯 create_attack_plan called - strategist={self.strategist is not None}, interesting={triage.interesting}")
        
        if not self.strategist:
            logger.error("❌ Strategist not available")
            return None
        
        if not triage.interesting:
            logger.warning(f"⚠️ Triage not interesting (interesting={triage.interesting})")
            return None
        
        try:
            logger.info(f"🧠 Calling strategist.create_plan for {triage.suggested_vulns}")
            plan = self.strategist.create_plan(triage)
            logger.info(
                f"📝 Plan d'attaque créé: {len(plan.payloads)} payloads, "
                f"{len(plan.injection_points)} points d'injection"
            )
            if not plan.payloads:
                logger.warning("⚠️ Plan créé mais SANS payloads!")
            return plan
            
        except Exception as e:
            logger.exception(f"❌ Erreur stratégie: {e}")
            return None
    
    async def execute_plan(self, plan: AttackPlan) -> tuple[list[Finding], list[dict]]:
        """
        Exécute un plan d'attaque et retourne les findings.
        
        Args:
            plan: Plan d'attaque généré par le Strategist
            
        Returns:
            Tuple (findings, test_details) - Liste des Findings et détails des tests
        """
        findings = []
        test_details = []
        
        if not self.http_runner:
            logger.warning("❌ HTTP Runner non disponible, impossible d'exécuter le plan")
            return findings, test_details
        
        if not plan.payloads:
            logger.warning("❌ Plan sans payloads, abandon")
            return findings, test_details
        
        try:
            from ghost_hunter.core.executor.tool_wrapper import ExecutionContext
            
            # Créer le contexte d'exécution
            context = ExecutionContext(
                plan=plan,
                dry_run=False,
            )
            
            logger.info(
                f"🚀 Exécution du plan: {plan.vuln_class} avec {len(plan.payloads)} payloads "
                f"sur {len(plan.injection_points)} points"
            )
            
            # Exécuter les tests
            result = await self.http_runner.execute(context)
            
            # Récupérer les détails des tests
            test_details = getattr(result, 'test_details', [])
            
            if result.success:
                if result.finding:
                    findings.append(result.finding)
                    self.add_finding(result.finding)
                    logger.info(f"🎯 Finding découvert: {result.finding.vuln_type}")
                else:
                    logger.info("✅ Plan exécuté, aucune vulnérabilité confirmée")
            else:
                logger.warning(f"⚠️ Exécution échouée: {result.error}")
                
        except Exception as e:
            logger.exception(f"❌ Erreur exécution plan: {e}")
        
        return findings, test_details
    
    def execute_plan_sync(self, plan: AttackPlan) -> tuple[list[Finding], list[dict]]:
        """
        Version synchrone de execute_plan pour l'API.
        Retourne (findings, test_details)
        """
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Si on est déjà dans une boucle async (FastAPI), créer une nouvelle
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        lambda: asyncio.new_event_loop().run_until_complete(self.execute_plan(plan))
                    )
                    return future.result(timeout=120)
            else:
                return loop.run_until_complete(self.execute_plan(plan))
        except Exception as e:
            logger.error(f"Sync execute error: {e}")
            # Fallback: créer une nouvelle boucle dans un thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    lambda: asyncio.new_event_loop().run_until_complete(self.execute_plan(plan))
                )
                return future.result(timeout=120)
    
    def add_finding(self, finding: Finding):
        """Ajoute un finding découvert."""
        self.stats["findings"] += 1
        self.findings_store[finding.id] = finding
        
        severity_emoji = {
            FindingSeverity.CRITICAL: "🚨",
            FindingSeverity.HIGH: "🔴",
            FindingSeverity.MEDIUM: "🟠",
            FindingSeverity.LOW: "🟡",
            FindingSeverity.INFO: "🔵"
        }
        
        logger.warning(
            f"{severity_emoji.get(finding.severity, '❓')} FINDING [{finding.severity.value}]: "
            f"{finding.vuln_type} @ {finding.endpoint}"
        )
        
        # Log le finding pour le path déterministe
        try:
            ai_logger = get_ai_logger()
            ai_logger.log_finding(
                endpoint=finding.endpoint,
                method=finding.method,
                vuln_class=finding.vuln_type,
                severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                payload=finding.payload_successful or "",
                injection_point=finding.injection_point or "",
                confidence=finding.confidence,
                host=finding.endpoint.split('/')[2] if '://' in finding.endpoint else "",
            )
        except Exception as e:
            logger.debug(f"Failed to log finding: {e}")
    
    def get_stats(self) -> dict:
        """Retourne les statistiques du pipeline."""
        elapsed = datetime.now().timestamp() - self.stats["start_time"]
        return {
            **self.stats,
            "elapsed_seconds": elapsed,
            "requests_per_minute": (self.stats["intercepted"] / elapsed * 60) if elapsed > 0 else 0
        }
    
    def print_stats(self):
        """Affiche les statistiques."""
        stats = self.get_stats()
        print("\n" + "=" * 60)
        print("📊 GHOST-HUNTER STATS")
        print("=" * 60)
        print(f"  Interceptées:    {stats['intercepted']}")
        print(f"  In-Scope:        {stats['in_scope']}")
        print(f"  Dédupliquées:    {stats['deduplicated']}")
        print(f"  Scorées:         {stats['scored']}")
        print(f"  Triées (IA):     {stats['triaged']}")
        print(f"  Findings:        {stats['findings']}")
        print(f"  Durée:           {stats['elapsed_seconds']:.1f}s")
        print(f"  Req/min:         {stats['requests_per_minute']:.1f}")
        print("=" * 60 + "\n")


# Instance globale du pipeline
_pipeline: Optional[GhostHunterPipeline] = None


def get_pipeline() -> GhostHunterPipeline:
    """Retourne l'instance du pipeline."""
    global _pipeline
    if _pipeline is None:
        _pipeline = GhostHunterPipeline()
    return _pipeline


def on_request_intercepted(intercepted: InterceptedRequest):
    """Callback appelé pour chaque requête interceptée."""
    pipeline = get_pipeline()
    
    # Traiter dans le pipeline
    scored = pipeline.process_request(intercepted)
    
    if scored and scored.score >= pipeline.score_threshold:
        # Triage IA si score suffisant
        triage = pipeline.triage_request(scored)
        
        if triage and triage.interesting:
            # Créer un plan d'attaque
            plan = pipeline.create_attack_plan(triage)
            # TODO: Exécuter le plan avec l'executor


def run_proxy(port: int = 8888):
    """Lance le proxy mitmproxy avec le pipeline connecté."""
    import subprocess
    
    proxy_script = Path(__file__).parent / "core" / "interceptor" / "proxy.py"
    
    logger.info(f"🚀 Lancement du proxy sur le port {port}")
    logger.info(f"📜 Script: {proxy_script}")
    
    # Lancer mitmdump
    cmd = ["mitmdump", "-s", str(proxy_script), "-p", str(port)]
    subprocess.run(cmd)


def run_dashboard(host: str = "0.0.0.0", port: int = 1010):
    """Lance le dashboard FastAPI."""
    import uvicorn
    from dashboard.api import create_app
    
    app = create_app()
    logger.info(f"🌐 Dashboard: http://{host}:{port}/dashboard")
    uvicorn.run(app, host=host, port=port)


def main():
    """Point d'entrée principal."""
    parser = argparse.ArgumentParser(description="Ghost-Hunter - AI Bug Bounty Agent")
    parser.add_argument("--proxy-port", type=int, default=8888, help="Port du proxy")
    parser.add_argument("--dashboard-port", type=int, default=1010, help="Port du dashboard")
    parser.add_argument("--no-ai", action="store_true", help="Désactiver l'IA")
    parser.add_argument("--redis", action="store_true", help="Utiliser Redis")
    parser.add_argument("--dashboard-only", action="store_true", help="Lancer uniquement le dashboard")
    parser.add_argument("--proxy-only", action="store_true", help="Lancer uniquement le proxy")
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   👻 GHOST-HUNTER - AI-Powered Bug Bounty Agent               ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialiser le pipeline
    global _pipeline
    _pipeline = GhostHunterPipeline(
        ai_enabled=not args.no_ai,
        use_redis=args.redis
    )
    
    if args.dashboard_only:
        run_dashboard(port=args.dashboard_port)
    elif args.proxy_only:
        run_proxy(port=args.proxy_port)
    else:
        # Lancer les deux en parallèle
        logger.info("🚀 Lancement de Ghost-Hunter (Proxy + Dashboard)")
        
        # Dashboard dans un thread
        dashboard_thread = threading.Thread(
            target=run_dashboard,
            kwargs={"port": args.dashboard_port},
            daemon=True
        )
        dashboard_thread.start()
        
        # Proxy dans le main thread
        run_proxy(port=args.proxy_port)


if __name__ == "__main__":
    main()

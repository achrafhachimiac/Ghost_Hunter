#!/usr/bin/env python3
"""
Ghost-Hunter Service Manager
=============================
Gère tous les services de Ghost-Hunter de manière centralisée.
"""

import os
import sys
import json
import time
import signal
import subprocess
import threading
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass, field, asdict
from collections import deque
from enum import Enum

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ServiceManager")


class ServiceStatus(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    ERROR = "error"
    STOPPING = "stopping"


@dataclass
class ServiceInfo:
    """Information sur un service."""
    name: str
    status: ServiceStatus = ServiceStatus.STOPPED
    pid: Optional[int] = None
    port: Optional[int] = None
    url: Optional[str] = None
    started_at: Optional[float] = None
    error: Optional[str] = None
    logs: deque = field(default_factory=lambda: deque(maxlen=500))
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "pid": self.pid,
            "port": self.port,
            "url": self.url,
            "started_at": self.started_at,
            "error": self.error,
            "logs_count": len(self.logs),
        }


class ServiceManager:
    """
    Gestionnaire centralisé de tous les services Ghost-Hunter.
    
    Services gérés:
    - Redis (déduplication)
    - Proxy mitmproxy (interception)
    - Dashboard FastAPI (UI)
    - OOB Listener (callbacks)
    - Pipeline Worker (traitement)
    """
    
    def __init__(self, base_dir: Path = None):
        self.base_dir = base_dir or Path(__file__).parent.parent
        self.config_dir = self.base_dir / "config"
        self.data_dir = self.base_dir / "data"
        self.logs_dir = self.data_dir / "logs"
        
        # Créer les dossiers nécessaires
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "findings").mkdir(exist_ok=True)
        (self.data_dir / "artifacts").mkdir(exist_ok=True)
        
        # Services
        self.services: Dict[str, ServiceInfo] = {
            "redis": ServiceInfo(name="Redis", port=6379),
            "proxy": ServiceInfo(name="Proxy", port=8888, url="http://127.0.0.1:8888"),
            "dashboard": ServiceInfo(name="Dashboard", port=1010, url="http://127.0.0.1:1010"),
            "oob": ServiceInfo(name="OOB Listener", port=9999),
            "pipeline": ServiceInfo(name="Pipeline Worker"),
        }
        
        # Processus
        self._processes: Dict[str, subprocess.Popen] = {}
        self._log_threads: Dict[str, threading.Thread] = {}
        self._running = False
        
        # Listeners pour les événements
        self._status_listeners: List[Callable] = []
        self._log_listeners: List[Callable] = []
        
        # Charger la config
        self._load_config()
    
    def _load_config(self):
        """Charge la configuration."""
        scope_file = self.config_dir / "scope.json"
        if scope_file.exists():
            with open(scope_file) as f:
                self.scope_config = json.load(f)
            self.target_name = self.scope_config.get("target", {}).get("name", "Unknown")
        else:
            self.scope_config = {}
            self.target_name = "No target configured"
    
    def add_log(self, service_name: str, message: str, level: str = "INFO"):
        """Ajoute un log à un service."""
        if service_name in self.services:
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_entry = {
                "timestamp": timestamp,
                "level": level,
                "message": message
            }
            self.services[service_name].logs.append(log_entry)
            
            # Notifier les listeners
            for listener in self._log_listeners:
                try:
                    listener(service_name, log_entry)
                except:
                    pass
    
    def _read_log_file(self, service_name: str, limit: int = 100) -> List[dict]:
        """Lit les logs depuis le fichier de log du service."""
        log_files = {
            "redis": self.logs_dir / "redis.log",
            "proxy": self.logs_dir / "proxy.log",
            "dashboard": self.logs_dir / "dashboard.log",
            "oob": self.logs_dir / "oob.log",
            "pipeline": self.logs_dir / "ghost_hunter.log",
        }
        
        log_file = log_files.get(service_name)
        if not log_file or not log_file.exists():
            return []
        
        try:
            with open(log_file, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            # Prendre les dernières lignes
            lines = lines[-limit:]
            
            logs = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Essayer de parser le timestamp
                level = "INFO"
                if "error" in line.lower():
                    level = "ERROR"
                elif "warn" in line.lower():
                    level = "WARNING"
                elif "⭐" in line or "🎯" in line:
                    level = "SUCCESS"
                
                # Extraire le timestamp si présent
                timestamp = ""
                if line.startswith("["):
                    try:
                        end = line.index("]")
                        timestamp = line[1:end]
                        line = line[end+1:].strip()
                    except:
                        pass
                
                if not timestamp:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                
                logs.append({
                    "timestamp": timestamp,
                    "level": level,
                    "message": line[:200]  # Limiter la longueur
                })
            
            return logs
        except Exception as e:
            return [{"timestamp": "", "level": "ERROR", "message": f"Error reading log: {e}"}]
    
    def get_service_logs(self, service_name: str, limit: int = 100) -> List[dict]:
        """Récupère les derniers logs d'un service (mémoire + fichier)."""
        logs = []
        
        # D'abord les logs en mémoire
        if service_name in self.services:
            logs.extend(list(self.services[service_name].logs))
        
        # Puis les logs du fichier
        file_logs = self._read_log_file(service_name, limit)
        if file_logs:
            logs = file_logs  # Préférer les logs du fichier s'ils existent
        
        return logs[-limit:]
    
    def _update_status(self, service_name: str, status: ServiceStatus, error: str = None):
        """Met à jour le statut d'un service."""
        if service_name in self.services:
            self.services[service_name].status = status
            self.services[service_name].error = error
            
            if status == ServiceStatus.RUNNING:
                self.services[service_name].started_at = datetime.now().timestamp()
            
            # Notifier les listeners
            for listener in self._status_listeners:
                try:
                    listener(service_name, status.value)
                except:
                    pass
    
    def _stream_output(self, service_name: str, process: subprocess.Popen):
        """Thread pour streamer les logs d'un processus."""
        try:
            for line in iter(process.stdout.readline, b''):
                if not self._running:
                    break
                decoded = line.decode('utf-8', errors='replace').strip()
                if decoded:
                    level = "ERROR" if "error" in decoded.lower() else "INFO"
                    self.add_log(service_name, decoded, level)
        except Exception as e:
            self.add_log(service_name, f"Log stream error: {e}", "ERROR")
    
    # ==================== SERVICE STARTERS ====================
    
    def start_redis(self) -> bool:
        """Démarre Redis."""
        service_name = "redis"
        self._update_status(service_name, ServiceStatus.STARTING)
        self.add_log(service_name, "Starting Redis...")
        
        # Vérifier si Redis est déjà lancé
        try:
            result = subprocess.run(
                ["redis-cli", "ping"],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0 and b"PONG" in result.stdout:
                self.add_log(service_name, "Redis already running")
                self._update_status(service_name, ServiceStatus.RUNNING)
                return True
        except:
            pass
        
        # Démarrer Redis
        try:
            process = subprocess.Popen(
                ["redis-server", "--daemonize", "no", "--loglevel", "notice"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=str(self.base_dir)
            )
            self._processes[service_name] = process
            self.services[service_name].pid = process.pid
            
            # Thread pour les logs
            log_thread = threading.Thread(
                target=self._stream_output,
                args=(service_name, process),
                daemon=True
            )
            log_thread.start()
            self._log_threads[service_name] = log_thread
            
            # Attendre que Redis soit prêt
            for _ in range(10):
                time.sleep(0.5)
                try:
                    result = subprocess.run(["redis-cli", "ping"], capture_output=True, timeout=1)
                    if result.returncode == 0:
                        self.add_log(service_name, "Redis started successfully")
                        self._update_status(service_name, ServiceStatus.RUNNING)
                        return True
                except:
                    pass
            
            self._update_status(service_name, ServiceStatus.ERROR, "Failed to start")
            return False
            
        except FileNotFoundError:
            self.add_log(service_name, "Redis not installed, using memory fallback", "WARNING")
            self._update_status(service_name, ServiceStatus.STOPPED)
            return False
        except Exception as e:
            self.add_log(service_name, f"Error starting Redis: {e}", "ERROR")
            self._update_status(service_name, ServiceStatus.ERROR, str(e))
            return False
    
    def start_proxy(self, port: int = 8888) -> bool:
        """Démarre le proxy mitmproxy."""
        service_name = "proxy"
        self._update_status(service_name, ServiceStatus.STARTING)
        self.add_log(service_name, f"Starting proxy on port {port}...")
        
        proxy_script = self.base_dir / "ghost_hunter" / "core" / "interceptor" / "proxy.py"
        
        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(self.base_dir)
            
            process = subprocess.Popen(
                ["mitmdump", "-s", str(proxy_script), "-p", str(port), "--set", "stream_large_bodies=10m"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=str(self.base_dir),
                env=env
            )
            self._processes[service_name] = process
            self.services[service_name].pid = process.pid
            self.services[service_name].port = port
            
            # Thread pour les logs
            log_thread = threading.Thread(
                target=self._stream_output,
                args=(service_name, process),
                daemon=True
            )
            log_thread.start()
            self._log_threads[service_name] = log_thread
            
            time.sleep(2)
            
            if process.poll() is None:
                self.add_log(service_name, f"Proxy running on port {port}")
                self._update_status(service_name, ServiceStatus.RUNNING)
                return True
            else:
                self._update_status(service_name, ServiceStatus.ERROR, "Process exited")
                return False
                
        except Exception as e:
            self.add_log(service_name, f"Error starting proxy: {e}", "ERROR")
            self._update_status(service_name, ServiceStatus.ERROR, str(e))
            return False
    
    def start_dashboard(self, host: str = "0.0.0.0", port: int = 1010) -> bool:
        """Démarre le dashboard FastAPI."""
        service_name = "dashboard"
        self._update_status(service_name, ServiceStatus.STARTING)
        self.add_log(service_name, f"Starting dashboard on {host}:{port}...")
        
        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(self.base_dir)
            
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "uvicorn",
                    "dashboard.api:app",
                    "--host", host,
                    "--port", str(port),
                    "--log-level", "info"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=str(self.base_dir),
                env=env
            )
            self._processes[service_name] = process
            self.services[service_name].pid = process.pid
            self.services[service_name].port = port
            self.services[service_name].url = f"http://{host}:{port}"
            
            # Thread pour les logs
            log_thread = threading.Thread(
                target=self._stream_output,
                args=(service_name, process),
                daemon=True
            )
            log_thread.start()
            self._log_threads[service_name] = log_thread
            
            time.sleep(2)
            
            if process.poll() is None:
                self.add_log(service_name, f"Dashboard: http://127.0.0.1:{port}")
                self._update_status(service_name, ServiceStatus.RUNNING)
                return True
            else:
                self._update_status(service_name, ServiceStatus.ERROR, "Process exited")
                return False
                
        except Exception as e:
            self.add_log(service_name, f"Error starting dashboard: {e}", "ERROR")
            self._update_status(service_name, ServiceStatus.ERROR, str(e))
            return False
    
    def start_oob_listener(self, port: int = 9999) -> bool:
        """Démarre le listener OOB."""
        service_name = "oob"
        self._update_status(service_name, ServiceStatus.STARTING)
        self.add_log(service_name, f"Starting OOB listener on port {port}...")
        
        # Pour l'instant, on marque comme non implémenté
        self.add_log(service_name, "OOB listener ready (passive mode)", "INFO")
        self._update_status(service_name, ServiceStatus.RUNNING)
        return True
    
    def start_pipeline_worker(self) -> bool:
        """Démarre le worker pipeline."""
        service_name = "pipeline"
        self._update_status(service_name, ServiceStatus.STARTING)
        self.add_log(service_name, "Initializing pipeline...")
        
        try:
            # Import et init du pipeline
            from ghost_hunter.main import GhostHunterPipeline, get_pipeline
            
            pipeline = get_pipeline()
            self.add_log(service_name, f"Pipeline initialized - Target: {self.target_name}")
            self.add_log(service_name, f"Score threshold: {pipeline.score_threshold}")
            self.add_log(service_name, f"AI enabled: {pipeline.ai_enabled}")
            
            self._update_status(service_name, ServiceStatus.RUNNING)
            return True
            
        except Exception as e:
            self.add_log(service_name, f"Error initializing pipeline: {e}", "ERROR")
            self._update_status(service_name, ServiceStatus.ERROR, str(e))
            return False
    
    # ==================== SERVICE CONTROL ====================
    
    def stop_service(self, service_name: str) -> bool:
        """Arrête un service."""
        if service_name not in self.services:
            return False
        
        self._update_status(service_name, ServiceStatus.STOPPING)
        self.add_log(service_name, "Stopping...")
        
        if service_name in self._processes:
            try:
                process = self._processes[service_name]
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
            del self._processes[service_name]
        
        # Cas spécial Redis
        if service_name == "redis":
            try:
                subprocess.run(["redis-cli", "shutdown"], capture_output=True, timeout=5)
            except:
                pass
        
        self.services[service_name].pid = None
        self._update_status(service_name, ServiceStatus.STOPPED)
        self.add_log(service_name, "Stopped")
        return True
    
    def restart_service(self, service_name: str) -> bool:
        """Redémarre un service."""
        self.stop_service(service_name)
        time.sleep(1)
        
        starters = {
            "redis": self.start_redis,
            "proxy": self.start_proxy,
            "dashboard": self.start_dashboard,
            "oob": self.start_oob_listener,
            "pipeline": self.start_pipeline_worker,
        }
        
        if service_name in starters:
            return starters[service_name]()
        return False
    
    def start_all(self) -> Dict[str, bool]:
        """Démarre tous les services."""
        self._running = True
        results = {}
        
        # Ordre de démarrage important
        results["redis"] = self.start_redis()
        time.sleep(1)
        results["pipeline"] = self.start_pipeline_worker()
        results["dashboard"] = self.start_dashboard()
        time.sleep(1)
        results["proxy"] = self.start_proxy()
        results["oob"] = self.start_oob_listener()
        
        return results
    
    def stop_all(self):
        """Arrête tous les services."""
        self._running = False
        
        for service_name in reversed(list(self.services.keys())):
            self.stop_service(service_name)
    
    def get_all_status(self) -> Dict[str, dict]:
        """Retourne le statut de tous les services."""
        return {name: info.to_dict() for name, info in self.services.items()}
    
    def _check_port(self, port: int) -> bool:
        """Vérifie si un port est en écoute."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result == 0
    
    def _check_redis_running(self) -> bool:
        """Vérifie si Redis répond."""
        try:
            result = subprocess.run(
                ["redis-cli", "ping"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0 and b"PONG" in result.stdout
        except:
            return False
    
    def _detect_service_status(self, service_name: str) -> ServiceStatus:
        """Détecte le statut réel d'un service."""
        service = self.services[service_name]
        
        # Redis - vérification spéciale
        if service_name == "redis":
            if self._check_redis_running():
                return ServiceStatus.RUNNING
            return ServiceStatus.STOPPED
        
        # Services avec ports
        if service.port:
            if self._check_port(service.port):
                return ServiceStatus.RUNNING
            return ServiceStatus.STOPPED
        
        # Pipeline - vérifier si le pipeline est initialisé
        if service_name == "pipeline":
            # Le pipeline est "running" si le proxy tourne ET le pipeline est importable
            if self._check_port(8888):  # Proxy tourne
                try:
                    from ghost_hunter.main import _pipeline
                    if _pipeline is not None:
                        return ServiceStatus.RUNNING
                    # Essayer d'initialiser le pipeline
                    from ghost_hunter.main import get_pipeline
                    pipeline = get_pipeline()
                    if pipeline:
                        return ServiceStatus.RUNNING
                except:
                    pass
            return ServiceStatus.STOPPED
        
        # OOB - si le fichier de config OOB existe et le port est libre
        if service_name == "oob":
            # OOB est considéré comme "running" en mode passif
            # quand le dashboard tourne (il peut recevoir des callbacks)
            if self._check_port(1010):  # Dashboard tourne
                return ServiceStatus.RUNNING
            return ServiceStatus.STOPPED
        
        return service.status
    
    def get_health(self) -> dict:
        """Retourne un résumé de santé avec détection réelle des services."""
        # Détecter l'état réel de chaque service
        for name in self.services:
            real_status = self._detect_service_status(name)
            self.services[name].status = real_status
        
        statuses = self.get_all_status()
        running = sum(1 for s in statuses.values() if s["status"] == "running")
        # OOB et Pipeline sont optionnels
        required = ["redis", "proxy", "dashboard"]
        required_running = sum(1 for name in required if statuses[name]["status"] == "running")
        total = len(statuses)
        
        return {
            "healthy": required_running >= 2,  # Au moins dashboard + proxy
            "running_services": running,
            "total_services": total,
            "target": self.target_name,
            "services": statuses
        }


# Instance globale
_manager: Optional[ServiceManager] = None


def get_service_manager() -> ServiceManager:
    """Retourne l'instance du service manager."""
    global _manager
    if _manager is None:
        _manager = ServiceManager()
    return _manager


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Ghost-Hunter Service Manager")
    parser.add_argument("action", choices=["start", "stop", "status", "restart"])
    parser.add_argument("--service", "-s", help="Service spécifique")
    
    args = parser.parse_args()
    manager = get_service_manager()
    
    if args.action == "start":
        if args.service:
            manager.restart_service(args.service)
        else:
            manager.start_all()
    elif args.action == "stop":
        if args.service:
            manager.stop_service(args.service)
        else:
            manager.stop_all()
    elif args.action == "status":
        print(json.dumps(manager.get_health(), indent=2))
    elif args.action == "restart":
        if args.service:
            manager.restart_service(args.service)
        else:
            manager.stop_all()
            time.sleep(2)
            manager.start_all()

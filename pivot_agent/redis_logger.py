"""
Redis Logger for Pivot Agent Live Thoughts
==========================================
Publishes agent state and reasoning to Redis for real-time dashboard monitoring.

Usage:
    from pivot_agent.redis_logger import AgentLogger
    
    logger = AgentLogger(log_id="abc123")
    logger.log_thought("analyzer", "Analyzing IDOR candidates...")
    logger.log_action("executor", "Replaying request with mutated ID")
    logger.log_finding("pivoter", "IDOR CONFIRMED", severity="high")
"""

import json
import time
from datetime import datetime
from typing import Any, Optional, Literal
from dataclasses import dataclass, asdict
from enum import Enum

from .config import REDIS_HOST, REDIS_PORT, REDIS_DB, AGENT_LOGS_CHANNEL


class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"
    CRITICAL = "critical"


class StopAgentException(Exception):
    """Exception raised when agent should stop (emergency stop)"""
    pass


class LogType(str, Enum):
    THOUGHT = "thought"       # Agent reasoning
    ACTION = "action"         # Agent taking action
    RESULT = "result"         # Action result
    FINDING = "finding"       # Security finding
    STATE = "state"           # State update
    ERROR = "error"           # Error occurred
    PROGRESS = "progress"     # Progress update


@dataclass
class AgentLogEntry:
    """A single log entry from the agent"""
    timestamp: float
    node: str                 # analyzer, researcher, strategist, executor, pivoter
    type: str                 # thought, action, result, finding, state, error
    level: str                # debug, info, warning, error, success
    message: str              # Human-readable message
    data: Optional[dict] = None  # Structured data
    iteration: int = 0
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AgentLogger:
    """
    Redis-based logger for live agent monitoring.
    
    Publishes to Redis channel: agent:logs:{log_id}
    Dashboard can subscribe to see real-time agent thoughts.
    """
    
    def __init__(
        self, 
        log_id: str,
        host: str = REDIS_HOST,
        port: int = REDIS_PORT,
        db: int = REDIS_DB
    ):
        self.log_id = log_id
        self.channel = f"{AGENT_LOGS_CHANNEL}:{log_id}"
        self.iteration = 0
        
        self._redis = None
        self._connected = False
        
        self._stop_key = f"agent:stop:{log_id}"
        
        try:
            import redis
            self._redis = redis.Redis(
                host=host,
                port=port,
                db=db,
                decode_responses=True,
                socket_timeout=2
            )
            self._redis.ping()
            self._connected = True
            # Clear any previous stop flag on init
            self._redis.delete(self._stop_key)
        except Exception as e:
            print(f"[AgentLogger] Redis connection failed: {e}")
            self._connected = False
    
    @property
    def connected(self) -> bool:
        return self._connected and self._redis is not None
    
    # ==================== Stop Flag Management ====================
    
    def set_stop_flag(self):
        """Set the stop flag to signal agent to stop"""
        if self.connected:
            try:
                self._redis.set(self._stop_key, "1", ex=3600)  # Expire in 1 hour
                self.log("system", "🛑 EMERGENCY STOP requested!", LogType.STATE, LogLevel.CRITICAL)
            except Exception as e:
                print(f"[AgentLogger] Failed to set stop flag: {e}")
    
    def clear_stop_flag(self):
        """Clear the stop flag"""
        if self.connected:
            try:
                self._redis.delete(self._stop_key)
            except Exception:
                pass
    
    def clear_all_logs(self):
        """
        Clear all logs for this agent session.
        Removes: history, http_requests, llm_responses, and stop flag.
        """
        if not self.connected:
            return False
        
        try:
            keys_to_delete = [
                f"{self.channel}:history",
                f"{self.channel}:http_requests", 
                f"{self.channel}:llm_responses",
                self._stop_key,
            ]
            
            for key in keys_to_delete:
                self._redis.delete(key)
            
            return True
        except Exception as e:
            print(f"[AgentLogger] Failed to clear logs: {e}")
            return False
    
    @classmethod
    def clear_all_agent_logs(cls, host: str = REDIS_HOST, port: int = REDIS_PORT, db: int = REDIS_DB):
        """
        Class method to clear ALL agent logs (all sessions).
        Use with caution - clears everything!
        """
        try:
            import redis
            r = redis.Redis(host=host, port=port, db=db, decode_responses=True)
            
            # Find and delete all agent-related keys
            patterns = [
                f"{AGENT_LOGS_CHANNEL}:*",  # All log channels
                "agent:stop:*",              # All stop flags
            ]
            
            deleted_count = 0
            for pattern in patterns:
                keys = r.keys(pattern)
                if keys:
                    deleted_count += r.delete(*keys)
            
            return deleted_count
        except Exception as e:
            print(f"[AgentLogger] Failed to clear all logs: {e}")
            return 0
    
    def is_stopped(self) -> bool:
        """Check if stop flag is set"""
        if not self.connected:
            return False
        try:
            return self._redis.exists(self._stop_key) > 0
        except Exception:
            return False
    
    def check_stop(self, node: str = "system"):
        """
        Check if stop flag is set and raise exception if so.
        Call this at the beginning of each node to allow interruption.
        """
        if self.is_stopped():
            self.log(node, "🛑 Agent stopped by user request", LogType.STATE, LogLevel.WARNING)
            raise StopAgentException("Agent stopped by user request")
    
    def set_iteration(self, iteration: int):
        """Update current iteration number"""
        self.iteration = iteration
    
    def _publish(self, entry: AgentLogEntry):
        """Publish log entry to Redis channel"""
        if not self.connected:
            # Fallback to console
            print(f"[{entry.node}] {entry.message}")
            return
        
        try:
            # Publish to channel (real-time)
            self._redis.publish(self.channel, entry.to_json())
            
            # Also store in list for history (last 200 entries for logs)
            history_key = f"{self.channel}:history"
            self._redis.lpush(history_key, entry.to_json())
            self._redis.ltrim(history_key, 0, 199)  # Keep last 200
            
            # Set expiry (24 hours)
            self._redis.expire(history_key, 86400)
            
        except Exception as e:
            print(f"[AgentLogger] Publish error: {e}")
    
    def log_http_request_detail(self, step: str, method: str, url: str, headers: dict, 
                                 body: str, status: int, response_body: str):
        """Store detailed HTTP request/response for debugging panel"""
        if not self.connected:
            return
        
        try:
            http_key = f"{self.channel}:http_requests"
            request_data = {
                "timestamp": time.time(),
                "step": step,
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
                "status": status,
                "response_body": response_body[:5000] if response_body else "",  # Limit size
                "response_preview": response_body[:500] if response_body else "",
                "iteration": self.iteration
            }
            self._redis.lpush(http_key, json.dumps(request_data))
            self._redis.ltrim(http_key, 0, 49)  # Keep last 50 requests
            self._redis.expire(http_key, 86400)
        except Exception as e:
            print(f"[AgentLogger] HTTP log error: {e}")
    
    def log_llm_response(self, node: str, model: str, prompt: str, response: str, 
                         tokens: int = 0, cost: float = 0):
        """Store LLM response for debugging panel (full, not truncated)"""
        if not self.connected:
            return
        
        try:
            llm_key = f"{self.channel}:llm_responses"
            llm_data = {
                "timestamp": time.time(),
                "node": node,
                "model": model,
                "prompt": prompt[:10000] if prompt else "",  # Truncate prompt to 10k
                "response": response,  # Full response, no truncation!
                "content": response,   # Alias
                "tokens": tokens,
                "cost": cost,
                "iteration": self.iteration
            }
            self._redis.lpush(llm_key, json.dumps(llm_data))
            self._redis.ltrim(llm_key, 0, 19)  # Keep last 20 LLM calls
            self._redis.expire(llm_key, 86400)
        except Exception as e:
            print(f"[AgentLogger] LLM log error: {e}")
    
    def _persist_finding(self, finding: str, severity: str, data: Optional[dict] = None):
        """Persist finding to disk (survives restart)"""
        import os
        import uuid
        
        findings_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "findings")
        os.makedirs(findings_dir, exist_ok=True)
        
        finding_record = {
            "id": str(uuid.uuid4())[:8],
            "log_id": self.log_id,
            "vuln_type": finding,
            "severity": severity,
            "timestamp": time.time(),
            "created_at": datetime.now().isoformat(),
            "source": "pivot_agent",
            "iteration": self.iteration,
            **(data or {})
        }
        
        filename = f"pivot_{self.log_id}_{finding_record['id']}.json"
        filepath = os.path.join(findings_dir, filename)
        
        try:
            with open(filepath, "w") as f:
                json.dump(finding_record, f, indent=2)
        except Exception as e:
            print(f"[AgentLogger] Failed to persist finding: {e}")
    
    def log(
        self,
        node: str,
        message: str,
        log_type: LogType = LogType.THOUGHT,
        level: LogLevel = LogLevel.INFO,
        data: Optional[dict] = None
    ):
        """Generic log method"""
        entry = AgentLogEntry(
            timestamp=time.time(),
            node=node,
            type=log_type.value,
            level=level.value,
            message=message,
            data=data,
            iteration=self.iteration
        )
        self._publish(entry)
    
    # ==================== Convenience Methods ====================
    
    def log_thought(self, node: str, thought: str, data: Optional[dict] = None):
        """Log agent reasoning/thought process"""
        self.log(node, thought, LogType.THOUGHT, LogLevel.INFO, data)
    
    def log_action(self, node: str, action: str, data: Optional[dict] = None):
        """Log agent taking an action"""
        self.log(node, action, LogType.ACTION, LogLevel.INFO, data)
    
    def log_result(self, node: str, result: str, data: Optional[dict] = None):
        """Log action result"""
        self.log(node, result, LogType.RESULT, LogLevel.INFO, data)
    
    def log_finding(
        self, 
        node: str, 
        finding: str, 
        severity: str = "medium",
        data: Optional[dict] = None
    ):
        """Log security finding and persist to disk"""
        level = LogLevel.SUCCESS if severity in ["high", "critical"] else LogLevel.WARNING
        finding_data = {
            "severity": severity,
            **(data or {})
        }
        self.log(node, f"🎯 FINDING: {finding}", LogType.FINDING, level, finding_data)
        
        # Persist finding to disk for survival across restarts
        self._persist_finding(finding, severity, data)
    
    def log_error(self, node: str, error: str, data: Optional[dict] = None):
        """Log error"""
        self.log(node, f"❌ ERROR: {error}", LogType.ERROR, LogLevel.ERROR, data)
    
    def log_warning(self, node: str, warning: str, data: Optional[dict] = None):
        """Log warning"""
        self.log(node, f"⚠️ WARNING: {warning}", LogType.WARNING if hasattr(LogType, 'WARNING') else LogType.THOUGHT, LogLevel.WARNING if hasattr(LogLevel, 'WARNING') else LogLevel.INFO, data)
    
    def log_http_request(self, node: str, method: str, url: str, headers: dict, body: str, status: int, response_preview: str):
        """Log detailed HTTP request/response for debugging"""
        # Mask sensitive headers for display
        safe_headers = {k: ("***" if k.lower() in ("authorization", "cookie", "x-csrf-token") else v) for k, v in headers.items()}
        
        request_log = f"""
📤 HTTP REQUEST:
   {method} {url}
   Headers: {safe_headers}
   Body: {body[:200] if body else 'None'}
📥 RESPONSE: {status}
   Preview: {response_preview[:300]}"""
        
        self.log(node, request_log.strip(), LogType.ACTION, LogLevel.DEBUG, {
            "method": method,
            "url": url,
            "headers": list(headers.keys()),
            "status": status
        })
    
    def log_state(self, node: str, state_summary: dict):
        """Log state update"""
        self.log(node, "State updated", LogType.STATE, LogLevel.DEBUG, state_summary)
    
    def log_progress(self, node: str, current: int, total: int, message: str = ""):
        """Log progress update"""
        self.log(node, message or f"Progress: {current}/{total}", LogType.PROGRESS, LogLevel.INFO, {
            "current": current,
            "total": total,
            "percentage": round(current / total * 100) if total > 0 else 0
        })
    
    # ==================== Node-Specific Logging ====================
    
    def analyzer_start(self, findings_count: int):
        """Log analyzer starting"""
        self.log_thought("analyzer", f"🔍 Analyzing {findings_count} findings for attack vectors...", {
            "findings_count": findings_count
        })
    
    def analyzer_found_targets(self, targets: list):
        """Log targets found by analyzer"""
        self.log_result("analyzer", f"📍 Found {len(targets)} potential targets", {
            "targets": [t.get("endpoint", t.get("url", "")) for t in targets[:5]]
        })
    
    def researcher_enriching(self, target: str):
        """Log researcher enriching target"""
        self.log_thought("researcher", f"📚 Enriching target with knowledge base: {target}")
    
    def strategist_planning(self, attack_type: str):
        """Log strategist creating plan"""
        self.log_thought("strategist", f"🎯 Creating attack strategy for: {attack_type}")
    
    def executor_running(self, method: str, url: str):
        """Log executor running request"""
        self.log_action("executor", f"🚀 Executing {method} {url[:60]}...", {
            "method": method,
            "url": url
        })
    
    def executor_replay(self, original_id: str, param: str, new_value: str):
        """Log executor replaying with mutation"""
        self.log_action("executor", f"🔄 Replay with mutation: {param} → {new_value[:20]}...", {
            "original_request_id": original_id,
            "mutated_param": param,
            "new_value": new_value
        })
    
    def executor_result(self, status_code: int, suspicious: bool = False):
        """Log executor result"""
        emoji = "⚠️" if suspicious else "✓"
        level = LogLevel.WARNING if suspicious else LogLevel.INFO
        self.log("executor", f"{emoji} Response: {status_code}", LogType.RESULT, level, {
            "status_code": status_code,
            "suspicious": suspicious
        })
    
    def pivoter_analyzing(self, extracted_count: int):
        """Log pivoter analyzing results"""
        self.log_thought("pivoter", f"🔄 Analyzing response, found {extracted_count} pivotable IDs")
    
    def pivoter_decision(self, decision: str, reasoning: str):
        """Log pivoter decision"""
        emoji = {"continue": "➡️", "replay": "🔄", "end": "✅"}.get(decision, "❓")
        self.log_result("pivoter", f"{emoji} Decision: {decision.upper()} - {reasoning}", {
            "decision": decision,
            "reasoning": reasoning
        })
    
    def idor_detected(self, param: str, original_value: str, new_value: str, evidence: str):
        """Log IDOR detection"""
        self.log_finding("pivoter", f"IDOR on '{param}': {evidence}", severity="high", data={
            "param": param,
            "original_value": original_value,
            "new_value": new_value,
            "evidence": evidence
        })
    
    # ==================== Session Management ====================
    
    def session_start(self, target: str, goal: Optional[str] = None):
        """Log session start"""
        self.log("system", f"🚀 Pivot Agent started - Target: {target}", LogType.STATE, LogLevel.INFO, {
            "target": target,
            "goal": goal,
            "started_at": datetime.now().isoformat()
        })
    
    def session_end(self, findings_count: int, iterations: int):
        """Log session end"""
        self.log("system", f"🏁 Session complete - {findings_count} findings in {iterations} iterations", 
                 LogType.STATE, LogLevel.SUCCESS if findings_count > 0 else LogLevel.INFO, {
            "findings_count": findings_count,
            "iterations": iterations,
            "ended_at": datetime.now().isoformat()
        })
    
    def get_history(self, limit: int = 50) -> list[dict]:
        """Get log history for this session"""
        if not self.connected:
            return []
        
        try:
            history_key = f"{self.channel}:history"
            entries = self._redis.lrange(history_key, 0, limit - 1)
            return [json.loads(e) for e in entries]
        except Exception:
            return []
    
    def get_http_requests(self, limit: int = 50) -> list[dict]:
        """Get HTTP request history for this session"""
        if not self.connected:
            return []
        
        try:
            http_key = f"{self.channel}:http_requests"
            entries = self._redis.lrange(http_key, 0, limit - 1)
            return [json.loads(e) for e in entries]
        except Exception:
            return []
    
    def get_llm_responses(self, limit: int = 20) -> list[dict]:
        """Get LLM response history for this session"""
        if not self.connected:
            return []
        
        try:
            llm_key = f"{self.channel}:llm_responses"
            entries = self._redis.lrange(llm_key, 0, limit - 1)
            return [json.loads(e) for e in entries]
        except Exception:
            return []


# ==================== Global Logger Instance ====================

_agent_logger: Optional[AgentLogger] = None


def get_agent_logger(log_id: Optional[str] = None) -> AgentLogger:
    """Get or create agent logger instance"""
    global _agent_logger
    
    if log_id is not None:
        _agent_logger = AgentLogger(log_id)
    elif _agent_logger is None:
        _agent_logger = AgentLogger("default")
    
    return _agent_logger


def set_agent_logger(log_id: str) -> AgentLogger:
    """Set a new agent logger with specific log_id"""
    global _agent_logger
    _agent_logger = AgentLogger(log_id)
    return _agent_logger


def stop_agent(log_id: str) -> bool:
    """Stop a running agent by setting its stop flag"""
    try:
        import redis
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True
        )
        stop_key = f"agent:stop:{log_id}"
        r.set(stop_key, "1", ex=3600)
        
        # Also publish stop message to channel
        channel = f"{AGENT_LOGS_CHANNEL}:{log_id}"
        stop_entry = AgentLogEntry(
            timestamp=time.time(),
            node="system",
            type=LogType.STATE.value,
            level=LogLevel.CRITICAL.value,
            message="🛑 EMERGENCY STOP activated!",
            data={"stopped_by": "user"},
            iteration=0
        )
        r.publish(channel, stop_entry.to_json())
        
        # Store in history
        history_key = f"{channel}:history"
        r.lpush(history_key, stop_entry.to_json())
        
        return True
    except Exception as e:
        print(f"[stop_agent] Error: {e}")
        return False

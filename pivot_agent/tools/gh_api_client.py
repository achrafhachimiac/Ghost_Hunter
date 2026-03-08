"""
Ghost-Hunter API Client
Async wrapper for Ghost-Hunter's REST API
"""

import httpx
from typing import Any, Optional
from ..config import GHOST_HUNTER_API_URL, REQUEST_TIMEOUT


class GhostHunterClient:
    """Async client for Ghost-Hunter API"""
    
    def __init__(self, base_url: str = GHOST_HUNTER_API_URL):
        self.base_url = base_url.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=REQUEST_TIMEOUT)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
    
    @property
    def client(self) -> httpx.AsyncClient:
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context manager.")
        return self._client
    
    # =========================================================================
    # READ OPERATIONS
    # =========================================================================
    
    async def get_logs(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """Get recent traffic requests from interceptor (uses /api/requests)"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/requests",
                params={"limit": limit, "offset": offset}
            )
            response.raise_for_status()
            return response.json()
        except Exception:
            # Fallback: return empty list if route doesn't exist
            return []
    
    async def get_related_requests(self, endpoint_path: str, limit: int = 20) -> list[dict[str, Any]]:
        """
        Get requests related to a specific endpoint path.
        Useful for finding similar requests with different params/auth states.
        """
        try:
            # Get all requests and filter by path
            all_logs = await self.get_logs(limit=200)
            related = []
            
            # Normalize the search path
            search_path = endpoint_path.split("?")[0]  # Remove query params
            
            for log in all_logs:
                log_path = log.get("path", "") or log.get("url", "").split("?")[0]
                # Match by path template or exact path
                if search_path in log_path or log_path in search_path:
                    related.append(log)
                    if len(related) >= limit:
                        break
            
            return related
        except Exception:
            return []
    
    async def get_requests_by_host(self, host: str, limit: int = 50) -> list[dict[str, Any]]:
        """Get all captured requests for a specific host"""
        try:
            all_logs = await self.get_logs(limit=500)
            return [
                log for log in all_logs 
                if log.get("host", "") == host
            ][:limit]
        except Exception:
            return []
    
    async def search_requests(self, query: str, limit: int = 30) -> list[dict[str, Any]]:
        """
        Search requests by URL, path, or response content.
        Useful when the agent needs to find specific patterns.
        """
        try:
            all_logs = await self.get_logs(limit=300)
            results = []
            query_lower = query.lower()
            
            for log in all_logs:
                # Search in URL, path, response body
                searchable = " ".join([
                    str(log.get("url", "")),
                    str(log.get("path", "")),
                    str(log.get("example_response_body", ""))[:1000],  # Limit body search
                ]).lower()
                
                if query_lower in searchable:
                    results.append(log)
                    if len(results) >= limit:
                        break
            
            return results
        except Exception:
            return []
    
    async def get_findings(self, severity: Optional[str] = None) -> list[dict[str, Any]]:
        """Get scanner findings, optionally filtered by severity"""
        params = {}
        if severity:
            params["severity"] = severity
        
        response = await self.client.get(
            f"{self.base_url}/api/findings",
            params=params
        )
        response.raise_for_status()
        return response.json()
    
    async def get_endpoints(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        """Get deduplicated endpoints"""
        params = {}
        if status:
            params["status"] = status
        
        response = await self.client.get(
            f"{self.base_url}/api/endpoints",
            params=params
        )
        response.raise_for_status()
        data = response.json()
        # API returns {endpoints: [...], total: ...}
        return data.get("endpoints", []) if isinstance(data, dict) else data
    
    async def get_endpoint_by_id(self, endpoint_id: str) -> dict[str, Any]:
        """Get specific endpoint details"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/endpoints/{endpoint_id}"
            )
            if response.status_code == 200:
                return response.json()
            # Fallback: search in all endpoints
            all_eps = await self.get_endpoints()
            for ep in all_eps:
                if ep.get("hash") == endpoint_id:
                    return ep
            return {}
        except Exception as e:
            return {"error": str(e)}
    
    async def get_triage(self, endpoint_id: str) -> dict[str, Any]:
        """Get AI triage analysis for endpoint (if available)"""
        try:
            # First try to get existing triage from endpoint details
            response = await self.client.get(
                f"{self.base_url}/api/endpoints/{endpoint_id}"
            )
            if response.status_code == 200:
                data = response.json()
                # Return triage_result if it exists
                if data.get("triage_result"):
                    return data["triage_result"]
            # No triage yet - return empty dict (don't trigger triage automatically)
            return {}
        except Exception:
            return {}
    
    # =========================================================================
    # EXECUTION OPERATIONS
    # =========================================================================
    
    async def run_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
        use_proxy: bool = True
    ) -> dict[str, Any]:
        """
        Execute a request through Ghost-Hunter's executor
        Returns: {status_code, headers, body, time_ms}
        """
        payload = {
            "method": method.upper(),
            "url": url,
            "headers": headers or {},
            "body": body,
            "use_proxy": use_proxy
        }
        
        response = await self.client.post(
            f"{self.base_url}/api/run",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    async def replay_endpoint(
        self,
        endpoint_id: str,
        modifications: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """
        Replay an endpoint's original request with optional modifications
        modifications: {headers: {}, params: {}, body: str}
        """
        payload = {"modifications": modifications or {}}
        
        response = await self.client.post(
            f"{self.base_url}/api/endpoints/{endpoint_id}/replay",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    # =========================================================================
    # REPORTING OPERATIONS
    # =========================================================================
    
    async def report_finding(
        self,
        title: str,
        description: str,
        severity: str,
        endpoint_id: Optional[str] = None,
        evidence: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """Report a confirmed vulnerability"""
        payload = {
            "title": title,
            "description": description,
            "severity": severity,  # critical, high, medium, low, info
            "endpoint_id": endpoint_id,
            "evidence": evidence or {}
        }
        
        response = await self.client.post(
            f"{self.base_url}/api/findings",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    async def health_check(self) -> bool:
        """Check if Ghost-Hunter is responsive"""
        try:
            # Try multiple health endpoints
            for endpoint in ["/api/services/health", "/api/stats"]:
                response = await self.client.get(f"{self.base_url}{endpoint}")
                if response.status_code == 200:
                    return True
            return False
        except Exception:
            return False
    
    async def get_stats(self) -> dict[str, Any]:
        """Get dashboard statistics"""
        response = await self.client.get(f"{self.base_url}/api/stats")
        response.raise_for_status()
        return response.json()


def get_client() -> GhostHunterClient:
    """
    Get a new client instance for use with async with.
    
    Usage:
        async with get_client() as client:
            data = await client.get_findings()
    """
    return GhostHunterClient()

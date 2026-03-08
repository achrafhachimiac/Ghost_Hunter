"""
Context Tools for Pivot Agent
LangChain tools that allow the agent to fetch more context from Ghost-Hunter
"""

from typing import Optional
from langchain_core.tools import tool

from .gh_api_client import GhostHunterClient


# Singleton client for tools
_client: Optional[GhostHunterClient] = None


def get_tools_client() -> GhostHunterClient:
    """Get or create the Ghost-Hunter client for tools"""
    global _client
    if _client is None:
        _client = GhostHunterClient()
    return _client


@tool
async def get_related_requests(endpoint_path: str) -> str:
    """
    Fetch related HTTP requests from Ghost-Hunter's captured traffic.
    Use this when you need more context about how an endpoint behaves
    with different parameters, users, or authentication states.
    
    Args:
        endpoint_path: The API path to search for (e.g., "/api/users" or "/api/security/tanker_groups")
    
    Returns:
        JSON string with related requests including their URLs, methods, status codes, and response previews.
    """
    import json
    
    client = get_tools_client()
    async with client:
        requests = await client.get_related_requests(endpoint_path, limit=10)
    
    # Format for LLM consumption
    formatted = []
    for req in requests:
        formatted.append({
            "method": req.get("method", "GET"),
            "url": req.get("url", ""),
            "status": req.get("response_status", req.get("status_code", 0)),
            "has_auth": bool(req.get("has_auth")),
            "params": list(req.get("param_names", [])),
            "response_preview": str(req.get("example_response_body", ""))[:500]
        })
    
    return json.dumps(formatted, indent=2)


@tool
async def search_captured_traffic(query: str) -> str:
    """
    Search through all captured HTTP traffic for specific patterns.
    Use this to find IDs, tokens, or specific data that appeared in other requests.
    
    Args:
        query: Search term - can be an ID, token, endpoint name, or any text pattern
    
    Returns:
        JSON string with matching requests and where the pattern was found.
    """
    import json
    
    client = get_tools_client()
    async with client:
        requests = await client.search_requests(query, limit=15)
    
    # Format results
    formatted = []
    for req in requests:
        formatted.append({
            "method": req.get("method", "GET"),
            "url": req.get("url", ""),
            "host": req.get("host", ""),
            "status": req.get("response_status", 0),
            "score": req.get("heuristic_score", 0),
            "potential_vulns": req.get("potential_vulns", [])
        })
    
    return json.dumps(formatted, indent=2)


@tool
async def get_all_endpoints_for_host(host: str) -> str:
    """
    Get all captured endpoints for a specific host/domain.
    Use this to discover other attack surfaces on the same target.
    
    Args:
        host: The hostname to search (e.g., "app.example.com")
    
    Returns:
        JSON string with all endpoints found for this host.
    """
    import json
    
    client = get_tools_client()
    async with client:
        requests = await client.get_requests_by_host(host, limit=30)
    
    # Group by endpoint path
    endpoints = {}
    for req in requests:
        path = req.get("path_template", req.get("path", ""))
        if path not in endpoints:
            endpoints[path] = {
                "path": path,
                "methods": set(),
                "params": set(),
                "has_auth_variants": False,
                "status_codes": set()
            }
        
        endpoints[path]["methods"].add(req.get("method", "GET"))
        endpoints[path]["params"].update(req.get("param_names", []))
        endpoints[path]["status_codes"].add(req.get("response_status", 0))
        if req.get("has_auth"):
            endpoints[path]["has_auth_variants"] = True
    
    # Convert sets to lists for JSON
    result = []
    for path, data in endpoints.items():
        result.append({
            "path": path,
            "methods": list(data["methods"]),
            "params": list(data["params"]),
            "has_auth_variants": data["has_auth_variants"],
            "status_codes": list(data["status_codes"])
        })
    
    return json.dumps(result, indent=2)


@tool
async def get_request_details(endpoint_id: str) -> str:
    """
    Get full details of a specific captured request including headers, body, and response.
    Use this when you need the complete request/response for analysis.
    
    Args:
        endpoint_id: The endpoint hash/ID from Ghost-Hunter
    
    Returns:
        JSON string with complete request and response details.
    """
    import json
    
    client = get_tools_client()
    async with client:
        endpoint = await client.get_endpoint_by_id(endpoint_id)
    
    if not endpoint or endpoint.get("error"):
        return json.dumps({"error": f"Endpoint {endpoint_id} not found"})
    
    # Return sanitized details
    return json.dumps({
        "method": endpoint.get("method", "GET"),
        "url": endpoint.get("example_url", ""),
        "path": endpoint.get("path_template", ""),
        "query_params": endpoint.get("example_query_params", {}),
        "request_headers": {
            k: v for k, v in endpoint.get("example_headers", {}).items()
            if k.lower() not in ["cookie", "authorization"]  # Don't leak secrets
        },
        "request_body": endpoint.get("example_body", ""),
        "response_status": endpoint.get("example_response_status", 0),
        "response_headers": endpoint.get("example_response_headers", {}),
        "response_body_preview": str(endpoint.get("example_response_body", ""))[:2000],
        "has_auth": endpoint.get("has_auth", False),
        "potential_vulns": endpoint.get("potential_vulns", []),
        "score": endpoint.get("heuristic_score", 0)
    }, indent=2)


# Export all tools
CONTEXT_TOOLS = [
    get_related_requests,
    search_captured_traffic,
    get_all_endpoints_for_host,
    get_request_details
]

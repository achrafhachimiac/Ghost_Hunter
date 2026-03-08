"""
Burp Suite integration routes.
"""

import json
import logging
import time

from fastapi import APIRouter, BackgroundTasks

from dashboard.deps import get_dedup, get_pipeline, get_redis_store
from dashboard.schemas.burp import BurpImportRequest, BurpImportResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/burp", tags=["burp"])


@router.post("/import", response_model=BurpImportResponse)
async def import_from_burp(data: BurpImportRequest, background_tasks: BackgroundTasks):
    """
    Import requests from Burp Suite extension.
    
    Receives batched requests from the Ghost-Hunter Burp extension,
    converts them to InterceptedRequest format, and feeds them into
    the deduplication and triage pipeline.
    """
    from ghost_hunter.core.contracts import InterceptedRequest
    from urllib.parse import urlparse, parse_qs
    
    # Get shared dedup engine (Redis backend = thread-safe)
    dedup = get_dedup()
    
    imported = 0
    deduplicated = 0
    new_endpoints = 0
    errors = []
    
    for req in data.requests:
        try:
            # Parse URL
            parsed = urlparse(req.url)
            
            # Convert headers to lowercase keys (standard)
            headers = {k.lower(): v for k, v in req.headers.items()}
            
            # Parse cookies from Cookie header
            cookies = {}
            if "cookie" in headers:
                for cookie in headers["cookie"].split(";"):
                    cookie = cookie.strip()
                    if "=" in cookie:
                        key, value = cookie.split("=", 1)
                        cookies[key.strip()] = value.strip()
            
            # Parse query params
            query_params = {}
            if parsed.query:
                query_params = {k: v[0] if len(v) == 1 else v 
                               for k, v in parse_qs(parsed.query).items()}
            
            # Parse body JSON if possible
            body_json = None
            body = req.body
            if body:
                try:
                    body_json = json.loads(body)
                except:
                    pass
            
            # Determine content type
            content_type = headers.get("content-type", "")
            
            # Create InterceptedRequest
            intercepted = InterceptedRequest(
                method=req.method,
                url=req.url,
                host=parsed.netloc or parsed.hostname or "",
                path=parsed.path,
                headers=headers,
                cookies=cookies,
                body=body,
                body_json=body_json,
                query_params=query_params,
                content_type=content_type,
                timestamp=time.time(),
                source="burp",  # Mark as coming from Burp
                response_status=req.response.status_code if req.response else None,
                response_headers=req.response.headers if req.response else None,
                response_body=req.response.body if req.response else None,
            )
            
            # Process through FULL pipeline (scope → dedup → scoring → triage)
            pipeline = get_pipeline()
            if pipeline:
                scored = pipeline.process_request(intercepted)
                imported += 1
                
                if scored is None:
                    # Filtered out (out of scope, static, or duplicate)
                    deduplicated += 1
                else:
                    new_endpoints += 1
                    # If score >= threshold, trigger AI triage
                    if scored.score >= pipeline.score_threshold:
                        triage = pipeline.triage_request(scored)
                        if triage and triage.interesting:
                            logger.info(f"🎯 INTERESTING [{triage.confidence}%]: {intercepted.path}")
            else:
                # Fallback: just dedup if pipeline not available
                result = dedup.check(intercepted)
                imported += 1
                if result.is_duplicate:
                    deduplicated += 1
                else:
                    new_endpoints += 1
                
        except Exception as e:
            errors.append(f"Error processing {req.method} {req.url}: {str(e)}")
            logger.error(f"Burp import error: {e}")
    
    # Log summary
    if new_endpoints > 0:
        logger.info(f"Burp import: {imported} processed, {new_endpoints} new endpoints scored/triaged")
    
    return BurpImportResponse(
        imported=imported,
        deduplicated=deduplicated,
        new_endpoints=new_endpoints,
        queued_for_analysis=new_endpoints,
        errors=errors
    )


@router.get("/status")
async def burp_import_status():
    """
    Get status of Burp integration.
    Returns stats about imports and connection status.
    """
    redis_store = get_redis_store()
    try:
        total_endpoints = redis_store.endpoint_count()
        burp_endpoints = 0  # TODO: track source=burp count
        
        return {
            "connected": True,
            "total_endpoints": total_endpoints,
            "burp_endpoints": burp_endpoints,
            "api_url": "http://127.0.0.1:1010/api/burp/import",
            "message": "Ready to receive requests from Burp extension"
        }
    except Exception as e:
        return {
            "connected": False,
            "error": str(e)
        }

"""
Pivot Agent State Definition
============================
Defines the state that flows through the LangGraph workflow.
"""
from typing import TypedDict, List, Dict, Any, Optional, Literal


class ExtractedData(TypedDict, total=False):
    """Data extracted from responses."""
    uuids: List[str]
    jwts: List[str]
    numeric_ids: List[str]
    signed_ids: List[str]
    emails: List[str]
    api_keys: List[str]


class AttackStep(TypedDict):
    """A single step in the attack plan."""
    id: str
    type: str  # 'idor', 'mass_assignment', 'auth_bypass', 'info_leak', etc.
    target_param: str
    payloads: List[str]
    method: str
    endpoint: str
    priority: int  # 1-5, 1 being highest
    status: Literal['pending', 'executing', 'completed', 'failed']
    result: Optional[Dict[str, Any]]


class HistoryEntry(TypedDict):
    """A single entry in the attack history."""
    timestamp: str
    node: str  # Which node executed this
    action: str
    request: Optional[Dict[str, Any]]
    response: Optional[Dict[str, Any]]
    findings: List[str]
    extracted_data: ExtractedData


class TargetLead(TypedDict, total=False):
    """Initial target information."""
    finding_id: Optional[str]
    endpoint: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    params: Dict[str, str]
    response_status: Optional[int]
    response_body: Optional[str]
    vuln_type: Optional[str]
    suspicious_params: List[str]


class AgentState(TypedDict, total=False):
    """
    Main state object that flows through the LangGraph workflow.
    
    This state is passed between nodes and accumulates knowledge
    as the agent pivots through vulnerabilities.
    """
    # Initial target
    target_lead: TargetLead
    
    # Accumulated knowledge
    knowledge_base: ExtractedData
    
    # Current attack plan
    attack_plan: List[AttackStep]
    current_step_index: int
    
    # History of all actions
    history: List[HistoryEntry]
    
    # Pivot tracking
    pivot_queue: List[TargetLead]  # New leads discovered during pivoting
    pivot_depth: int  # How many pivots deep we are
    
    # Status
    current_status: Literal['initializing', 'analyzing', 'researching', 'strategizing', 'attacking', 'pivoting', 'verified', 'completed', 'error']
    current_node: str
    
    # Findings
    confirmed_vulns: List[Dict[str, Any]]
    
    # Control
    iterations: int
    should_stop: bool
    error_message: Optional[str]
    
    # Messages for LLM reasoning
    messages: List[Dict[str, str]]
    
    # NEW: Data Provenance Tracking
    # Maps each extracted ID/value to its origin for intelligent pivoting
    # Example: {"uuid-123": {"source_url": "/api/groups/1", "json_path": "$.data.doctor_id", "user_role": "patient"}}
    data_provenance: Dict[str, Dict[str, Any]]
    
    # NEW: Last response data for extraction
    last_response: Optional[Dict[str, Any]]  # {url, method, status, headers, body, timestamp}
    
    # NEW: Baseline response for IDOR comparison (the "good" response)
    baseline_response: Optional[Dict[str, Any]]  # {url, method, status, headers, body, request_id}
    
    # NEW: Request log for replay functionality
    request_log: List[Dict[str, Any]]  # Stores all executed requests for replay
    
    # NEW: Real endpoints from captured traffic (NO HALLUCINATION!)
    real_endpoints: List[Dict[str, Any]]  # [{url, method, params, ...}]
    
    # NEW: Session context - captured headers/cookies for authenticated requests
    session_context: Dict[str, Any]  # {headers: {...}, cookies: {...}}
    
    # NEW: User goal (optional)
    user_goal: Optional[str]
    
    # NEW: Max iterations limit
    max_iterations: int
    
    # NEW: HTTP request history for debugging
    http_request_history: List[Dict[str, Any]]
    
    # NEW: IDOR detection result from semantic analysis
    idor_detection_result: Optional[Dict[str, Any]]
    
    # NEW: Decoded tokens found in responses
    decoded_tokens: Dict[str, Dict[str, Any]]


class DataProvenanceEntry(TypedDict, total=False):
    """Tracks where a piece of data was extracted from"""
    value: str
    data_type: str  # uuid, numeric_id, tanker_id, base64_id, etc.
    source_url: str
    source_method: str
    json_path: str  # JSONPath where the value was found
    source_field: str  # Field name if from a known field
    user_role: str  # Role of the user when this was captured (patient, doctor, etc.)
    timestamp: str
    context: str  # Surrounding text for debugging


def create_initial_state(target_lead: TargetLead) -> AgentState:
    """Create initial agent state from a target lead."""
    return AgentState(
        target_lead=target_lead,
        knowledge_base=ExtractedData(
            uuids=[],
            jwts=[],
            numeric_ids=[],
            signed_ids=[],
            emails=[],
            api_keys=[]
        ),
        attack_plan=[],
        current_step_index=0,
        history=[],
        pivot_queue=[],
        pivot_depth=0,
        current_status='initializing',
        current_node='start',
        confirmed_vulns=[],
        iterations=0,
        should_stop=False,
        error_message=None,
        messages=[],
        data_provenance={},
        last_response=None,
        baseline_response=None,  # NEW: For IDOR comparison
        request_log=[],
        real_endpoints=[],  # NEW: Real endpoints from traffic
        session_context={},  # Will be populated by dashboard
        user_goal=None,
        max_iterations=10,
        http_request_history=[],
        idor_detection_result=None,  # NEW: Semantic IDOR result
        decoded_tokens={}  # NEW: Decoded tokens
    )


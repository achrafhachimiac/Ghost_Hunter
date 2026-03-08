"""
LangGraph Workflow Definition
Cyclic agent workflow with Replay support for mutation-based IDOR testing

Flow:
    Analyze → Research → Strategize → Execute → Pivot → (loop or replay)
"""

from typing import Literal
from langgraph.graph import StateGraph, END

from .state import AgentState, create_initial_state
from .nodes import (
    analyzer_node,
    researcher_node,
    strategist_node,
    executor_node,
    pivoter_node,
)
from .nodes.pivoter import should_continue


def create_pivot_agent_graph() -> StateGraph:
    """
    Create the LangGraph workflow for the pivot agent
    
    Flow:
    ┌─────────────┐
    │   START     │
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │  Analyzer   │ ← Fetches findings, extracts patterns with provenance
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │ Researcher  │ ← Enriches with knowledge base
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │ Strategist  │ ← Creates attack plan
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │  Executor   │ ← Executes attacks OR replays via Ghost-Hunter
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐     continue      ┌───────────┐
    │   Pivoter   │ ─────────────────→│  Analyzer │
    └──────┬──────┘                   └───────────┘
           │                                ▲
           │ replay                         │
           └────────────────────────────────┤
           │                                │
           │ end                            │
           ▼                                │
    ┌─────────────┐                         │
    │    END      │                         │
    └─────────────┘                         │
                                            │
    REPLAY MODE: When pivoter decides to replay, execution goes directly
    to Executor (bypassing Analyzer/Researcher/Strategist) for mutation testing
    """
    
    # Create the graph
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("analyzer", analyzer_node)
    workflow.add_node("researcher", researcher_node)
    workflow.add_node("strategist", strategist_node)
    workflow.add_node("executor", executor_node)
    workflow.add_node("pivoter", pivoter_node)
    
    # Define edges (linear flow through the cycle)
    workflow.set_entry_point("analyzer")
    
    workflow.add_edge("analyzer", "researcher")
    workflow.add_edge("researcher", "strategist")
    workflow.add_edge("strategist", "executor")
    workflow.add_edge("executor", "pivoter")
    
    # Conditional edge: pivoter decides whether to continue, replay, or end
    # - "continue": Full loop restart (analyzer → researcher → strategist → executor)
    # - "replay": Direct to executor for mutation-based replay testing
    # - "end": Stop the agent
    workflow.add_conditional_edges(
        "pivoter",
        should_continue,
        {
            "continue": "analyzer",  # Full cycle restart
            "replay": "executor",    # Direct replay to executor (skip analysis)
            "end": END
        }
    )
    
    return workflow


def compile_pivot_agent():
    """Compile the workflow into a runnable graph"""
    workflow = create_pivot_agent_graph()
    return workflow.compile()


# Pre-compiled agent for convenience
pivot_agent = None

def get_pivot_agent():
    """Get or create the compiled pivot agent"""
    global pivot_agent
    if pivot_agent is None:
        pivot_agent = compile_pivot_agent()
    return pivot_agent

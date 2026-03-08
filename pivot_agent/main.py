"""
Pivot Agent - Main Entry Point
Autonomous pentest agent using LangGraph
"""

import asyncio
import argparse
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

from .graph import get_pivot_agent
from .state import create_initial_state, AgentState
from .config import GHOST_HUNTER_API_URL, MAX_ITERATIONS


console = Console()


def print_banner():
    """Print the agent banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██████╗ ██╗██╗   ██╗ ██████╗ ████████╗     █████╗  ██████╗  ║
    ║   ██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝    ██╔══██╗██╔════╝  ║
    ║   ██████╔╝██║██║   ██║██║   ██║   ██║       ███████║██║  ███╗ ║
    ║   ██╔═══╝ ██║╚██╗ ██╔╝██║   ██║   ██║       ██╔══██║██║   ██║ ║
    ║   ██║     ██║ ╚████╔╝ ╚██████╔╝   ██║       ██║  ██║╚██████╔╝ ║
    ║   ╚═╝     ╚═╝  ╚═══╝   ╚═════╝    ╚═╝       ╚═╝  ╚═╝ ╚═════╝  ║
    ║                                                               ║
    ║        Autonomous Pentest Agent powered by LangGraph          ║
    ║              Ghost-Hunter Integration Layer                   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def print_state_summary(state: AgentState):
    """Print a summary of the current agent state"""
    table = Table(title="Agent State Summary", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Iteration", str(state.get("iteration", 0)))
    table.add_row("Targets in Queue", str(len(state.get("pivot_queue", []))))
    table.add_row("Attack Steps", str(len(state.get("attack_plan", []))))
    table.add_row("History Entries", str(len(state.get("history", []))))
    table.add_row("Confirmed Vulns", str(len(state.get("confirmed_vulns", []))))
    table.add_row("Extracted IDs", str(len(state.get("extracted_data", {}).get("ids", []))))
    
    console.print(table)


def print_findings(state: AgentState):
    """Print confirmed vulnerabilities"""
    vulns = state.get("confirmed_vulns", [])
    
    if not vulns:
        console.print("\n[yellow]No confirmed vulnerabilities found.[/yellow]")
        return
    
    console.print(f"\n[bold red]🚨 {len(vulns)} Confirmed Vulnerabilities[/bold red]\n")
    
    for i, vuln in enumerate(vulns, 1):
        severity_color = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "blue",
            "info": "white"
        }.get(vuln.get("severity", "info"), "white")
        
        panel_content = f"""
[bold]Type:[/bold] {vuln.get('type', 'Unknown')}
[bold]URL:[/bold] {vuln.get('url', 'N/A')}
[bold]Method:[/bold] {vuln.get('method', 'GET')}
[bold]Modification:[/bold] {json.dumps(vuln.get('modification', {}), indent=2)}
"""
        
        console.print(Panel(
            panel_content,
            title=f"[{severity_color}]Vuln #{i} - {vuln.get('severity', 'unknown').upper()}[/{severity_color}]",
            border_style=severity_color
        ))


def print_reasoning_trace(state: AgentState):
    """Print the agent's reasoning trace"""
    trace = state.get("reasoning_trace", [])
    
    if not trace:
        return
    
    console.print("\n[bold cyan]📝 Reasoning Trace[/bold cyan]\n")
    
    for entry in trace[-20:]:  # Last 20 entries
        if "[Analyzer]" in entry:
            console.print(f"  [magenta]{entry}[/magenta]")
        elif "[Researcher]" in entry:
            console.print(f"  [blue]{entry}[/blue]")
        elif "[Strategist]" in entry:
            console.print(f"  [yellow]{entry}[/yellow]")
        elif "[Executor]" in entry:
            console.print(f"  [green]{entry}[/green]")
        elif "[Pivoter]" in entry:
            console.print(f"  [cyan]{entry}[/cyan]")
        else:
            console.print(f"  {entry}")


async def run_agent(
    endpoint_id: str = None,
    target_url: str = None,
    max_iterations: int = None,
    verbose: bool = False,
    output_file: str = None
):
    """
    Run the pivot agent
    
    Args:
        endpoint_id: Ghost-Hunter endpoint ID to start from
        target_url: Target URL to analyze
        max_iterations: Override max iterations
        verbose: Print detailed output
        output_file: Save results to file
    """
    
    print_banner()
    
    console.print(f"\n[cyan]🔗 Ghost-Hunter API:[/cyan] {GHOST_HUNTER_API_URL}")
    console.print(f"[cyan]🔄 Max Iterations:[/cyan] {max_iterations or MAX_ITERATIONS}")
    
    # Create initial state
    initial_state = create_initial_state()
    
    # Set target if provided
    if endpoint_id:
        initial_state["target_lead"] = {
            "endpoint_id": endpoint_id,
            "url": "",
            "method": "GET",
            "vulnerability_type": "UNKNOWN",
            "pivotable_params": [],
            "confidence_score": 1.0,
            "source": "user_input"
        }
        console.print(f"[cyan]🎯 Starting Endpoint:[/cyan] {endpoint_id}")
    
    if target_url:
        initial_state["target_lead"] = {
            "endpoint_id": "",
            "url": target_url,
            "method": "GET",
            "vulnerability_type": "UNKNOWN",
            "pivotable_params": [],
            "confidence_score": 1.0,
            "source": "user_input"
        }
        console.print(f"[cyan]🎯 Target URL:[/cyan] {target_url}")
    
    if max_iterations:
        initial_state["max_iterations"] = max_iterations
    
    console.print("\n[bold green]▶ Starting Agent...[/bold green]\n")
    
    # Get compiled agent
    agent = get_pivot_agent()
    
    # Run the agent
    start_time = datetime.now()
    final_state = None
    
    try:
        if verbose:
            # Stream updates
            async for event in agent.astream(initial_state):
                for node_name, state_update in event.items():
                    if node_name != "__end__":
                        console.print(f"[dim]→ {node_name}[/dim]")
                        if "reasoning_trace" in state_update:
                            latest = state_update["reasoning_trace"][-1] if state_update["reasoning_trace"] else ""
                            console.print(f"  [dim]{latest}[/dim]")
            
            # Get final state
            final_state = await agent.ainvoke(initial_state)
        else:
            # Simple run with spinner
            with console.status("[bold cyan]Agent running...[/bold cyan]", spinner="dots"):
                final_state = await agent.ainvoke(initial_state)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Agent interrupted by user[/yellow]")
        return
    
    except Exception as e:
        console.print(f"\n[red]❌ Agent error: {str(e)}[/red]")
        if verbose:
            console.print_exception()
        return
    
    # Calculate runtime
    runtime = datetime.now() - start_time
    
    console.print(f"\n[bold green]✓ Agent completed in {runtime.total_seconds():.1f}s[/bold green]\n")
    
    # Print results
    if final_state:
        print_state_summary(final_state)
        print_findings(final_state)
        
        if verbose:
            print_reasoning_trace(final_state)
        
        # Save to file if requested
        if output_file:
            output_data = {
                "timestamp": datetime.now().isoformat(),
                "runtime_seconds": runtime.total_seconds(),
                "iterations": final_state.get("iteration", 0),
                "confirmed_vulns": final_state.get("confirmed_vulns", []),
                "history": final_state.get("history", []),
                "reasoning_trace": final_state.get("reasoning_trace", [])
            }
            
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, "w") as f:
                json.dump(output_data, f, indent=2, default=str)
            
            console.print(f"\n[cyan]💾 Results saved to:[/cyan] {output_file}")


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Pivot Agent - Autonomous Pentest Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start from a Ghost-Hunter endpoint
  python -m pivot_agent --endpoint abc123
  
  # Target a specific URL
  python -m pivot_agent --url https://api.example.com/users/1
  
  # Verbose mode with output file
  python -m pivot_agent --endpoint abc123 -v -o results.json
  
  # Limit iterations
  python -m pivot_agent --url https://api.example.com/users/1 --max-iter 5
        """
    )
    
    parser.add_argument(
        "--endpoint", "-e",
        help="Ghost-Hunter endpoint ID to start analysis from"
    )
    
    parser.add_argument(
        "--url", "-u",
        help="Target URL to analyze"
    )
    
    parser.add_argument(
        "--max-iter", "-m",
        type=int,
        default=None,
        help=f"Maximum iterations (default: {MAX_ITERATIONS})"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed output including reasoning trace"
    )
    
    parser.add_argument(
        "--output", "-o",
        help="Save results to JSON file"
    )
    
    args = parser.parse_args()
    
    # Require at least one target
    if not args.endpoint and not args.url:
        console.print("[yellow]No target specified. Will analyze latest Ghost-Hunter findings.[/yellow]")
    
    # Run the agent
    asyncio.run(run_agent(
        endpoint_id=args.endpoint,
        target_url=args.url,
        max_iterations=args.max_iter,
        verbose=args.verbose,
        output_file=args.output
    ))


if __name__ == "__main__":
    main()

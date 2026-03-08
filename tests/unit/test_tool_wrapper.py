"""
Tests unitaires pour tool_wrapper.py
"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import tempfile

from ghost_hunter.core.executor.tool_wrapper import (
    ToolConfig,
    ExecutionContext,
    ToolWrapper,
    ToolRegistry,
    ShellTool,
    get_registry,
    register_tool,
)
from ghost_hunter.core.contracts import (
    AttackPlan,
    TriageDecision,
    ScoredRequest,
    FilteredRequest,
    InterceptedRequest,
    TestPhase,
    ExecutionResult,
)


# ==================== Fixtures ====================

@pytest.fixture
def sample_intercepted_request():
    return InterceptedRequest(
        method="GET",
        url="https://api.example.com/users/123",
        host="api.example.com",
        path="/users/123",
        headers={"Authorization": "Bearer token"},
        query_params={"id": "123"},
        body=None,
    )


@pytest.fixture
def sample_filtered_request(sample_intercepted_request):
    return FilteredRequest(
        request=sample_intercepted_request,
        in_scope=True,
    )


@pytest.fixture
def sample_scored_request(sample_filtered_request):
    return ScoredRequest(
        request=sample_filtered_request,
        score=75,
        interesting_params=["id"],
        potential_vulns=["IDOR"],
    )


@pytest.fixture
def sample_triage_decision(sample_scored_request):
    return TriageDecision(
        request=sample_scored_request,
        interesting=True,
        confidence=85,
        suggested_vulns=["IDOR"],
        reason="User ID in path",
        test_phase=TestPhase.SAFE,
    )


@pytest.fixture
def sample_attack_plan(sample_triage_decision):
    return AttackPlan(
        request=sample_triage_decision,
        tool="custom",
        vuln_class="IDOR",
        payloads=[],
        injection_points=["id"],
    )


@pytest.fixture
def tool_config():
    return ToolConfig(
        name="test_tool",
        executable="/bin/echo",
        timeout_seconds=30,
        max_concurrent=3,
    )


@pytest.fixture
def execution_context(sample_attack_plan, tmp_path):
    return ExecutionContext(
        plan=sample_attack_plan,
        working_dir=tmp_path,
        output_dir=tmp_path / "output",
    )


# ==================== ToolConfig Tests ====================

class TestToolConfig:
    
    def test_tool_config_creation(self):
        config = ToolConfig(
            name="nuclei",
            executable="nuclei",
            timeout_seconds=600,
        )
        assert config.name == "nuclei"
        assert config.executable == "nuclei"
        assert config.timeout_seconds == 600
    
    def test_tool_config_defaults(self):
        config = ToolConfig(name="test", executable="test")
        assert config.timeout_seconds == 300
        assert config.max_concurrent == 5
        assert config.env == {}
        assert config.default_args == []


# ==================== ExecutionContext Tests ====================

class TestExecutionContext:
    
    def test_context_creation(self, sample_attack_plan, tmp_path):
        ctx = ExecutionContext(
            plan=sample_attack_plan,
            working_dir=tmp_path,
            output_dir=tmp_path / "out",
        )
        assert ctx.plan == sample_attack_plan
        assert ctx.dry_run is False
        assert ctx.verbose is False
    
    def test_context_dry_run(self, sample_attack_plan, tmp_path):
        ctx = ExecutionContext(
            plan=sample_attack_plan,
            working_dir=tmp_path,
            output_dir=tmp_path / "out",
            dry_run=True,
        )
        assert ctx.dry_run is True


# ==================== ToolRegistry Tests ====================

class TestToolRegistry:
    """Tests for ToolRegistry singleton."""
    
    def test_registry_singleton(self):
        """Registry should be a singleton."""
        r1 = ToolRegistry()
        r2 = ToolRegistry()
        assert r1 is r2
    
    def test_register_and_get(self):
        """Test registering and retrieving a tool."""
        registry = ToolRegistry()
        tool = ShellTool("test_tool_rg", "echo hello")
        registry.register(tool)
        
        retrieved = registry.get("test_tool_rg")
        assert retrieved is tool
    
    def test_get_nonexistent_tool(self):
        registry = ToolRegistry()
        assert registry.get("nonexistent_xyz") is None
    
    def test_list_available(self):
        """Test listing available tools."""
        registry = ToolRegistry()
        
        # Register tool with available executable (echo)
        tool = ShellTool("echo_avail_test", "echo test")
        registry.register(tool)
        
        available = registry.list_available()
        assert "echo_avail_test" in available
    
    def test_list_all(self):
        """Test listing all tools with availability."""
        registry = ToolRegistry()
        
        tool1 = ShellTool("all_test_1", "echo test")
        registry.register(tool1)
        
        all_tools = registry.list_all()
        assert "all_test_1" in all_tools
        # echo exists, so should be True
        assert all_tools["all_test_1"] is True


# ==================== ShellTool Tests ====================

class TestShellTool:
    
    def test_tool_creation(self):
        """Test ShellTool can be created."""
        tool = ShellTool("my_echo", "echo hello")
        assert tool.config.name == "my_echo"
        assert tool.is_available is True  # echo exists
    
    def test_is_available_for_nonexistent(self):
        """Test is_available returns False for missing commands."""
        tool = ShellTool("fake_tool", "nonexistent_cmd_xyz123")
        assert tool.is_available is False
    
    def test_execute_success(self, execution_context):
        """Test executing a command successfully."""
        tool = ShellTool("echo_test", "echo hello world")
        
        result = asyncio.get_event_loop().run_until_complete(tool.execute(execution_context))
        
        assert result.success is True
        assert "hello world" in result.raw_response
    
    def test_execute_failure(self, execution_context):
        """Test executing a command that fails."""
        tool = ShellTool("false_test", "false")  # Always exits 1
        
        result = asyncio.get_event_loop().run_until_complete(tool.execute(execution_context))
        
        assert result.success is False
    
    def test_execute_timeout(self, execution_context):
        """Test timeout handling."""
        tool = ShellTool(
            "sleep_test",
            "sleep 10",
            timeout_seconds=1,
        )
        
        result = asyncio.get_event_loop().run_until_complete(tool.execute(execution_context))
        
        assert result.success is False
        assert "Timeout" in (result.error or "")
    
    def test_parse_output_raw(self):
        """Test default parse_output returns raw."""
        tool = ShellTool("parse_test", "echo")
        
        raw_output = "Some plain text output"
        parsed = tool.parse_output(raw_output)
        
        assert parsed["raw"] == raw_output
    
    def test_executions_tracking(self):
        """Test executions list starts empty."""
        tool = ShellTool("track_test", "echo")
        assert tool.executions == []
    
    def test_version(self):
        """Test version property returns something."""
        tool = ShellTool("version_test", "echo")
        # echo --version might work on some systems
        version = tool.version
        # Just test it doesn't raise, may return None
        assert version is None or isinstance(version, str)


# ==================== Global Registry Tests ====================

class TestGlobalRegistry:
    
    def test_get_registry(self):
        registry = get_registry()
        assert isinstance(registry, ToolRegistry)
    
    def test_register_tool_global(self):
        tool = ShellTool("global_test_tool", "echo global")
        
        # Should not raise
        register_tool(tool)
        
        # Should be retrievable
        retrieved = get_registry().get("global_test_tool")
        assert retrieved is not None


# ==================== Integration Tests ====================

class TestToolWrapperIntegration:
    
    def test_full_execution_flow(self, sample_attack_plan, tmp_path):
        """Test complet du flux d'exécution."""
        tool = ShellTool(
            "integration_runner",
            "echo test output",
        )
        
        context = ExecutionContext(
            plan=sample_attack_plan,
            working_dir=tmp_path,
            output_dir=tmp_path / "out",
        )
        
        # Execute
        result = asyncio.get_event_loop().run_until_complete(tool.execute(context))
        
        # Verify
        assert result.success is True
        assert result.tool_used == "integration_runner"
        assert result.request == sample_attack_plan.request
        assert result.plan == sample_attack_plan

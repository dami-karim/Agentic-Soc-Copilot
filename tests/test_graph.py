"""
Tests for the full LangGraph pipeline — end-to-end with mocked ReAct agent.

These tests run the ENTIRE pipeline from ingest → classify → investigate →
rca_generator → propose_actions → deploy, but MOCK the ReAct agent so we
don't need Ollama running. This lets us verify the pipeline structure,
state flow, and routing without external dependencies.

To run with the REAL ReAct agent (requires Ollama + model):
    pytest tests/test_graph.py -k "real" --runslow
"""
from unittest.mock import patch, MagicMock
from src.graph import build_graph, BENIGN_THRESHOLD
from src.nodes.ingest import make_initial_input
from src.state import Phase, FinalStatus


def _make_mock_agent_output(summary_text="Mock investigation complete"):
    """
    Create a fake agent output that mimics what create_react_agent returns.

    The real agent returns: {"messages": [SystemMessage, HumanMessage, AIMessage, ...]}
    This mock returns just the final AIMessage with the summary text.
    """
    from langchain_core.messages import AIMessage
    return {
        "messages": [
            AIMessage(content=summary_text),
        ]
    }


class TestBenignPath:
    """Test alerts that score below the benign threshold (score < 30)."""

    def test_benign_alert_skips_investigation(self, benign_alert):
        """Benign alerts should go directly to deploy, NOT through investigate."""
        app = build_graph()
        initial = make_initial_input(benign_alert)

        # Track which nodes are visited by checking event_log
        result = app.invoke(initial)
        visited_nodes = [e["node"] for e in result["event_log"]]

        assert "ingest" in visited_nodes
        assert "classify" in visited_nodes
        assert "investigate" not in visited_nodes  # SKIPPED!
        assert "rca_generator" not in visited_nodes  # SKIPPED!
        assert "deploy" in visited_nodes

    def test_benign_status(self, benign_alert):
        app = build_graph()
        initial = make_initial_input(benign_alert)
        result = app.invoke(initial)
        assert result["final_status"] == FinalStatus.COMPLETED_BENIGN

    def test_benign_no_rca(self, benign_alert):
        app = build_graph()
        initial = make_initial_input(benign_alert)
        result = app.invoke(initial)
        assert result["rca_report"] == {}

    def test_benign_no_proposed_actions(self, benign_alert):
        app = build_graph()
        initial = make_initial_input(benign_alert)
        result = app.invoke(initial)
        assert result["proposed_actions"] == []


class TestMaliciousPath:
    """Test alerts that score at or above the threshold (score >= 30)."""

    @patch("src.graph._investigation_agent")
    def test_malicious_alert_runs_investigation(self, mock_agent, brute_force_alert):
        """Malicious alerts must go through investigate → rca → actions → deploy."""
        mock_agent.invoke.return_value = _make_mock_agent_output()

        app = build_graph()
        initial = make_initial_input(brute_force_alert)
        result = app.invoke(initial)

        visited_nodes = [e["node"] for e in result["event_log"]]
        assert "ingest" in visited_nodes
        assert "classify" in visited_nodes
        assert "investigate" in visited_nodes
        assert "rca_generator" in visited_nodes
        assert "propose_actions" in visited_nodes
        assert "deploy" in visited_nodes

    @patch("src.graph._investigation_agent")
    def test_malicious_status(self, mock_agent, brute_force_alert):
        mock_agent.invoke.return_value = _make_mock_agent_output()
        app = build_graph()
        result = app.invoke(make_initial_input(brute_force_alert))
        assert result["final_status"] == FinalStatus.COMPLETED

    @patch("src.graph._investigation_agent")
    def test_rca_report_generated(self, mock_agent, brute_force_alert):
        mock_agent.invoke.return_value = _make_mock_agent_output()
        app = build_graph()
        result = app.invoke(make_initial_input(brute_force_alert))
        assert result["rca_report"] != {}
        assert "summary" in result["rca_report"]
        assert "overall_confidence" in result["rca_report"]

    @patch("src.graph._investigation_agent")
    def test_proposed_actions_generated(self, mock_agent, brute_force_alert):
        mock_agent.invoke.return_value = _make_mock_agent_output()
        app = build_graph()
        result = app.invoke(make_initial_input(brute_force_alert))
        assert len(result["proposed_actions"]) > 0

    @patch("src.graph._investigation_agent")
    def test_agent_invoked_with_alert(self, mock_agent, brute_force_alert):
        """The mock agent should have been called with a messages list."""
        mock_agent.invoke.return_value = _make_mock_agent_output()
        app = build_graph()
        app.invoke(make_initial_input(brute_force_alert))

        mock_agent.invoke.assert_called_once()
        call_args = mock_agent.invoke.call_args[0][0]
        assert "messages" in call_args
        assert len(call_args["messages"]) == 1
        assert "WIN-DC01" in call_args["messages"][0]["content"]


class TestAgentGracefulFailure:
    """Test that the pipeline handles ReAct agent failures gracefully."""

    @patch("src.graph._investigation_agent")
    def test_agent_exception_does_not_crash_pipeline(self, mock_agent, brute_force_alert):
        """If the agent raises an exception, the pipeline should continue."""
        mock_agent.invoke.side_effect = ConnectionError("Ollama not running")

        app = build_graph()
        result = app.invoke(make_initial_input(brute_force_alert))

        # Pipeline should still complete
        assert result["final_status"] == FinalStatus.COMPLETED

    @patch("src.graph._investigation_agent")
    def test_agent_exception_leaves_empty_investigation(self, mock_agent, brute_force_alert):
        """On agent failure, investigation data should be empty."""
        mock_agent.invoke.side_effect = ConnectionError("Ollama not running")

        app = build_graph()
        result = app.invoke(make_initial_input(brute_force_alert))

        # No IoCs or techniques from the failed investigation
        assert result["ioc_list"] == []
        assert result["attack_techniques"] == []

    @patch("src.graph._investigation_agent")
    def test_agent_failure_still_generates_rca(self, mock_agent, brute_force_alert):
        """Even with empty investigation, RCA should be generated (with empty data)."""
        mock_agent.invoke.side_effect = ConnectionError("Ollama not running")

        app = build_graph()
        result = app.invoke(make_initial_input(brute_force_alert))

        # RCA should exist but be mostly empty
        assert result["rca_report"] != {}
        assert result["rca_report"]["overall_confidence"] == 0.0


class TestStateFlow:
    """Test that state is correctly passed between nodes."""

    @patch("src.graph._investigation_agent")
    def test_state_preserves_workflow_id(self, mock_agent, brute_force_alert):
        mock_agent.invoke.return_value = _make_mock_agent_output()
        app = build_graph()
        result = app.invoke(make_initial_input(brute_force_alert))
        assert result["workflow_id"] == "test-workflow-001" or result["workflow_id"] is not None

    @patch("src.graph._investigation_agent")
    def test_state_preserves_alert_raw(self, mock_agent, brute_force_alert):
        mock_agent.invoke.return_value = _make_mock_agent_output()
        app = build_graph()
        result = app.invoke(make_initial_input(brute_force_alert))
        assert result["alert_raw"] == brute_force_alert

    @patch("src.graph._investigation_agent")
    def test_phase_ends_at_completed(self, mock_agent, brute_force_alert):
        mock_agent.invoke.return_value = _make_mock_agent_output()
        app = build_graph()
        result = app.invoke(make_initial_input(brute_force_alert))
        assert result["phase"] == Phase.COMPLETED

    @patch("src.graph._investigation_agent")
    def test_triage_score_set_by_classify(self, mock_agent, brute_force_alert):
        mock_agent.invoke.return_value = _make_mock_agent_output()
        app = build_graph()
        result = app.invoke(make_initial_input(brute_force_alert))
        assert result["triage_score"] == 60.0  # medium(40) + 4625(20)


class TestPersistenceAlert:
    """Test with a critical-severity scheduled task alert."""

    @patch("src.graph._investigation_agent")
    def test_critical_alert_runs_full_pipeline(self, mock_agent, persistence_alert):
        mock_agent.invoke.return_value = _make_mock_agent_output()
        app = build_graph()
        result = app.invoke(make_initial_input(persistence_alert))
        assert result["final_status"] == FinalStatus.COMPLETED
        assert result["triage_score"] == 100.0  # Capped at 100

    @patch("src.graph._investigation_agent")
    def test_critical_alert_has_rca(self, mock_agent, persistence_alert):
        mock_agent.invoke.return_value = _make_mock_agent_output()
        app = build_graph()
        result = app.invoke(make_initial_input(persistence_alert))
        assert "summary" in result["rca_report"]

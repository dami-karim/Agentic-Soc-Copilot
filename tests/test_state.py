"""
Tests for state creation and Phase/FinalStatus enums.

These tests verify the FOUNDATION of the entire system — if the state
is wrong, every downstream node will fail.
"""
from src.state import new_state, Phase, FinalStatus, SOCAgentState


class TestPhaseEnum:
    """Test that the Phase enum has all required values."""

    def test_pending_exists(self):
        assert Phase.PENDING == "Pending"

    def test_ingesting_exists(self):
        assert Phase.INGESTING == "Ingesting"

    def test_classifying_exists(self):
        assert Phase.CLASSIFYING == "Classifying"

    def test_analyzing_exists(self):
        assert Phase.ANALYZING == "Analyzing"

    def test_tagging_exists(self):
        assert Phase.TAGGING == "Tagging"

    def test_proposing_actions_exists(self):
        assert Phase.PROPOSING_ACTIONS == "Proposing_Actions"

    def test_completed_exists(self):
        assert Phase.COMPLETED == "Completed"

    def test_error_exists(self):
        assert Phase.ERROR == "Error"

    def test_all_phases_are_strings(self):
        """Every Phase value must be a string (for LangGraph state compatibility)."""
        for phase in Phase:
            assert isinstance(phase.value, str)


class TestFinalStatusEnum:
    """Test that FinalStatus enum has all required values."""

    def test_completed(self):
        assert FinalStatus.COMPLETED == "Completed"

    def test_benign(self):
        assert FinalStatus.COMPLETED_BENIGN == "Completed_Benign"

    def test_aborted(self):
        assert FinalStatus.ABORTED == "Aborted"

    def test_escalated(self):
        assert FinalStatus.ESCALATED == "Escalated"


class TestNewState:
    """Test the new_state factory function."""

    def test_creates_valid_state(self, brute_force_alert):
        state = new_state(
            alert_raw=brute_force_alert,
            workflow_id="wf-001",
            alert_id="al-001",
        )
        assert state["workflow_id"] == "wf-001"
        assert state["alert_id"] == "al-001"
        assert state["alert_raw"] == brute_force_alert

    def test_initial_phase_is_pending(self, brute_force_alert):
        state = new_state(brute_force_alert, "wf-001", "al-001")
        assert state["phase"] == Phase.PENDING

    def test_initial_scores_are_zero(self, brute_force_alert):
        state = new_state(brute_force_alert, "wf-001", "al-001")
        assert state["triage_score"] == 0.0
        assert state["severity"] == "unknown"

    def test_initial_lists_are_empty(self, brute_force_alert):
        state = new_state(brute_force_alert, "wf-001", "al-001")
        assert state["ioc_list"] == []
        assert state["attack_techniques"] == []
        assert state["proposed_actions"] == []
        assert state["human_decisions"] == []
        assert state["guardrail_flags"] == []
        assert state["event_log"] == []

    def test_initial_dicts_are_empty(self, brute_force_alert):
        state = new_state(brute_force_alert, "wf-001", "al-001")
        assert state["enrichment"] == {}
        assert state["blast_radius"] == {}
        assert state["rca_report"] == {}

    def test_initial_status_is_none(self, brute_force_alert):
        state = new_state(brute_force_alert, "wf-001", "al-001")
        assert state["final_status"] is None

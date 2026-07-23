"""
Tests for the propose actions node — containment proposals.

Each ATT&CK technique should map to a specific containment action.
The tests verify correct mapping, deduplication, risk levels, and
blast-radius context.
"""
from src.nodes.propose_actions import (
    propose_actions_node,
    extract_technique_prefix,
    build_action_proposals,
    TECHNIQUE_ACTIONS,
    DEFAULT_ACTIONS,
)
from src.state import Phase


class TestExtractTechniquePrefix:
    """Test technique ID prefix extraction."""

    def test_base_technique(self):
        assert extract_technique_prefix("T1110") == "T1110"

    def test_sub_technique(self):
        assert extract_technique_prefix("T1110.001") == "T1110"

    def test_sub_technique_long(self):
        assert extract_technique_prefix("T1059.001") == "T1059"

    def test_unknown_technique(self):
        assert extract_technique_prefix("T????") == "T????"


class TestBuildActionProposals:
    """Test action proposal generation from techniques."""

    def test_brute_force_produces_credential_reset(self):
        techniques = [{"technique_id": "T1110", "technique_name": "Brute Force"}]
        proposals = build_action_proposals(techniques, {}, {})
        action_types = [p["action_type"] for p in proposals]
        assert "reset_credentials" in action_types

    def test_command_execution_produces_host_isolation(self):
        techniques = [{"technique_id": "T1059", "technique_name": "Command Execution"}]
        proposals = build_action_proposals(techniques, {}, {})
        action_types = [p["action_type"] for p in proposals]
        assert "isolate_host" in action_types

    def test_lateral_movement_produces_network_block(self):
        techniques = [{"technique_id": "T1021", "technique_name": "Remote Services"}]
        proposals = build_action_proposals(techniques, {}, {})
        action_types = [p["action_type"] for p in proposals]
        assert "block_network_path" in action_types

    def test_unknown_technique_no_extra_actions(self):
        """Unknown technique should not produce technique-specific actions,
        only the default actions."""
        techniques = [{"technique_id": "T9999", "technique_name": "Unknown"}]
        proposals = build_action_proposals(techniques, {}, {})
        # Should only have the 2 default actions
        action_types = [p["action_type"] for p in proposals]
        assert "full_edr_scan" in action_types
        assert "update_detection_rules" in action_types

    def test_always_has_default_actions(self):
        techniques = [{"technique_id": "T1110", "technique_name": "Brute Force"}]
        proposals = build_action_proposals(techniques, {}, {})
        action_types = [p["action_type"] for p in proposals]
        assert "full_edr_scan" in action_types
        assert "update_detection_rules" in action_types

    def test_deduplication(self):
        """Two techniques mapping to the same action should produce one proposal."""
        techniques = [
            {"technique_id": "T1110", "technique_name": "Brute Force"},
            {"technique_id": "T1110.001", "technique_name": "Password Spraying"},
        ]
        proposals = build_action_proposals(techniques, {}, {})
        credential_resets = [p for p in proposals if p["action_type"] == "reset_credentials"]
        assert len(credential_resets) == 1

    def test_blast_radius_context_added(self):
        techniques = [{"technique_id": "T1110", "technique_name": "Brute Force"}]
        blast_radius = {
            "reachable_assets": [{"id": "WIN-WEB01"}, {"id": "WIN-FIN02"}],
            "max_hops": 3,
        }
        proposals = build_action_proposals(techniques, blast_radius, {})
        # The technique-specific proposal should have blast radius context
        cred_reset = [p for p in proposals if p["action_type"] == "reset_credentials"][0]
        assert "blast_radius_context" in cred_reset
        assert "2 additional" in cred_reset["blast_radius_context"]

    def test_no_blast_radius_no_context(self):
        techniques = [{"technique_id": "T1110", "technique_name": "Brute Force"}]
        proposals = build_action_proposals(techniques, {}, {})
        cred_reset = [p for p in proposals if p["action_type"] == "reset_credentials"][0]
        assert "blast_radius_context" not in cred_reset


class TestProposalsRiskLevels:
    """Test that risk levels are correct for each action type."""

    def test_host_isolation_is_high_risk(self):
        techniques = [{"technique_id": "T1059", "technique_name": "Command Execution"}]
        proposals = build_action_proposals(techniques, {}, {})
        isolate = [p for p in proposals if p["action_type"] == "isolate_host"][0]
        assert isolate["risk_level"] == "high"

    def test_network_block_is_high_risk(self):
        techniques = [{"technique_id": "T1021", "technique_name": "Remote Services"}]
        proposals = build_action_proposals(techniques, {}, {})
        block = [p for p in proposals if p["action_type"] == "block_network_path"][0]
        assert block["risk_level"] == "high"

    def test_credential_reset_is_medium_risk(self):
        techniques = [{"technique_id": "T1110", "technique_name": "Brute Force"}]
        proposals = build_action_proposals(techniques, {}, {})
        reset = [p for p in proposals if p["action_type"] == "reset_credentials"][0]
        assert reset["risk_level"] == "medium"

    def test_edr_scan_is_low_risk(self):
        techniques = [{"technique_id": "T1110", "technique_name": "Brute Force"}]
        proposals = build_action_proposals(techniques, {}, {})
        scan = [p for p in proposals if p["action_type"] == "full_edr_scan"][0]
        assert scan["risk_level"] == "low"


class TestProposeActionsNode:
    """Test the full propose_actions node with pre-populated state."""

    def test_proposals_generated(self, investigated_state):
        result = propose_actions_node(investigated_state)
        assert len(result["proposed_actions"]) > 0

    def test_proposal_count(self, investigated_state):
        """2 techniques (T1110, T1078) + 2 defaults = 4 proposals."""
        result = propose_actions_node(investigated_state)
        assert len(result["proposed_actions"]) == 4

    def test_phase_set(self, investigated_state):
        result = propose_actions_node(investigated_state)
        assert result["phase"] == Phase.PROPOSING_ACTIONS

    def test_event_log_appended(self, investigated_state):
        initial_len = len(investigated_state["event_log"])
        result = propose_actions_node(investigated_state)
        assert len(result["event_log"]) == initial_len + 1
        assert result["event_log"][-1]["node"] == "propose_actions"

    def test_high_risk_count_in_log(self, investigated_state):
        """The event log should report how many high-risk actions exist."""
        result = propose_actions_node(investigated_state)
        log_detail = result["event_log"][-1]["detail"]
        assert "high-risk" in log_detail

    def test_proposals_contain_technique_ids(self, investigated_state):
        result = propose_actions_node(investigated_state)
        technique_ids = [p.get("technique_id") for p in result["proposed_actions"]
                         if p.get("technique_id")]
        assert "T1110" in technique_ids
        assert "T1078" in technique_ids

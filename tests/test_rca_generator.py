"""
Tests for the RCA generator node — report structure and content.

The RCA generator is DETERMINISTIC — same inputs always produce the
same output. This makes it highly testable.
"""
from src.nodes.rca_generator import (
    rca_generator_node,
    compute_overall_confidence,
    build_timeline,
    identify_root_cause,
    identify_containment_actions,
)
from src.state import Phase


class TestComputeOverallConfidence:
    """Test the confidence score computation."""

    def test_empty_techniques(self):
        assert compute_overall_confidence([]) == 0.0

    def test_single_technique(self):
        techniques = [{"confidence": 0.8}]
        assert compute_overall_confidence(techniques) == 0.8

    def test_multiple_techniques_weighted(self):
        techniques = [
            {"confidence": 0.9},  # High confidence → contributes more
            {"confidence": 0.3},  # Low confidence → contributes less
        ]
        result = compute_overall_confidence(techniques)
        # weighted: (0.9*0.9 + 0.3*0.3) / (0.9 + 0.3) = (0.81+0.09)/1.2 = 0.75
        assert result == 0.75

    def test_all_zero_confidence(self):
        techniques = [{"confidence": 0.0}, {"confidence": 0.0}]
        assert compute_overall_confidence(techniques) == 0.0

    def test_missing_confidence_defaults_to_05(self):
        techniques = [{}]  # No "confidence" key → defaults to 0.5
        result = compute_overall_confidence(techniques)
        assert result == 0.5


class TestBuildTimeline:
    """Test timeline extraction from event log."""

    def test_empty_log(self):
        assert build_timeline([]) == []

    def test_single_entry(self):
        log = [{"timestamp": "2026-01-01T00:00:00Z", "node": "ingest", "detail": "Alert received"}]
        timeline = build_timeline(log)
        assert len(timeline) == 1
        assert timeline[0]["node"] == "ingest"
        assert timeline[0]["action"] == "Alert received"

    def test_missing_fields_default(self):
        log = [{}]  # Empty dict — all fields missing
        timeline = build_timeline(log)
        assert timeline[0]["node"] == "unknown"
        assert timeline[0]["action"] == ""
        assert timeline[0]["timestamp"] == ""


class TestIdentifyRootCause:
    """Test the RCA summary narrative generation."""

    def test_with_techniques_and_iocs(self, brute_force_alert):
        techniques = [
            {"technique_id": "T1110", "technique_name": "Brute Force", "confidence": 0.85}
        ]
        iocs = [
            {"type": "ip", "value": "10.0.2.15"},
            {"type": "account", "value": "administrator"},
        ]
        summary = identify_root_cause(brute_force_alert, techniques, iocs)
        assert "4625" in summary
        assert "WIN-DC01" in summary
        assert "T1110" in summary
        assert "Brute Force" in summary
        assert "10.0.2.15" in summary

    def test_no_techniques(self, brute_force_alert):
        summary = identify_root_cause(brute_force_alert, [], [])
        assert "T????" in summary
        assert "Unknown" in summary

    def test_no_iocs(self, brute_force_alert):
        techniques = [{"technique_id": "T1110", "technique_name": "Brute Force", "confidence": 0.8}]
        summary = identify_root_cause(brute_force_alert, techniques, [])
        assert "none identified" in summary


class TestIdentifyContainmentActions:
    """Test ATT&CK-to-containment-action mapping."""

    def test_brute_force_maps_to_credential_reset(self):
        techniques = [{"technique_id": "T1110"}]
        actions = identify_containment_actions(techniques)
        assert any("Reset compromised credentials" in a for a in actions)

    def test_command_execution_maps_to_host_isolation(self):
        techniques = [{"technique_id": "T1059"}]
        actions = identify_containment_actions(techniques)
        assert any("Isolate the affected host" in a for a in actions)

    def test_unknown_technique_gets_general_action(self):
        techniques = [{"technique_id": "T9999"}]
        actions = identify_containment_actions(techniques)
        assert any("Conduct full incident review" in a for a in actions)

    def test_deduplication(self):
        """Two techniques in the same tactic should produce only one action."""
        techniques = [
            {"technique_id": "T1110"},
            {"technique_id": "T1110.001"},  # Same prefix T1110
        ]
        actions = identify_containment_actions(techniques)
        credential_actions = [a for a in actions if "Reset" in a]
        assert len(credential_actions) == 1  # Deduplicated

    def test_always_includes_general_action(self):
        techniques = [{"technique_id": "T1110"}]
        actions = identify_containment_actions(techniques)
        assert any("Conduct full incident review" in a for a in actions)


class TestRcaGeneratorNode:
    """Test the full RCA generator node with pre-populated state."""

    def test_rca_report_structure(self, investigated_state):
        """The RCA report must have all required fields."""
        result = rca_generator_node(investigated_state)
        rca = result["rca_report"]

        assert "alert_id" in rca
        assert "workflow_id" in rca
        assert "summary" in rca
        assert "triage_score" in rca
        assert "severity" in rca
        assert "attack_techniques" in rca
        assert "ioc_summary" in rca
        assert "overall_confidence" in rca
        assert "containment_actions" in rca
        assert "timeline" in rca
        assert "generated_at" in rca

    def test_rca_summary_contains_alert_info(self, investigated_state):
        result = rca_generator_node(investigated_state)
        summary = result["rca_report"]["summary"]
        assert "WIN-DC01" in summary
        assert "administrator" in summary
        assert "T1110" in summary

    def test_rca_confidence_nonzero(self, investigated_state):
        """With techniques that have confidence > 0, overall should be > 0."""
        result = rca_generator_node(investigated_state)
        assert result["rca_report"]["overall_confidence"] > 0

    def test_rca_techniques_match_input(self, investigated_state):
        result = rca_generator_node(investigated_state)
        technique_ids = [t["technique_id"] for t in result["rca_report"]["attack_techniques"]]
        assert "T1110" in technique_ids
        assert "T1078" in technique_ids

    def test_rca_ioc_count_matches(self, investigated_state):
        result = rca_generator_node(investigated_state)
        assert len(result["rca_report"]["ioc_summary"]) == 3

    def test_rca_containment_actions_nonempty(self, investigated_state):
        result = rca_generator_node(investigated_state)
        assert len(result["rca_report"]["containment_actions"]) > 0

    def test_rca_timeline_from_event_log(self, investigated_state):
        result = rca_generator_node(investigated_state)
        assert len(result["rca_report"]["timeline"]) == 3  # 3 entries in event_log

    def test_phase_set_to_proposing_actions(self, investigated_state):
        result = rca_generator_node(investigated_state)
        assert result["phase"] == Phase.PROPOSING_ACTIONS

    def test_event_log_appended(self, investigated_state):
        initial_log_len = len(investigated_state["event_log"])
        result = rca_generator_node(investigated_state)
        assert len(result["event_log"]) == initial_log_len + 1
        assert result["event_log"][-1]["node"] == "rca_generator"

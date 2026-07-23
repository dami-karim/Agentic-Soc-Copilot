"""
Tests for the classify node — scoring logic and routing.

The classify node is the DECISION POINT of the pipeline:
  score < 30  → benign → deploy (early exit)
  score >= 30 → malicious → full investigation

These tests verify that every severity/EventCode combination
produces the correct score and routes to the correct path.
"""
from src.nodes.classify import classify_node, SEVERITY_SCORES, EVENTCODE_BOOSTS, BENIGN_THRESHOLD
from src.state import Phase


class TestClassifyScoring:
    """Test that classify_node produces correct triage scores."""

    def test_low_severity_no_eventcode(self, brute_force_state):
        """Low severity + no recognized EventCode → base score only."""
        brute_force_state["alert_raw"]["severity"] = "low"
        brute_force_state["alert_raw"]["EventCode"] = "9999"
        result = classify_node(brute_force_state)
        assert result["triage_score"] == 10.0  # SEVERITY_SCORES["low"]

    def test_medium_severity_4625(self, brute_force_state):
        """Medium severity + EventCode 4625 (failed logon) → 40 + 20 = 60."""
        result = classify_node(brute_force_state)
        assert result["triage_score"] == 60.0

    def test_high_severity_4688(self, brute_force_state):
        """High severity + EventCode 4688 (new process) → 70 + 25 = 95."""
        brute_force_state["alert_raw"]["severity"] = "high"
        brute_force_state["alert_raw"]["EventCode"] = "4688"
        result = classify_node(brute_force_state)
        assert result["triage_score"] == 95.0

    def test_critical_severity_4698(self, brute_force_state):
        """Critical severity + EventCode 4698 (scheduled task) → 90 + 30 = 120, capped at 100."""
        brute_force_state["alert_raw"]["severity"] = "critical"
        brute_force_state["alert_raw"]["EventCode"] = "4698"
        result = classify_node(brute_force_state)
        assert result["triage_score"] == 100.0  # Capped!

    def test_score_never_exceeds_100(self, brute_force_state):
        """Score must be capped at 100.0 regardless of inputs."""
        brute_force_state["alert_raw"]["severity"] = "critical"
        brute_force_state["alert_raw"]["EventCode"] = "4698"
        result = classify_node(brute_force_state)
        assert result["triage_score"] <= 100.0

    def test_unknown_severity_defaults_to_medium(self, brute_force_state):
        """Unknown severity string should default to medium (40)."""
        brute_force_state["alert_raw"]["severity"] = "weird_value"
        brute_force_state["alert_raw"]["EventCode"] = "9999"  # No boost
        result = classify_node(brute_force_state)
        assert result["triage_score"] == 40.0  # Default medium + no boost

    def test_unknown_eventcode_gets_no_boost(self, brute_force_state):
        """Unrecognized EventCode should add 0 boost."""
        brute_force_state["alert_raw"]["EventCode"] = "12345"
        result = classify_node(brute_force_state)
        assert result["triage_score"] == 40.0  # medium (40) + no boost


class TestClassifyRouting:
    """Test that classify_node sets the correct severity and routes correctly."""

    def test_severity_set_in_state(self, brute_force_state):
        result = classify_node(brute_force_state)
        assert result["severity"] == "medium"

    def test_phase_set_to_classifying(self, brute_force_state):
        result = classify_node(brute_force_state)
        assert result["phase"] == Phase.CLASSIFYING

    def test_event_log_appended(self, brute_force_state):
        result = classify_node(brute_force_state)
        assert len(result["event_log"]) == 1
        assert result["event_log"][0]["node"] == "classify"
        assert "triage_score=" in result["event_log"][0]["detail"]

    def test_benign_route_logged(self, brute_force_state):
        """Score < 30 should log 'route=benign'."""
        brute_force_state["alert_raw"]["severity"] = "low"
        brute_force_state["alert_raw"]["EventCode"] = "9999"
        result = classify_node(brute_force_state)
        assert "route=benign" in result["event_log"][0]["detail"]

    def test_malicious_route_logged(self, brute_force_state):
        """Score >= 30 should log 'route=malicious'."""
        result = classify_node(brute_force_state)
        assert "route=malicious" in result["event_log"][0]["detail"]


class TestClassifyThreshold:
    """Test the exact boundary at BENIGN_THRESHOLD = 30.0."""

    def test_score_exactly_30_is_malicious(self, brute_force_state):
        """Score of exactly 30.0 should route to malicious (>= 30)."""
        # severity="low" (10) + EventCode="4624" (10) = 20 → too low
        # Need: base=10, boost=20 → total=30
        # Use severity="low" (10) + EventCode="4625" (20) = 30
        brute_force_state["alert_raw"]["severity"] = "low"
        brute_force_state["alert_raw"]["EventCode"] = "4625"
        result = classify_node(brute_force_state)
        assert result["triage_score"] == 30.0
        assert "route=malicious" in result["event_log"][0]["detail"]

    def test_score_29_is_benign(self, brute_force_state):
        """Score of 29.0 should route to benign (< 30)."""
        # severity="low" (10) + EventCode="4624" (10) = 20 → benign
        # severity="low" (10) + EventCode="4672" (15) = 25 → benign
        brute_force_state["alert_raw"]["severity"] = "low"
        brute_force_state["alert_raw"]["EventCode"] = "4672"
        result = classify_node(brute_force_state)
        assert result["triage_score"] == 25.0
        assert "route=benign" in result["event_log"][0]["detail"]

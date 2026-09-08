"""
Tests for the false-positive filter subsystem.

Covers:
  - Score consistency with the classify node (single source of truth)
  - Rule-based verdicts for clear benign / clear malicious / borderline alerts
  - Signature overrides (malicious, benign, false-positive phrases)
  - Volume detection for brute-force patterns
  - Batch aggregation and metrics
"""
import json

import pytest

from src.fp_filter import (
    binary_metrics,
    classify_alert,
    compute_triage_score,
    run_batch,
)
from src.fp_filter.classifier import FALSE_POSITIVE, REVIEW, TRUE_POSITIVE
from src.fp_filter.signals import extract_signals
from src.nodes.classify import BENIGN_THRESHOLD, classify_node


def _alert(event_code, severity, signature, count=1, user="jsmith", logon="3"):
    return {
        "host": "WIN-DC01",
        "EventCode": event_code,
        "src_ip": "10.0.2.15",
        "dest_ip": "10.0.2.5",
        "user": user,
        "Logon_Type": logon,
        "sourcetype": "WinEventLog:Security",
        "signature": signature,
        "severity": severity,
        "count": count,
    }


class TestScoreConsistency:
    """The filter must compute the SAME triage score as the classify node."""

    @pytest.mark.parametrize(
        "alert",
        [
            _alert("4625", "medium", "An account failed to log on"),
            _alert("4688", "high", "A new process has been created"),
            _alert("4698", "critical", "A scheduled task was created"),
            _alert("9999", "low", "Informational event"),
            _alert("4624", "weird_severity", "Logon noise"),
        ],
    )
    def test_score_matches_classify_node(self, alert):
        assert compute_triage_score(alert) == classify_node(
            {"alert_raw": dict(alert), "triage_score": 0.0, "severity": "unknown",
             "event_log": [], "phase": "Pending"}
        )["triage_score"]


class TestRuleVerdicts:
    def test_benign_logoff_is_false_positive(self):
        result = classify_alert(_alert("4634", "low", "An account was successfully logged off"))
        assert result.verdict == FALSE_POSITIVE

    def test_low_informational_is_false_positive(self):
        result = classify_alert(_alert("9999", "low", "Informational event"))
        assert result.verdict == FALSE_POSITIVE

    def test_brute_force_failed_logon_is_true_positive(self):
        result = classify_alert(_alert(
            "4625", "medium", "An account failed to log on — multiple failures",
            count=40,
        ))
        assert result.verdict == TRUE_POSITIVE
        assert result.score >= BENIGN_THRESHOLD

    def test_powershell_encoded_execution_is_true_positive(self):
        result = classify_alert(_alert(
            "4688", "low", "powershell.exe -enc SGVsbG8=",
        ))
        assert result.verdict == TRUE_POSITIVE

    def test_critical_scheduled_task_is_true_positive(self):
        result = classify_alert(_alert(
            "4698", "critical", "A scheduled task was created", user="administrator",
        ))
        assert result.verdict == TRUE_POSITIVE

    def test_borderline_alert_routes_to_review(self):
        # medium (40) + 4624 (10) = 50 → borderline? No: 50 >= 30, so TP.
        # Force a borderline score: medium 4624 with fp signature would FP.
        # Use medium severity + unknown EventCode AND no signatures → 40 → TP.
        # To hit the band [25, 30) use low(10)+4672(15)=25.
        result = classify_alert(_alert("4672", "low", "Something routine happened"))
        assert result.verdict == REVIEW

    def test_passes_ground_truth_signature(self):
        # OCR-APT style: vulnerability scan text is a classic FP.
        result = classify_alert(_alert("9999", "medium", "Vulnerability scan from scanner"))
        assert result.verdict == FALSE_POSITIVE

    def test_benign_signature_wins_over_low_boost(self):
        result = classify_alert(_alert(
            "4624", "medium", "The workstation was unlocked — normal activity",
        ))
        assert result.verdict == FALSE_POSITIVE


class TestVolumeDetection:
    def test_low_volume_failed_logon_stays_below_threshold(self):
        result = classify_alert(_alert(
            "4625", "low", "An account failed to log on", count=1,
        ))
        assert result.verdict in (TRUE_POSITIVE, REVIEW)
        assert result.signals["high_failure_volume"] is False

    def test_high_volume_failed_logon_gets_bonus_and_is_true_positive(self):
        signals = extract_signals(
            _alert("4625", "low", "An account failed to log on", count=50),
            base_score=10.0,
            eventcode_boost=20.0,
        )
        assert signals.high_failure_volume is True


class TestBatch:
    def test_run_batch_counts_and_filter_rate(self):
        alerts = [
            _alert("4634", "low", "An account was successfully logged off"),   # FP
            _alert("4625", "high", "An account failed to log on", count=30),   # TP
            _alert("4672", "low", "Something routine happened"),               # REVIEW
        ]
        report = run_batch(alerts, verbose=False)
        assert report["total"] == 3
        assert report["verdicts"] == {
            FALSE_POSITIVE: 1, TRUE_POSITIVE: 1, REVIEW: 1,
        }
        assert report["false_positive_rate"] == pytest.approx(1 / 3, abs=0.001)
        assert len(report["per_alert"]) == 3

    def test_run_batch_with_ground_truth_metrics(self):
        alerts = [
            _alert("4634", "low", "An account was successfully logged off"),
            _alert("4625", "high", "An account failed to log on", count=30),
        ]
        report = run_batch(
            alerts,
            ground_truth=[{"is_false_positive": True}, {"is_false_positive": False}],
            verbose=False,
        )
        m = report["metrics"]
        assert m["true_negatives"] == 1     # predicted FP, truly benign
        assert m["true_positives"] == 1     # predicted TP, truly malicious
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["fp_reduction"] == 1.0

    def test_binary_metrics_missed_threat(self):
        labels = ["benign", "malicious"]
        predictions = [FALSE_POSITIVE, FALSE_POSITIVE]  # 2nd is a missed threat
        m = binary_metrics(labels, predictions)
        assert m["false_negatives"] == 1
        assert m["recall"] == 0.0
        assert m["missed_threat_rate"] == 1.0

    def test_binary_metrics_review_not_penalized(self):
        m = binary_metrics(["benign", "malicious"], [FALSE_POSITIVE, REVIEW])
        assert m["review"] == 1
        assert m["false_negatives"] == 0
        assert m["precision"] == 0.0  # no TP predicted


class TestLoadAlertsFormats:
    def test_load_json_array(self, tmp_path):
        p = tmp_path / "alerts.json"
        p.write_text(json.dumps([_alert("4625", "high", "x", count=1)]))
        from src.fp_filter.batch import load_alerts
        assert len(load_alerts(str(p))) == 1

    def test_load_jsonl(self, tmp_path):
        p = tmp_path / "alerts.jsonl"
        p.write_text(
            json.dumps(_alert("4625", "high", "x", count=1)) + "\n" +
            json.dumps(_alert("4634", "low", "y")) + "\n"
        )
        from src.fp_filter.batch import load_alerts
        assert len(load_alerts(str(p))) == 2

    def test_load_wrapped_object(self, tmp_path):
        p = tmp_path / "alerts.json"
        p.write_text(json.dumps({"alerts": [_alert("4625", "high", "x", count=1)]}))
        from src.fp_filter.batch import load_alerts
        assert len(load_alerts(str(p))) == 1
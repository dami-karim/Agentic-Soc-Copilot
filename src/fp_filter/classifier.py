"""
Classifier — rule-based triage + final FP/TP/REVIEW verdict.

The scoring formula mirrors src/nodes/classify.py EXACTLY so the filter is
consistent with the main LangGraph pipeline: an alert the filter calls a
TRUE POSITIVE would also route to "investigate" inside the graph, and one
it calls a FALSE POSITIVE would exit at "deploy" as COMPLETED_BENIGN.

Decision layers, applied in order:
  1. Strong benign override  -> FALSE_POSITIVE (known-benign code/signature
     and no conflicting malicious signature).
  2. Strong malicious override -> TRUE_POSITIVE (malicious signature or
     high-failure-volume brute-force pattern regardless of nominal severity).
  3. Score bins -> score >= threshold TRUE_POSITIVE, score in the borderline
     band REVIEW, otherwise FALSE_POSITIVE.
"""
from dataclasses import dataclass

from src.fp_filter.signals import AlertSignals, extract_signals
from src.nodes.classify import BENIGN_THRESHOLD, EVENTCODE_BOOSTS, SEVERITY_SCORES

# Width of the ambiguous band below the benign threshold. Matches the
# BORDERLINE_MARGIN used by the graph for the first HIL gate.
BORDERLINE_MARGIN = 5.0

# Verdict constants
FALSE_POSITIVE = "false_positive"
TRUE_POSITIVE = "true_positive"
REVIEW = "review"

# Score adjustments applied on top of base + eventcode boost.
VOLUME_BONUS = 15.0
STRONG_MALICIOUS_FLOOR = 70.0


@dataclass
class FPFilterResult:
    """Single-alert filter decision."""

    verdict: str
    score: float
    confidence: float
    reasons: list[str]
    signals: dict
    method: str = "rule"
    review_note: str = ""

    def to_dict(self, index: int | None = None, alert_id: str = "") -> dict:
        row = {
            "index": index,
            "alert_id": alert_id,
            "verdict": self.verdict,
            "score": self.score,
            "confidence": round(self.confidence, 3),
            "method": self.method,
            "reasons": self.reasons,
            "signals": self.signals,
        }
        if self.review_note:
            row["review_note"] = self.review_note
        return row


def compute_triage_score(alert: dict) -> float:
    """
    Triage score identical to src/nodes/classify.py.

    severity base (default medium=40) + EventCode boost, capped at 100.
    """
    severity = str(alert.get("severity", "medium")).lower()
    base_score = SEVERITY_SCORES.get(severity, 40)
    event_code = str(alert.get("EventCode", ""))
    boost = EVENTCODE_BOOSTS.get(event_code, 0)
    return min(base_score + boost, 100.0)


def _confidence_from_reasons(verdict: str, reasons: list[str], score: float) -> float:
    if verdict == TRUE_POSITIVE:
        # Strong textual signal pushes confidence up.
        if "signature" in " ".join(reasons):
            return min(0.75 + score / 500.0, 0.97)
        return min(0.55 + score / 200.0, 0.9)
    if verdict == FALSE_POSITIVE:
        if "known-benign" in " ".join(reasons) or "benign signature" in " ".join(reasons):
            return 0.92
        return 0.8
    return 0.35  # review


def classify_alert(
    alert: dict,
    benign_threshold: float = BENIGN_THRESHOLD,
    borderline_margin: float = BORDERLINE_MARGIN,
) -> FPFilterResult:
    """
    Classify a single alert as FALSE_POSITIVE / TRUE_POSITIVE / REVIEW.

    Args:
        alert: Raw SIEM alert dictionary.
        benign_threshold: Score above which an alert is a TRUE POSITIVE.
        borderline_margin: Width of the band below the threshold routed to REVIEW.

    Returns:
        FPFilterResult with verdict, adjusted score, confidence, and reasons.
    """
    severity = str(alert.get("severity", "medium")).lower()
    base_score = SEVERITY_SCORES.get(severity, 40)
    event_code = str(alert.get("EventCode", ""))
    boost = EVENTCODE_BOOSTS.get(event_code, 0)
    score = min(base_score + boost, 100.0)

    signals: AlertSignals = extract_signals(alert, base_score, boost)
    reasons: list[str] = []

    # ── Score adjustments ─────────────────────────────────────────────────────
    if signals.high_failure_volume:
        score = min(score + VOLUME_BONUS, 100.0)
        reasons.append(
            f"high failure volume (count={signals.count}) for EventCode "
            f"{event_code} — +{VOLUME_BONUS:.0f} points"
        )
    if signals.malicious_signature:
        reasons.append(
            f"malicious signature: '{signals.malicious_signature}'"
        )
        # Avoid double counting when volume is already covered.
        if not signals.high_failure_volume:
            score = min(score + VOLUME_BONUS, 100.0)

    strong_malicious = signals.malicious_signature is not None or score >= STRONG_MALICIOUS_FLOOR

    # ── Layer 1: strong benign override ───────────────────────────────────────
    benign_override = (
        signals.has_benign_code
        or signals.benign_signature is not None
        or signals.false_positive_signature is not None
    )
    if benign_override and not strong_malicious:
        if signals.has_benign_code:
            reasons.append(
                f"known-benign EventCode {signals.event_code} "
                f"(routine operational event)"
            )
        elif signals.benign_signature:
            reasons.append(f"benign signature: '{signals.benign_signature}'")
        else:
            reasons.append(
                f"false-positive signature: '{signals.false_positive_signature}'"
            )
        if signals.is_service_account:
            reasons.append(
                f"service account '{signals.user}' — scheduled/automated activity"
            )
        return FPFilterResult(
            verdict=FALSE_POSITIVE,
            score=score,
            confidence=_confidence_from_reasons(FALSE_POSITIVE, reasons, score),
            reasons=reasons,
            signals=signals.to_dict(),
        )

    # ── Layer 2: strong malicious override ────────────────────────────────────
    if strong_malicious:
        if signals.malicious_signature is None:
            reasons.append(f"score {score:.0f} >= strong-malicious floor")
        return FPFilterResult(
            verdict=TRUE_POSITIVE,
            score=score,
            confidence=_confidence_from_reasons(TRUE_POSITIVE, reasons, score),
            reasons=reasons,
            signals=signals.to_dict(),
        )

    # ── Weak-evidence guard: a successful logon alone is NOT a threat ─────────
    # EventCode 4624 (or any non-failure code) scoring above threshold via
    # severity boost, but with no malicious action and no privileged account,
    # is routine activity — route to REVIEW, not automatic TRUE_POSITIVE.
    weak_evidence = (
        not signals.malicious_signature
        and not signals.is_admin
        and not signals.high_failure_volume
        and event_code not in ("4625", "4688", "4698", "7045", "1102", "4672", "4776", "4932")
    )

    # ── Layer 3: score bins (consistent with the graph's routing) ─────────────
    borderline_low = benign_threshold - borderline_margin
    if score < borderline_low:
        reasons.append(
            f"triage score {score:.0f} below benign threshold "
            f"{benign_threshold:.0f} (band starts at {borderline_low:.0f})"
        )
        return FPFilterResult(
            verdict=FALSE_POSITIVE,
            score=score,
            confidence=_confidence_from_reasons(FALSE_POSITIVE, reasons, score),
            reasons=reasons,
            signals=signals.to_dict(),
        )

    if (score < benign_threshold) or weak_evidence:
        if weak_evidence:
            reasons.append(
                f"'benign activity with a high severity boost — "
                f"successful logon/operation on EventCode {event_code}: "
                f"no malicious signature, no privileged account"
            )
        else:
            reasons.append(
                f"triage score {score:.0f} in borderline band "
                f"[{borderline_low:.0f}, {benign_threshold:.0f}) — needs review"
            )
        if signals.is_admin:
            reasons.append(f"privileged account '{signals.user}' involved")
        return FPFilterResult(
            verdict=REVIEW,
            score=score,
            confidence=_confidence_from_reasons(REVIEW, reasons, score),
            reasons=reasons,
            signals=signals.to_dict(),
        )

    reasons.append(
        f"triage score {score:.0f} >= benign threshold {benign_threshold:.0f}"
    )
    return FPFilterResult(
        verdict=TRUE_POSITIVE,
        score=score,
        confidence=_confidence_from_reasons(TRUE_POSITIVE, reasons, score),
        reasons=reasons,
        signals=signals.to_dict(),
    )
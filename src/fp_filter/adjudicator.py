"""
LLM Adjudicator — resolves REVIEW (borderline) alerts.

The rule classifier is deliberately conservative: alerts scored inside the
borderline band get verdict REVIEW instead of a hard FP/TP call. When the
adjudicator is enabled, those REVIEW alerts are passed to the local LLM
(Ollama) which decides false_positive vs true_positive with a confidence
score and a short rationale.

Every LLM output passes through the guardrails (check_content); a blocked or
unparseable response falls back to REVIEW so a borderline alert is never
silently dropped.
"""
import json

from langchain_ollama import ChatOllama

from src.config import load_config
from src.fp_filter.classifier import FALSE_POSITIVE, TRUE_POSITIVE
from src.guardrails.guardrail_wrapper import check_content

_MODEL = None

ADJUDICATION_PROMPT = """You are a senior SOC analyst. A SIEM alert is BORDERLINE:
the rule-based triage score is near the benign threshold and needs a manual call.

ALERT (JSON):
{alert_json}

TRIAGE SCORE: {score:.1f}/{100}
SIGNALS:
{signals_json}

Decide whether this alert is a FALSE POSITIVE (benign noise — no analyst
attention required) or a TRUE POSITIVE (genuine threat — requires investigation).

The raw triage score is NOT authoritative: use the alert's signature,
EventCode, user, volume/count, and host context to judge intent.

Respond with ONLY JSON in this exact format:
{{"verdict": "true_positive" OR "false_positive", "confidence": 0.0 to 1.0, "rationale": "one sentence"}}"""


def _get_model():
    global _MODEL
    if _MODEL is not None:
        return _MODEL
    cfg = load_config()
    provider = cfg.get("model", {}).get("provider", "ollama")
    if provider == "vllm":
        from langchain_openai import ChatOpenAI
        _MODEL = ChatOpenAI(
            base_url=cfg["model"].get("base_url", "http://localhost:8000/v1"),
            model=cfg["model"].get("model", "Qwen/Qwen3-8B"),
            api_key="not-needed",
            temperature=0.0,
        )
    else:
        _MODEL = ChatOllama(
            model=cfg["model"].get("model", "llama3.2:3b"),
            base_url=cfg["model"].get("base_url", "http://localhost:11434"),
            temperature=0.0,
        )
    return _MODEL


def _extract_json(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass
    return {}


def adjudicate_alert(alert: dict, score: float, signals: dict) -> dict | None:
    """
    Ask the local LLM to resolve a REVIEW alert.

    Args:
        alert: Raw SIEM alert dictionary.
        score: Rule-based triage score.
        signals: Signals dict from extract_signals().

    Returns:
        A dict {"verdict", "confidence", "rationale"} for a decisive call, or
        None if the model is unavailable / output is blocked / unparseable.
    """
    prompt = ADJUDICATION_PROMPT.format(
        alert_json=json.dumps(alert, default=str)[:800],
        score=float(score),
        signals_json=json.dumps(signals, default=str)[:600],
    )

    try:
        model = _get_model()
        response = model.invoke(prompt)
        text = response.content if hasattr(response, "content") else str(response)
    except Exception:  # noqa: BLE001
        return None  # Ollama not running — keep the alert in REVIEW.

    if not text or not isinstance(text, str):
        return None

    result = check_content(text, node_name="fp_filter:adjudicator:output")
    if not result.passed:
        return None  # Guardrail blocked the output — stay in REVIEW.

    parsed = _extract_json(text)
    verdict = str(parsed.get("verdict", "")).lower().strip()
    if verdict not in (TRUE_POSITIVE, FALSE_POSITIVE):
        return None

    try:
        confidence = float(parsed.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    return {
        "verdict": verdict,
        "confidence": confidence,
        "rationale": str(parsed.get("rationale", ""))[:300],
    }
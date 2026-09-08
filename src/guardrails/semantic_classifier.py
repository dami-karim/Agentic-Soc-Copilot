"""
Semantic Classifier — Layer 2 of the two-layer guardrail pipeline.

Detects semantically dangerous content that regex alone cannot catch
— paraphrased injections, indirect jailbreaks, subtle exfiltration.

For Week 6, this uses a simple keyword-based semantic check rather
than a full neural classifier. The architecture is designed to slot
in a real classifier (e.g., Llama Prompt Guard 2 as used in LanG)
without changing any calling code — just replace the classify()
implementation.

Called only when Layer 1 (regex_prefilter) passes, so it only
processes content that isn't obviously malicious.
"""
from src.guardrails.regex_prefilter import GuardrailResult

# Semantic danger categories — keyword clusters that indicate risky intent
# Each category has a threshold: fraction of keywords that must match
SEMANTIC_CATEGORIES = [
    {
        "name": "instruction_override",
        "keywords": ["override", "bypass", "ignore", "disable", "circumvent",
                     "pretend", "roleplay", "act as", "simulate", "hypothetically"],
        "threshold": 0.2,
        "level": "block",
        "reason": "Semantic pattern: possible instruction override attempt"
    },
    {
        "name": "data_exfiltration",
        "keywords": ["send", "upload", "transmit", "exfiltrate", "leak",
                     "export", "copy to", "forward to", "external server"],
        "threshold": 0.15,
        "level": "warn",
        "reason": "Semantic pattern: possible data exfiltration intent"
    },
    {
        "name": "destructive_intent",
        "keywords": ["destroy", "wipe", "erase", "corrupt", "ransomware",
                     "encrypt all", "delete all", "overwrite", "brick"],
        "threshold": 0.15,
        "level": "block",
        "reason": "Semantic pattern: possible destructive intent"
    },
]


def classify(content: str) -> GuardrailResult:
    """
    Semantic check on content that passed regex pre-filter.

    Uses keyword density analysis per semantic category.
    A category triggers if the fraction of its keywords found
    in the content exceeds its threshold.
    """
    if not content or not isinstance(content, str):
        return GuardrailResult(passed=True, level="pass", reason="Empty content")

    content_lower = content.lower()

    for category in SEMANTIC_CATEGORIES:
        keywords = category["keywords"]
        matched = sum(1 for kw in keywords if kw in content_lower)
        density = matched / len(keywords)

        if density >= category["threshold"]:
            level = category["level"]
            passed = (level != "block")
            return GuardrailResult(
                passed=passed,
                level=level,
                reason=category["reason"],
                pattern_matched=f"{matched}/{len(keywords)} keywords matched"
            )

    return GuardrailResult(
        passed=True,
        level="pass",
        reason="No semantic danger patterns detected"
    )

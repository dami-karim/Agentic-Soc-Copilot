"""
Regex Pre-filter — Layer 1 of the two-layer guardrail pipeline.

Scans LLM inputs and outputs for known dangerous patterns BEFORE
the semantic classifier (Layer 2) is applied.

Why regex first:
  - Zero latency (no model inference needed)
  - Catches obvious injection attempts immediately
  - Filters the highest-confidence bad patterns without cost

Following LanG's (arXiv:2604.05440) two-layer guardrail pattern:
  Layer 1: regex pre-filter  (this file)
  Layer 2: semantic classifier (semantic_classifier.py)

If Layer 1 flags content, the call is blocked immediately.
Layer 2 is only called if Layer 1 passes.
"""
import re
from dataclasses import dataclass


@dataclass
class GuardrailResult:
    passed: bool
    level: str        # "pass", "warn", "block"
    reason: str
    pattern_matched: str | None = None


# Patterns that BLOCK execution immediately — high confidence bad input
BLOCK_PATTERNS = [
    # Prompt injection attempts
    (r"ignore\s+(all\s+)?previous\s+instructions", "Prompt injection: ignore previous instructions"),
    (r"you\s+are\s+now\s+(a\s+)?different", "Prompt injection: persona override"),
    (r"forget\s+(everything|all)\s+(you|i)\s+(were|told)", "Prompt injection: forget instructions"),
    (r"jailbreak", "Prompt injection: jailbreak attempt"),
    (r"<\s*script\s*>", "XSS injection attempt"),

    # Destructive command injection
    (r"rm\s+-rf\s+/", "Destructive command: rm -rf /"),
    (r"format\s+c:", "Destructive command: format drive"),
    (r"DROP\s+TABLE", "SQL injection: DROP TABLE"),
    (r";\s*DELETE\s+FROM", "SQL injection: DELETE FROM"),

    # Exfiltration patterns
    (r"curl\s+.*\|\s*bash", "Exfiltration: curl pipe to bash"),
    (r"wget\s+.*\|\s*sh", "Exfiltration: wget pipe to shell"),
    (r"base64\s+--decode\s+.*\|\s*(bash|sh)", "Exfiltration: base64 decode pipe to shell"),
]

# Patterns that WARN but do not block — suspicious but potentially legitimate
WARN_PATTERNS = [
    (r"sudo\s+", "Privileged command: sudo detected"),
    (r"chmod\s+777", "Permissive chmod: 777 detected"),
    (r"eval\s*\(", "Dynamic eval() detected"),
    (r"exec\s*\(", "Dynamic exec() detected"),
    (r"\.\./\.\./", "Path traversal: ../ detected"),
    (r"password\s*=\s*['\"]?\w+['\"]?", "Hardcoded password pattern detected"),
]

# Compile all patterns once at module load
_BLOCK_COMPILED = [(re.compile(p, re.IGNORECASE), msg) for p, msg in BLOCK_PATTERNS]
_WARN_COMPILED = [(re.compile(p, re.IGNORECASE), msg) for p, msg in WARN_PATTERNS]


def check(content: str, context: str = "") -> GuardrailResult:
    """
    Scans content for dangerous patterns.

    Args:
        content: The text to scan (LLM input, LLM output, or tool argument)
        context: Optional description of what's being scanned (for logging)

    Returns:
        GuardrailResult with passed=False if blocked or warned
    """
    if not content or not isinstance(content, str):
        return GuardrailResult(passed=True, level="pass", reason="Empty or non-string content")

    # Check block patterns first
    for pattern, reason in _BLOCK_COMPILED:
        match = pattern.search(content)
        if match:
            return GuardrailResult(
                passed=False,
                level="block",
                reason=f"BLOCKED: {reason}",
                pattern_matched=match.group(0)
            )

    # Check warn patterns
    for pattern, reason in _WARN_COMPILED:
        match = pattern.search(content)
        if match:
            return GuardrailResult(
                passed=True,
                level="warn",
                reason=f"WARNING: {reason}",
                pattern_matched=match.group(0)
            )

    return GuardrailResult(passed=True, level="pass", reason="No dangerous patterns detected")

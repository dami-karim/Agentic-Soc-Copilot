"""
Validators — Structured argument validation for tool calls and LLM outputs.

This file implements the three validation functions referenced in the
Week 6 plan table:
  - validate_tool_args(tool_name, args) — checks tool arguments against schemas
  - validate_attack_techniques(techniques, threshold) — filters low-confidence tags
  - validate_llm_output(output, schema) — validates LLM response format

Why this file exists separately from guardrail_wrapper.py:
  guardrail_wrapper.py handles content safety (injection detection, semantic danger).
  validators.py handles structural correctness (is this a valid IP? is this a real
  ATT&CK ID? does this JSON match the expected schema?). These are two different
  concerns — content safety vs. data integrity — so they live in separate files.
"""
import re
import ipaddress
from dataclasses import dataclass


@dataclass
class ValidationResult:
    valid: bool
    reason: str
    sanitized_value: object = None


# ── Tool argument schemas ─────────────────────────────────────────────────────
# Each tool has a schema defining what valid arguments look like.
# validate_tool_args() checks incoming arguments against these schemas
# BEFORE the tool is actually called.

TOOL_SCHEMAS = {
    "search_logs": {
        "query": {"type": "str", "max_length": 500, "required": True},
    },
    "query_blast_radius": {
        "start_node_id": {"type": "str", "max_length": 100, "required": True},
        "max_hops": {"type": "int", "min": 1, "max": 5, "required": False},
    },
    "search_similar_incidents": {
        "query_text": {"type": "str", "max_length": 500, "required": True},
        "top_k": {"type": "int", "min": 1, "max": 20, "required": False},
    },
    "search_attack_techniques": {
        "data_component": {"type": "str", "max_length": 300, "required": True},
        "top_k": {"type": "int", "min": 1, "max": 20, "required": False},
    },
}

# Valid ATT&CK technique ID format: T followed by 4 digits,
# optionally followed by a dot and 3 digits (sub-technique)
# Case-insensitive to accept lowercase input (normalized to uppercase)
ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)

# Valid hostname: alphanumeric with hyphens and dots
HOSTNAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
)


def _validate_string_field(value: object, schema: dict) -> ValidationResult:
    """Validates a string field against its schema definition."""
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            return ValidationResult(valid=False, reason=f"Cannot convert to string: {value!r}")

    max_len = schema.get("max_length", 1000)
    if len(value) > max_len:
        truncated = value[:max_len]
        return ValidationResult(
            valid=True,
            reason=f"String truncated from {len(value)} to {max_len} chars",
            sanitized_value=truncated
        )

    return ValidationResult(valid=True, reason="Valid string", sanitized_value=value)


def _validate_int_field(value: object, schema: dict) -> ValidationResult:
    """Validates an integer field against its schema definition."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return ValidationResult(valid=False, reason=f"Cannot convert to int: {value!r}")

    min_val = schema.get("min")
    max_val = schema.get("max")

    if min_val is not None and value < min_val:
        clamped = min_val
        return ValidationResult(
            valid=True,
            reason=f"Int {value} clamped to minimum {min_val}",
            sanitized_value=clamped
        )

    if max_val is not None and value > max_val:
        clamped = max_val
        return ValidationResult(
            valid=True,
            reason=f"Int {value} clamped to maximum {max_val}",
            sanitized_value=clamped
        )

    return ValidationResult(valid=True, reason="Valid int", sanitized_value=value)


def validate_tool_args(tool_name: str, args: dict) -> dict[str, ValidationResult]:
    """
    Validates all arguments for a named tool against its schema.

    Args:
        tool_name: The name of the tool being called (must be in TOOL_SCHEMAS)
        args: Dictionary of argument name -> value

    Returns:
        Dictionary of argument name -> ValidationResult.
        All results must have valid=True before the tool should be called.

    Example:
        results = validate_tool_args("search_logs", {"query": "EventCode:4625"})
        if all(r.valid for r in results.values()):
            # safe to call the tool
    """
    schema = TOOL_SCHEMAS.get(tool_name)
    if not schema:
        return {k: ValidationResult(valid=True, reason=f"No schema for tool '{tool_name}'")
                for k in args}

    results = {}

    for arg_name, field_schema in schema.items():
        required = field_schema.get("required", False)

        if arg_name not in args:
            if required:
                results[arg_name] = ValidationResult(
                    valid=False,
                    reason=f"Required argument '{arg_name}' missing"
                )
            continue

        value = args[arg_name]
        field_type = field_schema.get("type", "str")

        if field_type == "str":
            result = _validate_string_field(value, field_schema)
        elif field_type == "int":
            result = _validate_int_field(value, field_schema)
        else:
            result = ValidationResult(valid=True, reason=f"Unknown type '{field_type}' -- skipped")

        results[arg_name] = result

    # Flag unexpected arguments not in schema
    for arg_name in args:
        if arg_name not in schema:
            results[arg_name] = ValidationResult(
                valid=True,
                reason=f"Unexpected argument '{arg_name}' -- passed through"
            )

    return results


def validate_attack_techniques(
    techniques: list[dict],
    threshold: float = 0.3
) -> list[dict]:
    """
    Filters and validates a list of ATT&CK technique assignments.

    Validation rules:
      1. technique_id must match the ATT&CK ID format (T\\d{4}(\\.\\d{3})?)
      2. confidence must be a float between 0 and 1
      3. Techniques below the confidence threshold are filtered out
      4. technique_name must be a non-empty string

    Args:
        techniques: List of technique dicts with technique_id, technique_name, confidence
        threshold: Minimum confidence to keep a technique (default 0.3)

    Returns:
        Filtered list of valid, high-confidence techniques
    """
    validated = []

    for t in techniques:
        tid = t.get("technique_id", "")
        if not ATTACK_ID_PATTERN.match(str(tid)):
            continue

        try:
            conf = float(t.get("confidence", 0))
        except (TypeError, ValueError):
            conf = 0.0

        if conf < threshold:
            continue

        name = t.get("technique_name", "")
        if not name or not isinstance(name, str):
            continue

        t_clean = dict(t)
        t_clean["confidence"] = round(min(max(conf, 0.0), 1.0), 3)
        t_clean["technique_id"] = tid.upper()

        validated.append(t_clean)

    return validated


def validate_llm_output(output: str, schema: dict) -> ValidationResult:
    """
    Validates that an LLM response matches an expected schema.

    For structured outputs (JSON), checks that required keys are present.
    For free-text outputs, checks minimum length and absence of refusal patterns.

    Args:
        output: The LLM's raw output string
        schema: Dict describing expected format:
            {"type": "json", "required_keys": [...]}  for JSON outputs
            {"type": "text", "min_length": N}          for text outputs

    Returns:
        ValidationResult with valid=True if output matches schema
    """
    if not output or not isinstance(output, str):
        return ValidationResult(valid=False, reason="LLM output is empty or not a string")

    output_type = schema.get("type", "text")

    if output_type == "json":
        import json
        clean = output.strip()
        if clean.startswith("```"):
            lines = clean.split("\n")
            clean = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        try:
            parsed = json.loads(clean)
        except json.JSONDecodeError as e:
            return ValidationResult(
                valid=False,
                reason=f"LLM output is not valid JSON: {e}",
                sanitized_value=None
            )

        required_keys = schema.get("required_keys", [])
        missing = [k for k in required_keys if k not in parsed]
        if missing:
            return ValidationResult(
                valid=False,
                reason=f"LLM JSON output missing required keys: {missing}",
                sanitized_value=parsed
            )

        return ValidationResult(valid=True, reason="Valid JSON output", sanitized_value=parsed)

    else:
        min_length = schema.get("min_length", 10)
        if len(output.strip()) < min_length:
            return ValidationResult(
                valid=False,
                reason=f"LLM output too short: {len(output)} chars (min {min_length})"
            )

        refusal_patterns = [
            "i cannot", "i can't", "i'm unable", "as an ai",
            "i don't have access", "i am not able"
        ]
        output_lower = output.lower()
        for pattern in refusal_patterns:
            if pattern in output_lower:
                return ValidationResult(
                    valid=False,
                    reason=f"LLM output appears to be a refusal: '{pattern}' detected",
                    sanitized_value=output
                )

        return ValidationResult(valid=True, reason="Valid text output", sanitized_value=output)

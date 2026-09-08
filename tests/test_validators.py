"""
Tests for the validators module — schema validation, ATT&CK ID validation,
and LLM output validation.
"""
import pytest
from src.guardrails.validators import (
    ValidationResult,
    validate_tool_args,
    validate_attack_techniques,
    validate_llm_output,
    TOOL_SCHEMAS,
    ATTACK_ID_PATTERN,
)


class TestValidationResult:

    def test_valid_result(self):
        result = ValidationResult(valid=True, reason="OK")
        assert result.valid is True
        assert result.reason == "OK"

    def test_invalid_result(self):
        result = ValidationResult(valid=False, reason="Bad")
        assert result.valid is False
        assert result.reason == "Bad"

    def test_sanitized_value(self):
        result = ValidationResult(valid=True, reason="Truncated", sanitized_value="abc")
        assert result.sanitized_value == "abc"


class TestValidateToolArgs:

    def test_search_logs_valid(self):
        results = validate_tool_args("search_logs", {"query": "EventCode:4625"})
        assert results["query"].valid is True
        assert results["query"].sanitized_value == "EventCode:4625"

    def test_search_logs_truncates_long_query(self):
        long_query = "x" * 600
        results = validate_tool_args("search_logs", {"query": long_query})
        assert results["query"].valid is True
        assert len(results["query"].sanitized_value) == 500

    def test_query_blast_radius_valid(self):
        results = validate_tool_args("query_blast_radius", {
            "start_node_id": "WIN-DC01", "max_hops": 3
        })
        assert results["start_node_id"].valid is True
        assert results["max_hops"].valid is True

    def test_query_blast_radius_max_hops_clamped(self):
        results = validate_tool_args("query_blast_radius", {
            "start_node_id": "WIN-DC01", "max_hops": 10
        })
        assert results["max_hops"].sanitized_value == 5  # clamped to max

    def test_query_blast_radius_max_hops_too_low(self):
        results = validate_tool_args("query_blast_radius", {
            "start_node_id": "WIN-DC01", "max_hops": 0
        })
        assert results["max_hops"].sanitized_value == 1  # clamped to min
        assert "minimum" in results["max_hops"].reason

    def test_missing_required_argument(self):
        results = validate_tool_args("search_logs", {"index": "soc-alerts"})
        assert results["query"].valid is False
        assert "missing" in results["query"].reason.lower()

    def test_unknown_tool_passes_through(self):
        results = validate_tool_args("unknown_tool", {"foo": "bar"})
        assert results["foo"].valid is True

    def test_unexpected_argument_flagged(self):
        results = validate_tool_args("search_logs", {"query": "test", "extra": "data"})
        assert "extra" in results
        assert results["extra"].valid is True  # allowed but flagged in reason


class TestAttackIdPattern:

    def test_valid_base_technique(self):
        assert ATTACK_ID_PATTERN.match("T1110") is not None

    def test_valid_sub_technique(self):
        assert ATTACK_ID_PATTERN.match("T1110.001") is not None

    def test_invalid_no_t(self):
        assert ATTACK_ID_PATTERN.match("1110") is None

    def test_invalid_short(self):
        assert ATTACK_ID_PATTERN.match("T111") is None

    def test_invalid_wrong_subformat(self):
        assert ATTACK_ID_PATTERN.match("T1110.01") is None  # needs 3 digits


class TestValidateAttackTechniques:

    def test_valid_technique_kept(self):
        techniques = [
            {"technique_id": "T1110", "technique_name": "Brute Force", "confidence": 0.9}
        ]
        result = validate_attack_techniques(techniques)
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1110"

    def test_invalid_technique_id_filtered(self):
        techniques = [
            {"technique_id": "INVALID", "technique_name": "Bad", "confidence": 0.9}
        ]
        result = validate_attack_techniques(techniques)
        assert len(result) == 0

    def test_low_confidence_filtered(self):
        techniques = [
            {"technique_id": "T1110", "technique_name": "Brute Force", "confidence": 0.1}
        ]
        result = validate_attack_techniques(techniques, threshold=0.3)
        assert len(result) == 0

    def test_custom_threshold(self):
        techniques = [
            {"technique_id": "T1110", "technique_name": "Brute Force", "confidence": 0.5}
        ]
        result = validate_attack_techniques(techniques, threshold=0.4)
        assert len(result) == 1

    def test_sub_technique_valid(self):
        techniques = [
            {"technique_id": "T1110.001", "technique_name": "Password Spraying", "confidence": 0.85}
        ]
        result = validate_attack_techniques(techniques)
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1110.001"

    def test_confidence_clamped(self):
        techniques = [
            {"technique_id": "T1110", "technique_name": "Brute Force", "confidence": 1.5}
        ]
        result = validate_attack_techniques(techniques)
        assert result[0]["confidence"] == 1.0

    def test_missing_technique_name_filtered(self):
        techniques = [
            {"technique_id": "T1110", "technique_name": "", "confidence": 0.9}
        ]
        result = validate_attack_techniques(techniques)
        assert len(result) == 0

    def test_empty_list(self):
        result = validate_attack_techniques([])
        assert result == []

    def test_technique_id_uppercased(self):
        techniques = [
            {"technique_id": "t1110", "technique_name": "Brute Force", "confidence": 0.9}
        ]
        result = validate_attack_techniques(techniques)
        assert len(result) == 1
        # The validator calls .upper() on the technique_id
        assert result[0]["technique_id"] == "T1110"


class TestValidateLlmOutput:

    def test_valid_text_output(self):
        result = validate_llm_output("This is a sufficient investigation summary", {"type": "text"})
        assert result.valid is True

    def test_short_text_rejected(self):
        result = validate_llm_output("hi", {"type": "text", "min_length": 20})
        assert result.valid is False
        assert "short" in result.reason.lower()

    def test_empty_output_rejected(self):
        result = validate_llm_output("", {"type": "text"})
        assert result.valid is False

    def test_refusal_detected(self):
        result = validate_llm_output("I cannot help with that request", {"type": "text"})
        assert result.valid is False
        assert "refusal" in result.reason.lower()

    def test_valid_json_output(self):
        result = validate_llm_output('{"key": "value"}', {"type": "json", "required_keys": ["key"]})
        assert result.valid is True
        assert result.sanitized_value == {"key": "value"}

    def test_json_missing_required_key(self):
        result = validate_llm_output('{"key": "value"}', {"type": "json", "required_keys": ["missing"]})
        assert result.valid is False
        assert "missing required" in result.reason.lower()

    def test_invalid_json_rejected(self):
        result = validate_llm_output("not json at all", {"type": "json", "required_keys": ["key"]})
        assert result.valid is False

    def test_json_with_markdown_fence(self):
        output = '```json\n{"key": "value"}\n```'
        result = validate_llm_output(output, {"type": "json", "required_keys": ["key"]})
        assert result.valid is True

    def test_non_string_output_rejected(self):
        result = validate_llm_output(None, {"type": "text"})
        assert result.valid is False

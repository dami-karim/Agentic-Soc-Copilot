"""
Week 8 — LLM-based ATT&CK technique mapping tool wrapper.

This replaces the keyword-based search_attack_techniques tool with
RAM's 6-step LLM pipeline for higher precision/recall classification.

The LLM mapper performs multi-step reasoning:
  1. Extract IoCs from alert + findings
  2. Retrieve ATT&CK technique context (RAG)
  3. Translate observations to natural language
  5. Propose candidates with Chain-of-Thought
  6. Validate & select final technique set

RAM achieves AR=0.75/AP=0.52 with this approach vs 0.46/0.31 zero-shot.
"""
from langchain_core.tools import tool
from src.llm.attack_mapper import LLMAttackMapper
from src.guardrails.guardrail_wrapper import check_content


_mapper = LLMAttackMapper()


@tool
def classify_attack_techniques(alert_json: str, findings_json: str) -> str:
    """Map a SIEM alert and investigation findings to MITRE ATT&CK technique
    IDs using LLM-based multi-step reasoning (RAM's 6-step pipeline).

    Use this tool to classify the observed behavior of an alert into specific
    ATT&CK technique IDs (e.g. T1110 for Brute Force, T1059 for Command
    Execution). Unlike keyword matching, this tool uses Chain-of-Thought
    reasoning to understand the attacker's intent and behavior.

    Args:
        alert_json: The raw SIEM alert as a JSON string. Must include fields
                    like EventCode, host, src_ip, user, signature, severity.
                    Example: '{"EventCode": "4625", "host": "WIN-DC01", ...}'
        findings_json: Investigation findings as a JSON string. Include any
                       IoCs, log context, or blast-radius results discovered
                       during investigation. Example: '{"ioc_list": [...],
                       "enrichment": {...}}'

    Returns:
        JSON string with technique mappings: each entry has technique_id,
        technique_name, confidence (0-1), and rationale.
    """
    # Guardrail: content safety
    safety = check_content(alert_json, node_name="classify_attack_techniques:alert")
    if not safety.passed:
        return f"{'BLOCKED by guardrail: ' + safety.reason}"

    safety2 = check_content(findings_json, node_name="classify_attack_techniques:findings")
    if not safety2.passed:
        return f"{'BLOCKED by guardrail: ' + safety2.reason}"

    import json
    try:
        alert = json.loads(alert_json)
    except json.JSONDecodeError:
        return f"{'BLOCKED by schema validation: alert_json is not valid JSON'}"

    try:
        findings = json.loads(findings_json) if findings_json else {}
    except json.JSONDecodeError:
        findings = {}

    techniques = _mapper.map_techniques(alert, findings)
    return str(techniques)

"""
Guardrail Wrapper — Applies both guardrail layers to any content.

This is the single entry point for guardrail checks throughout
the pipeline. Every LLM call and tool call passes through here.

Usage:
    from src.guardrails.guardrail_wrapper import check_content, apply_to_state

    result = check_content(content, node_name="attack_tagger")
    if not result.passed:
        # handle block
        pass

The wrapper:
  1. Runs regex pre-filter (Layer 1)
  2. If Layer 1 passes, runs semantic classifier (Layer 2)
  3. Returns a combined GuardrailResult
  4. Logs flags to state["guardrail_flags"] via apply_to_state()
"""
from datetime import datetime, timezone
from src.guardrails.regex_prefilter import check as regex_check, GuardrailResult
from src.guardrails.semantic_classifier import classify as semantic_check
from src.state import SOCAgentState


def check_content(content: str, node_name: str = "unknown") -> GuardrailResult:
    """
    Runs both guardrail layers on content.

    Layer 1: regex pre-filter
    Layer 2: semantic classifier (only if Layer 1 passes)

    Returns the most severe result from either layer.
    """
    # Layer 1
    layer1 = regex_check(content, context=node_name)
    if not layer1.passed:
        return layer1  # Blocked immediately — don't run Layer 2

    # Layer 2
    layer2 = semantic_check(content)
    if not layer2.passed or layer2.level == "warn":
        return layer2

    return layer1  # Both passed


def apply_to_state(
    state: SOCAgentState,
    content: str,
    node_name: str,
    check_type: str = "output"
) -> tuple[SOCAgentState, bool]:
    """
    Runs guardrail check and logs result to state.

    Args:
        state: Current SOCAgentState
        content: Content to check
        node_name: Name of the node calling this
        check_type: "input" or "output" (for logging context)

    Returns:
        (updated_state, should_continue)
        should_continue=False means the node should abort
    """
    result = check_content(content, node_name=node_name)

    if result.level != "pass":
        state["guardrail_flags"].append({
            "node": node_name,
            "check_type": check_type,
            "level": result.level,
            "reason": result.reason,
            "pattern_matched": result.pattern_matched,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    should_continue = result.passed
    return state, should_continue


def check_tool_argument(
    state: SOCAgentState,
    tool_name: str,
    argument_name: str,
    argument_value: str,
    node_name: str
) -> tuple[SOCAgentState, bool]:
    """
    Validates a tool argument before the tool is called.

    This is the specific mechanism the MDPI survey identified as
    the most common failure mode — hallucinated or injected tool
    arguments. This function checks the argument value before
    passing it to the tool.

    Returns:
        (updated_state, argument_is_safe)
    """
    content = str(argument_value)
    result = check_content(content, node_name=f"{node_name}:{tool_name}:{argument_name}")

    if result.level != "pass":
        state["guardrail_flags"].append({
            "node": node_name,
            "check_type": "tool_argument",
            "tool": tool_name,
            "argument": argument_name,
            "value": content[:200],
            "level": result.level,
            "reason": result.reason,
            "pattern_matched": result.pattern_matched,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    return state, result.passed
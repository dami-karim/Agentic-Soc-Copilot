"""
LangChain @tool wrappers for the four agent tools.

Each function below wraps one of the ABC-based tool classes from
interfaces.py / opensearch_tool.py / neo4j_tool.py / qdrant_tool.py /
attack_corpus_tool.py, converting them into LangChain @tool-decorated
functions that an LLM can call dynamically inside a ReAct agent.

The LLM sees the docstring of each function as the tool description,
so every docstring must clearly explain:
  - What the tool does
  - What each argument means
  - What the tool returns

Week 6: Each tool now has TWO layers of protection before execution:
  1. Schema validation (validate_tool_args) — checks types, lengths, ranges
  2. Content safety (check_content) — blocks injection, XSS, destructive cmds
"""
from datetime import datetime, timezone
from langchain_core.tools import tool
from src.tools.opensearch_tool import OpenSearchLogTool
from src.tools.neo4j_tool import Neo4jGraphTool
from src.tools.qdrant_tool import QdrantIncidentTool
from src.tools.attack_corpus_tool import AttackStixTool
from src.guardrails.guardrail_wrapper import check_content
from src.guardrails.validators import validate_tool_args, ValidationResult

# Instantiate each tool class ONCE at module level.
# This avoids reconnecting to the database on every single tool call,
# which would be extremely slow in a multi-step ReAct loop.
_log_tool = OpenSearchLogTool()
_graph_tool = Neo4jGraphTool()
_incident_tool = QdrantIncidentTool()
_attack_tool = AttackStixTool()

# Module-level accumulator for guardrail violations detected during tool execution.
# The ReAct agent's tools don't have access to SOCAgentState, so we collect flags
# here and merge them into state in investigate_node after the agent finishes.
_guardrail_log: list[dict] = []


def get_guardrail_log() -> list[dict]:
    """Return accumulated guardrail flags from tool calls, then clear the log."""
    global _guardrail_log
    flags = _guardrail_log
    _guardrail_log = []
    return flags


def _log_guardrail_flag(tool_name: str, arg_name: str, value: str,
                        result: ValidationResult | None = None,
                        check_result=None):
    """Helper to log a guardrail flag."""
    if result is None:
        return  # No flag to log

    _guardrail_log.append({
        "node": tool_name,
        "check_type": "tool_argument",
        "argument": arg_name,
        "value": str(value)[:200],
        "level": check_result.level if check_result else "warn",
        "reason": result.reason,
        "pattern_matched": check_result.pattern_matched if check_result else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@tool
def search_logs(query: str) -> str:
    """Search the OpenSearch SIEM log store for events matching the given query.

    Use this tool when you need to find related log events for an IP address,
    hostname, username, or other indicator found in an alert. The query is a
    free-text search string that matches against all fields in the log index.

    Args:
        query: The search string. Can be an IP address, hostname, username,
               EventCode, or any free-text query (e.g. "10.0.2.15", "WIN-DC01",
               "4625", "administrator").

    Returns:
        A list of matching log event dictionaries, or an error message string
        if the search fails (e.g. OpenSearch is not running).
    """
    # GUARDRAIL 1: Schema validation (type, length)
    schema_results = validate_tool_args("search_logs", {"query": query})
    for arg_name, result in schema_results.items():
        if not result.valid:
            _log_guardrail_flag("search_logs", arg_name, query, result)
            return f"BLOCKED by schema validation: {result.reason}"

    # GUARDRAIL 2: Content safety (injection, XSS, destructive cmds)
    safety_result = check_content(query, node_name="search_logs:query")
    if not safety_result.passed:
        _log_guardrail_flag("search_logs", "query", query, safety_result)
        return f"BLOCKED by guardrail: {safety_result.reason}"

    # Use sanitized value if schema validation truncated it
    validated_query = schema_results["query"].sanitized_value
    results = _log_tool.search(validated_query, time_range=("now-30d", "now"))
    return str(results)


@tool
def query_blast_radius(host_id: str, max_hops: int = 3) -> str:
    """Query the Neo4j asset/identity graph to find all assets reachable from
    a given host or user within max_hops hops.

    Use this tool when you need to understand the blast radius of a compromise
    — i.e. what other machines, accounts, or services the attacker could reach
    from a compromised starting point via network connections or authentication
    relationships.

    Args:
        host_id: The identifier of the starting node (e.g. "WIN-DC01",
                 "administrator"). Must match an existing node id in the graph.
        max_hops: Maximum number of relationship hops to traverse (default 3).
                  1 hop = direct connection, 2 hops = two-step lateral movement.

    Returns:
        A dictionary with keys: start_node, max_hops, reachable_assets (list of
        dicts with id, labels, hops), and reachable_count.
    """
    # GUARDRAIL 1: Schema validation
    schema_results = validate_tool_args("query_blast_radius", {
        "start_node_id": host_id, "max_hops": max_hops
    })
    for arg_name, result in schema_results.items():
        if not result.valid:
            _log_guardrail_flag("query_blast_radius", arg_name, str(locals()[arg_name]), result)
            return f"BLOCKED by schema validation: {result.reason}"

    # GUARDRAIL 2: Content safety
    safety_result = check_content(host_id, node_name="query_blast_radius:host_id")
    if not safety_result.passed:
        _log_guardrail_flag("query_blast_radius", "host_id", host_id, safety_result)
        return f"BLOCKED by guardrail: {safety_result.reason}"

    validated_host_id = schema_results["start_node_id"].sanitized_value
    validated_max_hops = schema_results["max_hops"].sanitized_value if "max_hops" in schema_results else max_hops
    result_data = _graph_tool.blast_radius(validated_host_id, validated_max_hops)
    return str(result_data)


@tool
def search_similar_incidents(description: str) -> str:
    """Search the Qdrant vector store for past incidents similar to the given
    description.

    Use this tool when you want to find precedent — prior incidents that had
    similar characteristics — to inform your investigation. Similar incidents
    include their resolution and the ATT&CK technique that was identified.

    Args:
        description: A plain-text description of the current alert or
                     investigation finding. The more specific, the better the
                     retrieval. Example: "Repeated failed logons EventCode 4625
                     on WIN-DC01 from IP 10.0.2.15".

    Returns:
        A list of similar incident dictionaries, each containing a similarity
        score, incident_id, technique, and resolution.
    """
    # GUARDRAIL 1: Schema validation
    schema_results = validate_tool_args("search_similar_incidents", {"query_text": description})
    for arg_name, result in schema_results.items():
        if not result.valid:
            _log_guardrail_flag("search_similar_incidents", arg_name, description, result)
            return f"BLOCKED by schema validation: {result.reason}"

    # GUARDRAIL 2: Content safety
    safety_result = check_content(description, node_name="search_similar_incidents:description")
    if not safety_result.passed:
        _log_guardrail_flag("search_similar_incidents", "description", description, safety_result)
        return f"BLOCKED by guardrail: {safety_result.reason}"

    validated_desc = schema_results["query_text"].sanitized_value
    results = _incident_tool.similar_incidents(validated_desc, top_k=3)
    return str(results)


@tool
def search_attack_techniques(keywords: str) -> str:
    """Search the MITRE ATT&CK STIX corpus for techniques that match the given
    keywords.

    Use this tool when you need to identify which ATT&CK technique IDs
    correspond to observed attacker behavior. The keywords should describe the
    behavior you observed (e.g. "brute force logon failed authentication",
    "powershell encoded command", "scheduled task persistence").

    Args:
        keywords: Space-separated keywords describing the observed behavior.
                  Multiple keywords improve precision — each keyword is matched
                  against technique names and descriptions independently.

    Returns:
        A list of matching technique dictionaries, each containing:
        technique_id (e.g. "T1110"), technique_name, description (first 200
        chars), and a relevance score. Results are sorted by score descending.
    """
    # GUARDRAIL 1: Schema validation
    schema_results = validate_tool_args("search_attack_techniques", {"data_component": keywords})
    for arg_name, result in schema_results.items():
        if not result.valid:
            _log_guardrail_flag("search_attack_techniques", arg_name, keywords, result)
            return f"BLOCKED by schema validation: {result.reason}"

    # GUARDRAIL 2: Content safety
    safety_result = check_content(keywords, node_name="search_attack_techniques:keywords")
    if not safety_result.passed:
        _log_guardrail_flag("search_attack_techniques", "keywords", keywords, safety_result)
        return f"BLOCKED by guardrail: {safety_result.reason}"

    validated_keywords = schema_results["data_component"].sanitized_value
    results = _attack_tool.query_techniques(validated_keywords, top_k=5)
    return str(results)

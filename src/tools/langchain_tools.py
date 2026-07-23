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
"""
from langchain_core.tools import tool
from src.tools.opensearch_tool import OpenSearchLogTool
from src.tools.neo4j_tool import Neo4jGraphTool
from src.tools.qdrant_tool import QdrantIncidentTool
from src.tools.attack_corpus_tool import AttackStixTool

# Instantiate each tool class ONCE at module level.
# This avoids reconnecting to the database on every single tool call,
# which would be extremely slow in a multi-step ReAct loop.
_log_tool = OpenSearchLogTool()
_graph_tool = Neo4jGraphTool()
_incident_tool = QdrantIncidentTool()
_attack_tool = AttackStixTool()


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
    results = _log_tool.search(query, time_range=("now-30d", "now"))
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
    result = _graph_tool.blast_radius(host_id, max_hops)
    return str(result)


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
    results = _incident_tool.similar_incidents(description, top_k=3)
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
    results = _attack_tool.query_techniques(keywords, top_k=5)
    return str(results)


# ──────────────────────────────────────────────────────────────────────────────
# WHAT WAS DONE HERE — Teaching Notes
# ──────────────────────────────────────────────────────────────────────────────
#
# WHY WE NEED THIS FILE:
# ────────────────────────
# The original tool classes (OpenSearchLogTool, Neo4jGraphTool, etc.) are
# plain Python classes with abstract base classes (ABCs). They work fine for
# calling from code, but an LLM cannot "see" or "call" a Python class method.
# To let the LLM dynamically choose and invoke tools during a ReAct loop,
# we need to wrap them as LangChain "tools".
#
# WHAT IS A LANGCHAIN @tool?
# ──────────────────────────
# When you decorate a function with @tool, LangChain:
#   1. Extracts the function name → becomes the tool name the LLM sees
#   2. Extracts the docstring → becomes the tool description the LLM reads
#   3. Inspects the type hints → builds a JSON schema for the arguments
#   4. Makes it callable by the LLM via a standard tool_call mechanism
#
# The LLM receives a list of available tools with their names and descriptions.
# When it decides to use a tool, it emits a tool_call with the tool name and
# a JSON object of arguments. LangGraph's ToolNode then executes the actual
# Python function and feeds the result back to the LLM as a ToolMessage.
#
# WHY MODULE-LEVEL INSTANCES?
# ──────────────────────────
# We create _log_tool, _graph_tool, etc. ONCE when the module is imported,
# not inside each function. This means:
#   - The OpenSearch/Neo4j/Qdrant connections are opened once and reused
#   - The ATT&CK STIX data is loaded from disk once (it's ~10MB JSON)
#   - No cold-start penalty on every tool call
#   - In a ReAct loop that might call 5-10 tools, this matters a LOT
#
# WHAT THE LLM SEES VS WHAT ACTUALLY HAPPENS:
# ───────────────────────────────────────────
# The LLM sees:
#   - Tool name: "search_logs"
#   - Description: "Search the OpenSearch SIEM log store..."
#   - Arguments: {"query": {"type": "string", "description": "..."}}
#
# What actually happens when the LLM calls search_logs("10.0.2.15"):
#   1. LangGraph's ToolNode receives the tool_call
#   2. It looks up "search_logs" in the tools list
#   3. It calls search_logs.invoke({"query": "10.0.2.15"})
#   4. Inside the function, _log_tool.search("10.0.2.15") runs
#   5. The result string is returned as a ToolMessage to the LLM
#   6. The LLM reads the result and decides its next action
#
# ──────────────────────────────────────────────────────────────────────────────

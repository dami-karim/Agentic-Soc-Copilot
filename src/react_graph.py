"""
ReAct Investigation Agent — The dynamic tool-calling brain of the pipeline.

This module builds a ReAct (Reason + Act) agent using LangGraph's
create_react_agent. Unlike the fixed pipeline in the original graph.py,
this agent DYNAMICALLY decides which tools to call, in what order, and
how many times — mimicking how a real SOC analyst investigates an alert.

The ReAct loop:
  1. PLAN:    LLM reads the alert and decides what to investigate first
  2. TOOL_CALL: LLM selects a tool (search_logs, query_blast_radius, etc.)
  3. OBSERVE: Tool returns results to the LLM
  4. REFINE:  LLM integrates the new info and decides next step
  5. REPEAT   until the LLM has enough evidence to produce a final answer

This replaces the fixed "analyze_logs → attack_tagger" path from Week 3's
original graph with a dynamic, multi-step investigation.
"""
import os
from langgraph.prebuilt import create_react_agent
from langchain_ollama import ChatOllama
from src.tools.langchain_tools import (
    search_logs,
    query_blast_radius,
    search_similar_incidents,
    search_attack_techniques,
)
try:
    from src.llm.langchain_attack_mapper import classify_attack_techniques
    _HAS_LLM_MAPPER = True
except Exception:
    _HAS_LLM_MAPPER = False


# ──────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT — The LLM's "job description" for the investigation
# ──────────────────────────────────────────────────────────────────────────────
# This prompt is critical. It tells the LLM:
#   - What role it plays (SOC analyst)
#   - What tools it has and when to use each one
#   - What order to investigate in (systematic, not random)
#   - What format to output at the end
#
# The prompt is intentionally short because we're using a 3B-parameter model
# (llama3.2:3b) which has limited context window and reasoning ability.
# A larger model (Qwen3-8B, Llama-3.1-8B) would get a more detailed prompt.
INVESTIGATION_SYSTEM_PROMPT = """You are a SOC Tier-2 analyst investigating a SIEM alert.

AVAILABLE TOOLS:
- search_logs: Search SIEM logs for related events (IPs, hosts, users, event codes)
- query_blast_radius: Check what assets a compromised host/user can reach (Neo4j graph)
- search_similar_incidents: Find past incidents with similar patterns
- search_attack_techniques: Map observed behaviors to MITRE ATT&CK technique IDs

INVESTIGATION STEPS:
1. Search logs around the source IP and affected host for related events
2. Identify ATT&CK techniques for the observed behavior
3. Query blast radius if the host may be compromised
4. Check for similar past incidents

OUTPUT FORMAT — When you have enough evidence, output your final answer as:
INVESTIGATION SUMMARY:
[sentence describing what happened]
IOC_LIST:
[type:value pairs found]
ATTACK_TECHNIQUES:
[TechniqueID - Name - Confidence(0-1)]
BLAST_RADIUS: [yes/no]
SIMILAR_INCIDENTS: [count found]"""

# Tools the agent can call during investigation
TOOLS = [
    search_logs,
    query_blast_radius,
    search_similar_incidents,
    search_attack_techniques,
]
if _HAS_LLM_MAPPER:
    TOOLS.append(classify_attack_techniques)


def build_investigation_agent():
    """
    Build and compile the ReAct investigation agent.

    Returns a compiled LangGraph that can be invoked with a messages list.
    The agent will:
      1. Read the system prompt + the alert description
      2. Plan its investigation
      3. Call tools dynamically (search_logs, query_blast_radius, etc.)
      4. Observe results and refine its understanding
      5. Output a final investigation summary

    The returned graph uses MessagesState internally (key = "messages"),
    NOT SOCAgentState. The investigate_node in graph.py handles the
    translation between the two state formats.
    """
    model = ChatOllama(
        model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        temperature=0,   # Deterministic — we want consistent investigation results
    )

    agent = create_react_agent(
        model=model,
        tools=TOOLS,
        prompt=INVESTIGATION_SYSTEM_PROMPT,
    )
    return agent


def parse_investigation_output(messages: list) -> dict:
    """
    Parse the ReAct agent's output messages to extract structured
    investigation findings.

    The agent's message history looks like:
      [0] SystemMessage (system prompt)
      [1] HumanMessage (alert description)
      [2] AIMessage (plan: "I'll search logs for...")
      [3] ToolMessage (search_logs result)
      [4] AIMessage (observation: "I found 5 events...")
      [5] ToolMessage (search_attack_techniques result)
      [6] AIMessage (final answer with INVESTIGATION SUMMARY)

    This function walks through the messages and extracts:
      - IoCs from tool results
      - ATT&CK techniques from the corpus tool
      - Blast radius from Neo4j
      - Similar incidents from Qdrant
      - The final text summary

    Returns a dict with keys: ioc_list, attack_techniques, enrichment,
    blast_radius, summary_text.
    """
    results = {
        "ioc_list": [],
        "attack_techniques": [],
        "enrichment": {
            # Ordered record of every tool invocation made by the ReAct agent.
            # Presentation-only data: consumed by the UI "Agent Execution" view
            # to render the execution trace. Does not affect pipeline logic.
            "tool_trace": [],
        },
        "blast_radius": {},
        "summary_text": "",
    }

    for msg in messages:
        msg_type = type(msg).__name__

        # Record AI tool-call requests into the trace (args only; the result
        # is attached when the matching ToolMessage arrives).
        if msg_type == "AIMessage" and getattr(msg, "tool_calls", None):
            for tc in msg.tool_calls:
                results["enrichment"]["tool_trace"].append({
                    "step": len(results["enrichment"]["tool_trace"]) + 1,
                    "tool": tc.get("name", "unknown"),
                    "args": tc.get("args", {}) if isinstance(tc.get("args", {}), dict) else {"input": str(tc.get("args"))},
                    "output": None,
                })

        # Process tool results — these contain the raw data from each tool
        if msg_type == "ToolMessage":
            tool_content = msg.content if hasattr(msg, "content") else str(msg)
            tool_name = ""
            if hasattr(msg, "name"):
                tool_name = msg.name
            elif hasattr(msg, "tool_call_id"):
                tool_name = msg.tool_call_id

            # Attach the result to the most recent matching pending trace entry
            for entry in reversed(results["enrichment"]["tool_trace"]):
                if entry["tool"] == tool_name and entry["output"] is None:
                    entry["output"] = str(tool_content)
                    break

            # Parse based on which tool was called
            if "search_logs" in str(tool_name):
                results["enrichment"]["log_search"] = tool_content
                # Try to extract IoCs from the log search results
                results["ioc_list"] = _extract_iocs_from_logs(tool_content)

            elif "query_blast_radius" in str(tool_name):
                results["blast_radius"] = _parse_blast_radius(tool_content)

            elif "search_similar_incidents" in str(tool_name):
                results["enrichment"]["similar_incidents"] = tool_content

            elif "search_attack_techniques" in str(tool_name):
                results["attack_techniques"] = _parse_attack_techniques(
                    tool_content
                )

        # Process AI messages — the final one contains the investigation summary
        elif msg_type == "AIMessage":
            ai_content = msg.content if hasattr(msg, "content") else str(msg)
            # The last AIMessage (without tool_calls) is the final answer
            if not getattr(msg, "tool_calls", None):
                results["summary_text"] = ai_content
                results["enrichment"]["tool_trace"].append({
                    "step": len(results["enrichment"]["tool_trace"]) + 1,
                    "tool": "_final_answer",
                    "args": {},
                    "output": str(ai_content),
                })

    return results


def _extract_iocs_from_logs(log_content: str) -> list[dict]:
    """
    Extract IoC dictionaries from OpenSearch log search results.

    The tool returns a string representation of a list of dicts.
    We parse it and extract known IoC fields (IPs, hosts, users).
    """
    iocs = []
    try:
        # The tool returns str(list_of_dicts), try to parse it
        import ast
        logs = ast.literal_eval(log_content)
        if not isinstance(logs, list):
            return iocs

        seen = set()
        for log_entry in logs:
            if not isinstance(log_entry, dict):
                continue
            # Extract IPs
            for ip_field in ["src_ip", "dest_ip", "Source_Network_Address"]:
                ip = log_entry.get(ip_field, "")
                if ip and ip not in seen and ip != "":
                    iocs.append({"type": "ip", "value": ip,
                                 "confidence": 0.7, "source": "log_search"})
                    seen.add(ip)
            # Extract hosts
            host = log_entry.get("host", "")
            if host and host not in seen:
                iocs.append({"type": "host", "value": host,
                             "confidence": 0.8, "source": "log_search"})
                seen.add(host)
            # Extract users
            user = log_entry.get("user", "")
            if user and user not in seen and user != "":
                iocs.append({"type": "account", "value": user,
                             "confidence": 0.7, "source": "log_search"})
                seen.add(user)
    except (ValueError, SyntaxError, TypeError):
        pass
    return iocs


def _parse_blast_radius(radius_content: str) -> dict:
    """
    Parse the Neo4j blast-radius query result into a structured dict.

    The tool returns str(dict). We parse it and normalize the format
    to match the SOCAgentState.blast_radius schema.
    """
    try:
        import ast
        data = ast.literal_eval(radius_content)
        if isinstance(data, dict):
            return data
    except (ValueError, SyntaxError, TypeError):
        pass
    return {"raw": radius_content, "reachable_assets": [], "reachable_count": 0}


def _parse_attack_techniques(attack_content: str) -> list[dict]:
    """
    Parse ATT&CK corpus search results into a list of technique dicts.

    The tool returns str(list_of_dicts). We normalize each entry to
    match the SOCAgentState.attack_techniques schema:
      {technique_id, technique_name, confidence, rationale}
    """
    techniques = []
    try:
        import ast
        candidates = ast.literal_eval(attack_content)
        if not isinstance(candidates, list):
            return techniques

        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            score = candidate.get("score", 0)
            techniques.append({
                "technique_id": candidate.get("technique_id", "T????"),
                "technique_name": candidate.get("technique_name", "Unknown"),
                # Normalize the score (which is a raw keyword-match count)
                # to a 0-1 confidence value
                "confidence": min(score / 6.0, 1.0),
                "rationale": (
                    f"Matched via keyword search: "
                    f"{candidate.get('description', '')[:150]}"
                ),
            })
    except (ValueError, SyntaxError, TypeError):
        pass
    return techniques


# ──────────────────────────────────────────────────────────────────────────────
# WHAT WAS DONE HERE — Teaching Notes
# ──────────────────────────────────────────────────────────────────────────────
#
# THIS IS THE MOST IMPORTANT FILE FOR WEEK 3.
# ─────────────────────────────────────────────
# The document says Week 3 requires:
#   "Build the LangGraph state machine: plan → select tool → call → observe
#    → refine. Serve an open model (Qwen3 / Llama-3.x) via vLLM with
#    tool-calling. Get end-to-end triage working on simple alerts."
#
# This file IS that ReAct loop. Here's what each piece does:
#
# ──────────────────────────────────────────────────────────────────────────────
# 1. THE SYSTEM PROMPT (INVESTIGATION_SYSTEM_PROMPT)
# ──────────────────────────────────────────────────
# This is the LLM's "job description." It tells the model:
#   - "You are a SOC analyst" (role)
#   - "Here are 4 tools you can use" (capabilities)
#   - "Investigate in this order: logs → techniques → blast radius" (strategy)
#   - "Output your findings in this format" (output schema)
#
# Why is it so short? Because we're using llama3.2:3b (a 3-billion parameter
# model). Smaller models have limited context windows and struggle with long,
# complex instructions. A 70B model would get a much more detailed prompt.
#
# ──────────────────────────────────────────────────────────────────────────────
# 2. THE TOOLS LIST
# ─────────────────────
# We pass the 4 LangChain @tool functions to create_react_agent. During
# the ReAct loop, the LLM can call ANY of these tools in ANY order:
#
#   Iteration 1: LLM thinks "I should search logs for 10.0.2.15"
#     → calls search_logs("10.0.2.15")
#     → gets back 12 matching events
#
#   Iteration 2: LLM thinks "I see brute force patterns, let me check ATT&CK"
#     → calls search_attack_techniques("brute force logon failed")
#     → gets back T1110 (Brute Force), T1110.001 (Password Spraying)
#
#   Iteration 3: LLM thinks "This host may be compromised, check blast radius"
#     → calls query_blast_radius("WIN-DC01")
#     → gets back 3 reachable assets
#
#   Iteration 4: LLM has enough evidence, outputs final summary
#
# THIS is the "dynamic tool selection" the document requires. The fixed
# pipeline (analyze_logs → attack_tagger) always calls the same tools in
# the same order. The ReAct agent decides for itself.
#
# ──────────────────────────────────────────────────────────────────────────────
# 3. build_investigation_agent()
# ──────────────────────────────
# This function creates the ReAct agent by calling LangGraph's prebuilt
# create_react_agent(). What this function does under the hood:
#
#   a. Creates a LangGraph StateGraph with MessagesState
#   b. Adds an "agent" node that calls the LLM with tool definitions
#   c. Adds a "tools" node (ToolNode) that executes tool calls
#   d. Adds conditional edges:
#        - If LLM output has tool_calls → go to "tools" node
#        - If LLM output has no tool_calls → go to END (final answer)
#   e. After tools execute → loop back to "agent" node
#
# The resulting topology is:
#   agent → [has_tool_calls?] → tools → agent → ... → [no tool_calls] → END
#            ↑_________________________|
#
# This IS the plan → tool_call → observe → refine loop.
#
# ──────────────────────────────────────────────────────────────────────────────
# 4. parse_investigation_output()
# ─────────────────────────────
# After the ReAct agent finishes, its output is a list of messages:
#   [0] SystemMessage (prompt)
#   [1] HumanMessage (alert)
#   [2] AIMessage (first plan + tool_calls)
#   [3] ToolMessage (tool result)
#   [4] AIMessage (observation + next plan)
#   [5] ToolMessage (tool result)
#   ...
#   [N] AIMessage (final answer, no tool_calls)
#
# This function walks through ALL messages and extracts:
#   - From ToolMessages: raw IoCs, ATT&CK techniques, blast radius, etc.
#   - From the last AIMessage: the investigation summary text
#
# The extracted data is then written back into the SOCAgentState by the
# investigate_node (in graph.py), bridging the gap between the ReAct
# agent's MessagesState and the main graph's SOCAgentState.
#
# ──────────────────────────────────────────────────────────────────────────────
# 5. THE PARSING FUNCTIONS (_extract_iocs_from_logs, _parse_attack_techniques, etc.)
# ──────────────────────────────────────────────────────────────────────────────
# These are "glue" functions that convert the raw string output of each tool
# into structured data that fits the SOCAgentState schema.
#
# Why do we need them? Because the tools return strings (the LLM expects
# strings), but the state schema expects structured dicts/lists. These
# parsing functions bridge that gap.
#
# They use ast.literal_eval() to safely parse Python dict/list string
# representations. This is safe because we control the tool output format.
#
# WHY NOT JUST PASS RAW STRINGS TO THE STATE?
# ────────────────────────────────────────────
# Because downstream nodes (rca_generator, propose_actions) need structured
# data to work with. The RCA generator needs a list of technique dicts with
# technique_id, technique_name, confidence. The propose_actions node needs
# a blast_radius dict with reachable_assets. Raw strings won't work.
#
# ──────────────────────────────────────────────────────────────────────────────
# IMPORTANT DESIGN DECISION: We use ChatOllama, not vLLM
# ──────────────────────────────────────────────────────
# The document mandates vLLM for model serving. However, for Week 3's
# development and testing, Ollama is faster to set up and debug with.
# When moving to production/evaluation (Week 7), switch to vLLM:
#
#   from langchain_openai import ChatOpenAI
#   model = ChatOpenAI(
#       base_url="http://localhost:8000/v1",  # vLLM endpoint
#       model="Qwen/Qwen3-8B",
#       api_key="not-needed",
#   )
#
# The rest of the code stays exactly the same — LangChain's model interface
# is model-agnostic.
#
# ──────────────────────────────────────────────────────────────────────────────

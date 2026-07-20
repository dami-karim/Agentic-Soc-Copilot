# Notebook: LanG — A Governance-Aware Agentic AI Platform for Unified Security Operations

## Title & Source
"LanG — A Governance-Aware Agentic AI Platform for Unified Security Operations," arXiv:2604.05440v1 [cs.CR], submitted 7 April 2026. Authors: Anes Abdennebi, Nadjia Kara, Laaziz Lahlou (École de technologie supérieure), Hakima Ould-Slimane. Note: the paper's actual title differs from the shorthand "LangGraph-Based SOC Pipeline" used in the project brief — LanG is a broader governance-aware platform, of which the 5-node LangGraph pipeline is one of five contributions.

## Problem Addressed
SOCs suffer alert fatigue, fragmented tooling, and weak cross-source correlation, which existing SIEM/EDR/XDR tools only partly solve. Layering LLMs on top introduces new risks — prompt injection, excessive tool agency, hallucinated ATT&CK mappings — that regulatory frameworks (EU AI Act, NIST AI RMF) increasingly require organizations to govern, audit, and keep human-overseen.

## Proposed Solution & Architecture
Five integrated contributions on a bottom-up four-layer stack (Security → Agentic AI → MCP → Governance):
1. A **Unified Incident Context Record (UICR)** with a correlation engine that groups related alerts and computes a 0–100 triage score.
2. An **Agentic AI Orchestrator** — a five-node LangGraph pipeline (Ingest/Detect → Classify → Human Review 1 → Analyze Logs → Propose Rules → Human Review 2 → Deploy) with two mandatory human-approval gates.
3. An **LLM-based multi-format detection-rule generator**, QLoRA-finetuned across four base models, producing Snort 2/3, Suricata, and YARA rules.
4. A **three-phase Attack Scenario Reconstructor** combining Louvain community detection, LLM-driven hypothesis generation, and Bayesian scoring.
5. A **layered Governance–MCP–Agentic AI–Security architecture** in which every tool call passes through a two-layer guardrail pipeline (regex pre-filter plus a Llama Prompt Guard 2 semantic classifier).

## Key Technologies Used
- LangGraph (five-node StateGraph with `interrupt()`-based HIL)
- Ollama for fully local LLM inference (Llama 3.1, Llama 3.2, Phi-3-mini)
- QLoRA/LoRA fine-tuning (Phi-3-mini 3.8B, CodeLlama-7B, Mistral-7B, Qwen3-1.7B-base)
- Model Context Protocol — 10 tools across 5 categories plus 4 resources
- SQLite for workflow-state persistence and audit logging; Streamlit web UI

## Evaluation: Dataset + Metrics + Results
Correlation engine F1 = 87%. Rule generator: 96.2% average acceptance rate, >91% deployability on live Snort/Suricata/YARA engines. Attack Scenario Reconstructor: 87.5% kill-chain accuracy. Anomaly/threat detectors: weighted F1 of 99.0% (binary DoH-traffic detector) and 91.0% (10-class UNSW-derived detector), ~21 ms inference, machine-side mean-time-to-detect of 1.58 s. Guardrail pipeline: 98.1% F1 with zero false positives in their experimental run. Positioned against eight commercial/open SOC platforms in a qualitative capability comparison.

## Strengths (What Works Well)
- Only published open system combining an agentic triage pipeline, a formal governance layer, multi-format rule generation, and attack reconstruction in a single stack
- Fully local/open-source deployment (Ollama-based) removes cloud-API data-sovereignty concerns
- The two-gate HIL design maps directly onto LangGraph's `interrupt()` construct, giving a concrete, working reference implementation

## Limitations & Weaknesses
- No live asset/blast-radius graph: correlation and attack reconstruction operate over the flat/relational UICR store rather than a queryable entity graph
- Relies on Ollama for local inference rather than a high-throughput serving engine such as vLLM, which will not scale to concurrent tool-call volume
- Evaluation centers on rule generation, correlation, and guardrails; no end-to-end investigation-quality benchmark against a labeled public dataset such as BOTS v3

## Key Contributions (Novel Claims)
A five-contribution, governance-first platform whose central architectural claim is that agentic SOC automation must be built on a bottom-up Security→Agentic AI→MCP→Governance hierarchy, with the LangGraph pipeline's two human-review gates enforcing the NIST recommendation that automated tools augment, not replace, analyst decision-making.

## Ideas I Will Reuse in My Project
- Redraw the five-node LangGraph pipeline (Ingest/Detect → Classify → HIL 1 → Analyze Logs → Propose Rules → HIL 2 → Deploy) as this project's ReAct triage skeleton
- Model the `SOCAgentState` TypedDict on LanG's `WorkflowState` dataclass — unique workflow id, a Phase enum, accumulated per-node results, a timestamped event log, human-decision records
- Adopt the two-layer guardrail pattern (regex pre-filter + semantic classifier) for pre- and post-LLM content screening
- Use the UICR schema as a starting point for a normalized incident record, extended with a Neo4j-backed asset graph

## Open Questions After Reading
- Section VII (Limitations and Future Work) not fully retrieved yet — **re-read before finalizing the SotA note** to confirm the authors' self-identified gaps
- How would the UICR correlation engine's 5-minute default time-window perform on much larger enterprise event volume?
- Does adding a Neo4j blast-radius layer subsume or duplicate the UICR correlation engine's role?

## Important Figures
Figure 1: the four-layer Security → Agentic AI → MCP → Governance architecture. Figure 2: the five-node SOC agentic pipeline with its two human-review gates — most directly reusable diagram for this project's own architecture diagram.

## Important Citations Within This Paper
Cites Kryukov et al. (rule-based ATT&CK mapping); also cites HOLMES and ATLAS as prior provenance/graph-based attack-correlation systems worth a follow-up skim.

## Final Takeaway (One Sentence)
LanG is the closest published open blueprint for a governed LangGraph SOC pipeline with human-in-the-loop gates, but it correlates and reconstructs incidents from a flat UICR store rather than a live asset graph — precisely the gap this project's Neo4j blast-radius layer is designed to close.
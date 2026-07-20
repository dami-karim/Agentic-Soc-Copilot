# SOCAgentState — TypedDict Specification

Modeled directly on LanG's `WorkflowState` dataclass (arXiv:2604.05440, Section IV-B2): a unique workflow id, a phase enum, accumulated per-node results, a timestamped event log, and a full human-decision audit trail. Extended here with the fields this project's own architecture adds beyond LanG — ATT&CK tagging (RAM) and provenance/blast-radius reasoning (OCR-APT / Neo4j).

This is a **spec**, not code — implementation starts Week 3. The Python `TypedDict` this becomes is a mechanical translation of the table below.

| Field | Type | Description | Written by (node) |
|---|---|---|---|
| `workflow_id` | `str` | Unique identifier for this investigation, generated once at pipeline start | Ingest/Detect |
| `alert_raw` | `dict` | The raw, unmodified SIEM alert as received | Ingest/Detect |
| `alert_id` | `str` | Normalized alert identifier (deduplication key) | Ingest/Detect |
| `phase` | `Enum` | Current pipeline phase — mirrors LanG's 12-state enum: `Pending`, `Ingesting`, `Classifying`, `Awaiting_Classification_Review`, `Analyzing`, `Tagging`, `Blast_Radius_Query`, `Proposing_Actions`, `Awaiting_Action_Review`, `Completed`, `Aborted`, `Error` | All nodes update on entry/exit |
| `triage_score` | `float` (0–100) | Composite triage score, following LanG's weighted-factor pattern (IoC count/confidence, alert severity, kill-chain depth) | Classify |
| `severity` | `str` | Human-readable severity label (`Low`/`Medium`/`High`/`Critical`) | Classify |
| `ioc_list` | `List[dict]` | Extracted indicators of compromise — `{type, value, confidence, source}` | IoC Extraction (part of Analyze Logs) |
| `enrichment` | `dict` | Results of OpenSearch log-search and internal threat-intel lookups, keyed by IoC | Analyze Logs |
| `attack_techniques` | `List[dict]` | Tagged ATT&CK techniques — `{technique_id, technique_name, confidence, rationale}`, following RAM's chain-of-thought rationale pattern | Attack Tagger |
| `blast_radius` | `dict` | Neo4j query result — reachable assets within configured hop limit from the compromised host/identity | Blast-Radius Query |
| `rca_report` | `dict` | Structured root-cause analysis — `{summary, apt_stage_breakdown, iocs_with_context, timeline}`, following OCR-APT's narrative RCA schema | RCA Generator |
| `proposed_actions` | `List[dict]` | Candidate high-impact actions awaiting analyst approval — `{action_type, target, justification}` | Propose Actions |
| `human_decisions` | `List[dict]` | Full audit trail of analyst approvals/rejections — `{gate_name, decision, analyst_id, timestamp, notes}` | Human Review 1, Human Review 2 |
| `guardrail_flags` | `List[dict]` | Any guardrail-pipeline warnings or blocks raised during this workflow — `{node, level (warn/block), reason, timestamp}` | Guardrail wrapper (applies to every node) |
| `event_log` | `List[dict]` | Full timestamped trace of every node transition, for session recovery and audit | All nodes append |
| `final_status` | `Enum` | `Completed` / `Completed_Benign` / `Aborted` / `Escalated` | Deploy/Terminate |

## Node → field write map (summary)

Ingest/Detect → workflow_id, alert_raw, alert_id, phase, event_log
Classify → triage_score, severity, phase, event_log
Human Review 1 → human_decisions, phase, event_log
Analyze Logs → ioc_list, enrichment, phase, event_log
Attack Tagger → attack_techniques, phase, event_log
Blast-Radius Query → blast_radius, phase, event_log
RCA Generator → rca_report, phase, event_log
Propose Actions → proposed_actions, phase, event_log
Human Review 2 → human_decisions, phase, event_log
Deploy/Terminate → final_status, phase, event_log
(all nodes) → guardrail_flags (via wrapper, not the node itself)

## Design notes
- **`guardrail_flags` is written by a wrapper, not by individual nodes** — following LanG's pattern of routing every tool/LLM call through the guardrail pipeline before and after execution, rather than trusting each node to self-police.
- **`human_decisions` accumulates across both gates** rather than being overwritten, so the final audit trail shows the full approval history for compliance/review purposes (LanG's stated motivation: NIST SP 800-61 rev. 3 incident-handling guidance that automation should augment, not replace, human decision-making).
- **`blast_radius` and `rca_report` are the two fields with no equivalent in LanG's own `WorkflowState`** — they are the concrete, schema-level expression of Gap 1 (`research/synthesis/gaps_and_contribution.md`).
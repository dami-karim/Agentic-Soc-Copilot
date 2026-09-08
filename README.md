# Agentic SOC Co-Pilot

An autonomous security operations center (SOC) alert triage system powered by LangGraph, local LLMs, and a multi-store data architecture. It ingests SIEM alerts, investigates them through a ReAct agent loop, maps findings to MITRE ATT&CK techniques, and proposes containment actions — with human-in-the-loop checkpoints for high-risk decisions.

## Architecture

```
ingest → classify → [conditional]
                        ├── score < threshold     → deploy (benign, no action)
                        ├── score in borderline   → HIL gate 1 → investigate OR deploy
                        └── score >= threshold    → investigate (ReAct loop)
                                                      → rca_generator
                                                      → propose_actions
                                                      → [high-risk?] → HIL gate 2 → deploy
```

**Data stores:**

| Store | Purpose |
|-------|---------|
| OpenSearch | SIEM log storage and search (BOTS v3 dataset) |
| Neo4j | Asset graph and blast-radius queries (variable-depth traversal) |
| Qdrant | Vector store for similar past-incident retrieval (RAG) |
| Ollama | Local LLM inference (llama3.2:3b default) |

## Project Structure

```
├── src/
│   ├── api/               # FastAPI REST backend
│   ├── ui/                # Streamlit dashboard (17 views)
│   ├── nodes/             # Pipeline nodes (ingest, classify, investigate, rca, propose, deploy)
│   ├── tools/             # LangChain tool wrappers (OpenSearch, Neo4j, Qdrant, ATT&CK corpus)
│   ├── guardrails/        # Input/output validation, regex prefilter, semantic classifier
│   ├── fp_filter/         # Batch false-positive classifier (signals, verdict, LLM adjudicator)
│   ├── llm/               # LLM integration (ATT&CK mapper)
│   ├── eval/              # Evaluation metrics (MTTR, precision, recall)
│   ├── graph.py           # Main LangGraph pipeline (orchestrator)
│   ├── react_graph.py     # ReAct investigation agent (dynamic tool calling)
│   ├── state.py           # SOCAgentState TypedDict schema
│   └── config.py          # Multi-tenant YAML config with env overrides
├── lab/                   # Docker Compose + data ingestion scripts
│   ├── docker-compose.yml # OpenSearch, Neo4j, Qdrant, Ollama
│   ├── ingest_bots.py     # BOTS v3 → OpenSearch loader
│   ├── load_assets_neo4j.py
│   ├── seed_qdrant.py
│   ├── generate_fp_filter_dataset.py  # 1000-alert FP/TP benchmark generator
│   └── data/              # Sample alerts and datasets
├── tests/                 # Unit tests (classify, graph, guardrails, RCA, actions, validators)
├── architecture/          # ADRs, state schema docs, architecture figures
├── research/              # Literature review, domain research, synthesis notes
├── report/                # Final writeup and references
└── test_alerts/           # Sample alert fixtures
```

## Quick Start

### Prerequisites

- Python 3.10+
- Docker & Docker Compose
- Ollama (installed separately or via Docker)

### 1. Clone and install

```bash
git clone <repo-url> && cd agentic-soc-copilot
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Start infrastructure

```bash
cp .env.example .env          # edit passwords as needed
cp .env.example lab/.env
cd lab && docker compose up -d
```

This starts: OpenSearch (9200), Neo4j (7687), Qdrant (6333), Ollama (11434).

### 3. Ingest data

```bash
cd lab
python ingest_bots.py         # Load BOTS v3 logs into OpenSearch
python load_assets_neo4j.py   # Load asset graph into Neo4j
python seed_qdrant.py         # Seed vector store with past incidents
```

### 4. Run the pipeline

```bash
# Smoke test (HIL disabled)
python -m src.graph

# Or start the API
uvicorn src.api.main:app --reload --port 8000

# Or start the Streamlit dashboard
streamlit run src/ui/app.py
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/alerts` | Ingest a SIEM alert (returns workflow_id) |
| `GET` | `/api/v1/investigations/{id}` | Poll investigation status/result |
| `POST` | `/api/v1/hil/{id}` | Submit analyst HIL decision |
| `POST` | `/api/v1/fp-filter/batch` | Batch false-positive classification of many alerts |
| `GET` | `/api/v1/metrics` | Evaluation metrics summary |
| `GET` | `/api/v1/config/{org_id}` | Get tenant configuration |
| `GET` | `/health` | Health check |

## False-Positive Filter

A pre-triage batch classifier (`src/fp_filter/`) that reduces alert fatigue: send it hundreds or thousands of alerts and it labels each one as a **false positive** (noise — filtered out), **true positive** (real threat), or **review** (borderline), all without LLM or database round-trips. Only true positives need to flow into the full investigation pipeline.

### How it works

1. `extract_signals()` — deterministic features: severity, EventCode, user, volume/count, and signature patterns (known-benign, SOC-noise, and malicious phrases).
2. `classify_alert()` — triage scoring **identical to the `classify` node** so verdicts agree with the main graph, then layered decisions:
   - Known-benign code/signature → `false_positive`
   - Malicious signature or high failure volume or strong score → `true_positive`
   - Score in the borderline band (or weak evidence like a success logon on a non-privileged account) → `review`
3. `adjudicate_alert()` *(optional, `--llm`)* — borderline alerts are resolved by the local Ollama model, with guardrail validation on its output.
4. `run_batch()` — aggregates a per-alert report + summary; if ground-truth labels are supplied, computes precision/recall/F1 and the **false-positive-reduction** rate (the share of benign alerts correctly suppressed).

### Usage

```bash
# Generate a 1000-alert test dataset (mixed FP/TP + ground-truth labels)
python lab/generate_fp_filter_dataset.py -n 1000 --fp-ratio 0.85

# Classify the whole batch (rule-based, <1 second)
python -m src.fp_filter --input lab/data/fp_batch.jsonl \
    --ground-truth lab/data/fp_batch_labels.jsonl \
    --output report/fp_report.json

# Add --llm to resolve borderline alerts via the local model
python -m src.fp_filter --input lab/data/fp_batch.jsonl \
    --ground-truth lab/data/fp_batch_labels.jsonl --llm

# Or via the API
curl -X POST http://localhost:8000/api/v1/fp-filter/batch \
  -H "Content-Type: application/json" \
  -d '{"alerts": [{...}, {...}], "ground_truth": [true, false]}'
```

On a 1000-alert benchmark (85% benign noise) the rule-based filter achieves ~99% accuracy, ~0.99 precision, recall 1.0 (no missed threats), and suppresses ~99% of benign alerts before investigation. A 10,000-alert batch completes in under a second.

### In the dashboard

Launch the app and use the **FP Filter** page (sidebar → Home → FP Filter):

```bash
streamlit run src/demo/app.py
```

From there you can **Generate sample** (10,000 alerts by default, tune the noise share and seed) or **Upload file** (JSON/JSONL), then hit **Classify N alerts** to get a live scoreboard — TP / FP / REVIEW counts, precision/recall/F1 against ground truth, a per-alert table, and a downloadable JSON report. Check **Resolve REVIEW alerts via local LLM** (requires Ollama) to have borderline alerts adjudicated by the model.

## Configuration

Multi-tenant config loaded from `config/{org_id}.yaml` with environment variable overrides (`SOC_*` prefix). Key settings:

```yaml
severity_weights:      # Custom scoring per severity level
eventcode_boosts:      # Score adjustments per Windows Event ID
benign_threshold:      # Triage score cutoff (default: 30.0)
playbooks:             # Containment actions per ATT&CK technique
integrations:          # SIEM, asset graph, vector store endpoints
model:                 # LLM provider settings
```

## Development

```bash
# Lint
ruff check src/ tests/

# Type check
mypy src/

# Tests
pytest tests/ -v
```

## Human-in-the-Loop

Two checkpoint gates enforce analyst review:

1. **HIL Gate 1 (Classification Review):** Borderline alerts (score near threshold) are paused for analyst approval before full investigation
2. **HIL Gate 2 (Action Approval):** High-risk containment actions (host isolation, network blocking) require explicit analyst approval before execution

Low-risk actions (EDR scan, rule updates) are auto-approved without human intervention.

## Guardrails

- **Regex prefilter** — blocks known prompt injection patterns on tool inputs
- **Semantic classifier** — detects adversarial/omanipulative content
- **Input/output validators** — enforce schema and content policy on LLM inputs and outputs
- **Tool argument validation** — every tool call is validated before execution

## License

See LICENSE file for details.

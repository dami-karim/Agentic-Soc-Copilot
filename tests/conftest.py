"""
Shared test fixtures — reusable alert data and state factories.

Every test file imports from here to get consistent test data.
This avoids duplicating alert dictionaries across 6 test files.
"""
import pytest
from src.state import new_state


# ──────────────────────────────────────────────────────────────────────────────
# FIXTURE 1: A brute-force alert (malicious path)
# ──────────────────────────────────────────────────────────────────────────────
# EventCode 4625 + severity "medium" → score = 40 + 20 = 60 (≥ 30, malicious)
@pytest.fixture
def brute_force_alert():
    return {
        "host": "WIN-DC01",
        "EventCode": "4625",
        "src_ip": "10.0.2.15",
        "dest_ip": "10.0.2.5",
        "user": "administrator",
        "Logon_Type": "3",
        "sourcetype": "WinEventLog:Security",
        "signature": "An account failed to log on",
        "severity": "medium",
    }


# ──────────────────────────────────────────────────────────────────────────────
# FIXTURE 2: A benign alert (benign path)
# ──────────────────────────────────────────────────────────────────────────────
# EventCode 4624 + severity "low" → score = 10 + 10 = 20 (< 30, benign)
@pytest.fixture
def benign_alert():
    return {
        "host": "WIN-WEB01",
        "EventCode": "4624",
        "src_ip": "10.0.2.1",
        "dest_ip": "10.0.2.20",
        "user": "jsmith",
        "Logon_Type": "10",
        "sourcetype": "WinEventLog:Security",
        "signature": "An account was successfully logged on",
        "severity": "low",
    }


# ──────────────────────────────────────────────────────────────────────────────
# FIXTURE 3: A critical scheduled-task alert (high severity)
# ──────────────────────────────────────────────────────────────────────────────
# EventCode 4698 + severity "critical" → score = 90 + 30 = 120, capped at 100
@pytest.fixture
def persistence_alert():
    return {
        "host": "WIN-FIN02",
        "EventCode": "4698",
        "src_ip": "",
        "dest_ip": "",
        "user": "administrator",
        "Logon_Type": "",
        "sourcetype": "WinEventLog:Security",
        "signature": "A scheduled task was created",
        "severity": "critical",
    }


# ──────────────────────────────────────────────────────────────────────────────
# FIXTURE 4: A fresh SOCAgentState initialized from the brute-force alert
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def brute_force_state(brute_force_alert):
    return new_state(
        alert_raw=brute_force_alert,
        workflow_id="test-workflow-001",
        alert_id="test-alert-001",
    )


# ──────────────────────────────────────────────────────────────────────────────
# FIXTURE 5: A state pre-populated with investigation findings
# ──────────────────────────────────────────────────────────────────────────────
# This simulates what the state looks like AFTER the ReAct investigation
# has run and populated ioc_list, attack_techniques, etc.
@pytest.fixture
def investigated_state(brute_force_alert):
    state = new_state(
        alert_raw=brute_force_alert,
        workflow_id="test-workflow-002",
        alert_id="test-alert-002",
    )
    state["triage_score"] = 60.0
    state["severity"] = "medium"

    # IoCs extracted during investigation
    state["ioc_list"] = [
        {"type": "ip", "value": "10.0.2.15", "confidence": 0.8, "source": "alert_field"},
        {"type": "account", "value": "administrator", "confidence": 0.8, "source": "alert_field"},
        {"type": "host", "value": "WIN-DC01", "confidence": 0.9, "source": "alert_field"},
    ]

    # ATT&CK techniques identified during investigation
    state["attack_techniques"] = [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "confidence": 0.85,
            "rationale": "EventCode 4625 on WIN-DC01 involving account 'administrator' from 10.0.2.15.",
        },
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "confidence": 0.60,
            "rationale": "Successful logon after multiple failures suggests credential compromise.",
        },
    ]

    # Blast radius from Neo4j
    state["blast_radius"] = {
        "start_node": "WIN-DC01",
        "max_hops": 3,
        "reachable_assets": [
            {"id": "WIN-WEB01", "labels": ["Host"], "hops": 1},
            {"id": "WIN-FIN02", "labels": ["Host"], "hops": 2},
            {"id": "jsmith", "labels": ["User"], "hops": 1},
        ],
        "reachable_count": 3,
    }

    # Enrichment from OpenSearch + Qdrant
    state["enrichment"] = {
        "log_search": "[{'host': 'WIN-DC01', 'EventCode': '4625', ...}]",
        "similar_incidents": "[{'incident_id': 'INC-001', 'technique': 'T1110'}]",
    }

    # Event log entries from the investigation
    state["event_log"] = [
        {"node": "ingest", "timestamp": "2026-01-01T00:00:00Z", "detail": "Alert received"},
        {"node": "classify", "timestamp": "2026-01-01T00:00:01Z", "detail": "triage_score=60"},
        {"node": "investigate", "timestamp": "2026-01-01T00:00:02Z", "detail": "ReAct investigation complete"},
    ]

    return state

from typing import TypedDict, List, Optional
from enum import Enum


class Phase(str, Enum):
    PENDING = "Pending"
    INGESTING = "Ingesting"
    CLASSIFYING = "Classifying"
    AWAITING_CLASSIFICATION_REVIEW = "Awaiting_Classification_Review"
    ANALYZING = "Analyzing"
    TAGGING = "Tagging"
    BLAST_RADIUS_QUERY = "Blast_Radius_Query"
    PROPOSING_ACTIONS = "Proposing_Actions"
    AWAITING_ACTION_REVIEW = "Awaiting_Action_Review"
    COMPLETED = "Completed"
    ABORTED = "Aborted"
    ERROR = "Error"


class FinalStatus(str, Enum):
    COMPLETED = "Completed"
    COMPLETED_BENIGN = "Completed_Benign"
    ABORTED = "Aborted"
    ESCALATED = "Escalated"


class SOCAgentState(TypedDict):
    workflow_id: str
    alert_raw: dict
    alert_id: str
    phase: Phase
    triage_score: float
    severity: str
    ioc_list: List[dict]
    enrichment: dict
    attack_techniques: List[dict]
    blast_radius: dict
    rca_report: dict
    proposed_actions: List[dict]
    human_decisions: List[dict]
    guardrail_flags: List[dict]
    event_log: List[dict]
    final_status: Optional[FinalStatus]


def new_state(alert_raw: dict, workflow_id: str, alert_id: str) -> SOCAgentState:
    return SOCAgentState(
        workflow_id=workflow_id,
        alert_raw=alert_raw,
        alert_id=alert_id,
        phase=Phase.PENDING,
        triage_score=0.0,
        severity="unknown",
        ioc_list=[],
        enrichment={},
        attack_techniques=[],
        blast_radius={},
        rca_report={},
        proposed_actions=[],
        human_decisions=[],
        guardrail_flags=[],
        event_log=[],
        final_status=None,
    )


"""
3lech SOCAgentState bech tkoun dict form mouch class 3adiya?
3la 5ater el LanGgraph(the orchestration framwork) t3adi state bin nodes as dictionary. kol node te5ou state dict, tbadalha w traja3ha. heka 3leh LanGgraph yestana fi dict-like object w heka 3leh bech nesta3emlou TypeDict 5ater ta3tik el structure mta3 dict lel LangGraph elli yest7a9ha
"""
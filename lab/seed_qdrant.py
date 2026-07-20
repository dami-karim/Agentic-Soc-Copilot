import sys
import os
sys.path.insert(0, "/home/karim/agentic-soc-copilot")

from src.tools.qdrant_tool import QdrantIncidentTool

t = QdrantIncidentTool()
for text, meta in [
    ("Repeated failed logons EventCode 4625 on domain controller from internal IP",
     {"incident_id": "INC-001", "technique": "T1110", "resolution": "Password spray, account locked"}),
    ("Successful admin logon after brute force WIN-DC01",
     {"incident_id": "INC-002", "technique": "T1078", "resolution": "Credentials reset, session killed"}),
    ("PowerShell encoded command execution on workstation",
     {"incident_id": "INC-003", "technique": "T1059.001", "resolution": "Malicious script blocked, host isolated"}),
    ("Lateral movement via SMB from web server to finance server",
     {"incident_id": "INC-004", "technique": "T1021.002", "resolution": "SMB blocked, host reimaged"}),
    ("Scheduled task created for persistence on domain controller",
     {"incident_id": "INC-005", "technique": "T1053.005", "resolution": "Task removed, persistence eliminated"}),
]:
    t.index_incident(text, meta)
print("Qdrant seeded with 5 incidents OK")

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.qdrant_tool import QdrantIncidentTool

SYNTHETIC_INCIDENTS = [
    (
        "Multiple failed Windows logon attempts EventCode 4625 from single source IP "
        "targeting administrator account on domain controller WIN-DC01 over 5 minutes",
        {"incident_id": "INC-101", "technique": "T1110", "sub_technique": "T1110.001",
         "severity": "high", "host": "WIN-DC01",
         "resolution": "Source IP blocked at firewall, account password reset, logon hours restricted"}
    ),
    (
        "Password spray attack EventCode 4625 targeting multiple accounts from single IP "
        "low volume per account to avoid lockout threshold on Active Directory",
        {"incident_id": "INC-102", "technique": "T1110", "sub_technique": "T1110.003",
         "severity": "high", "host": "WIN-DC01",
         "resolution": "Source IP blocked, all targeted accounts forced password reset"}
    ),
    (
        "Repeated RDP brute force EventCode 4625 against Remote Desktop port 3389 "
        "from external IP address targeting local administrator account",
        {"incident_id": "INC-103", "technique": "T1110", "sub_technique": "T1110.001",
         "severity": "critical", "host": "WIN-WEB01",
         "resolution": "RDP disabled from external IPs, account locked, escalated to Tier-2"}
    ),
    (
        "Successful administrator logon EventCode 4624 following multiple failed attempts "
        "EventCode 4625 from same source IP — likely successful brute force compromise",
        {"incident_id": "INC-201", "technique": "T1078", "sub_technique": "T1078.002",
         "severity": "critical", "host": "WIN-DC01",
         "resolution": "Session terminated, credentials reset, host forensically imaged"}
    ),
    (
        "Domain admin account used from unusual workstation EventCode 4624 Logon Type 3 "
        "at abnormal hours — possible credential theft and reuse",
        {"incident_id": "INC-202", "technique": "T1078", "sub_technique": "T1078.002",
         "severity": "high", "host": "WIN-FIN02",
         "resolution": "Session blocked, account suspended, MFA enforcement applied"}
    ),
    (
        "New logon from compromised host to finance server EventCode 4624 Logon Type 3 "
        "using administrator credentials — lateral movement via SMB confirmed",
        {"incident_id": "INC-301", "technique": "T1021", "sub_technique": "T1021.002",
         "severity": "critical", "host": "WIN-FIN02",
         "resolution": "SMB traffic blocked between segments, both hosts isolated"}
    ),
    (
        "WMI remote execution from web server to internal host EventCode 4688 "
        "wmiprvse.exe spawning cmd.exe — lateral movement via WMI confirmed",
        {"incident_id": "INC-302", "technique": "T1021", "sub_technique": "T1021.006",
         "severity": "critical", "host": "WIN-DEV03",
         "resolution": "WMI remote access blocked, source and destination hosts quarantined"}
    ),
    (
        "PowerShell execution with base64 encoded command EventCode 4688 "
        "powershell.exe -enc on workstation following successful logon",
        {"incident_id": "INC-401", "technique": "T1059", "sub_technique": "T1059.001",
         "severity": "high", "host": "WIN-WEB01",
         "resolution": "Malicious script decoded, dropper identified, host reimaged, IOCs blocklisted"}
    ),
    (
        "cmd.exe spawned by IIS worker process w3wp.exe EventCode 4688 "
        "possible web shell execution on public-facing web server",
        {"incident_id": "INC-402", "technique": "T1059", "sub_technique": "T1059.003",
         "severity": "critical", "host": "WIN-WEB01",
         "resolution": "Web shell removed, IIS logs reviewed, WAF rule added, host patched"}
    ),
    (
        "Scheduled task created by administrator account EventCode 4698 "
        "pointing to suspicious executable in temp directory for persistence",
        {"incident_id": "INC-501", "technique": "T1053", "sub_technique": "T1053.005",
         "severity": "high", "host": "WIN-FIN02",
         "resolution": "Scheduled task removed, executable analyzed as backdoor, host reimaged"}
    ),
    (
        "New service installed EventCode 7045 with suspicious binary path "
        "in AppData folder — likely persistence via malicious service",
        {"incident_id": "INC-502", "technique": "T1543", "sub_technique": "T1543.003",
         "severity": "high", "host": "WIN-DC01",
         "resolution": "Service stopped and removed, binary submitted for analysis, host hardened"}
    ),
    (
        "LLMNR and NBT-NS poisoning detected Responder tool signature in network traffic "
        "forced authentication credential capture attempt from internal host",
        {"incident_id": "INC-601", "technique": "T1187", "sub_technique": None,
         "severity": "high", "host": "WIN-DC01",
         "resolution": "LLMNR and NBT-NS disabled via GPO, captured hashes invalidated"}
    ),
    (
        "Windows event logs cleared EventCode 1102 by administrator account "
        "following suspicious activity — evidence tampering suspected",
        {"incident_id": "INC-701", "technique": "T1070", "sub_technique": "T1070.001",
         "severity": "critical", "host": "WIN-DC01",
         "resolution": "Log forwarding confirmed to SIEM, account suspended, forensics initiated"}
    ),
]


def main():
    print("Generating synthetic past incidents for Qdrant...")
    tool = QdrantIncidentTool()

    for i, (description, metadata) in enumerate(SYNTHETIC_INCIDENTS, 1):
        tool.index_incident(description, metadata)
        print(f"  [{i:02d}/{len(SYNTHETIC_INCIDENTS)}] {metadata['incident_id']} — {metadata['technique']}")

    print(f"\nDone. {len(SYNTHETIC_INCIDENTS)} synthetic incidents indexed into Qdrant.")
    print("Coverage: Brute Force, Valid Accounts, Lateral Movement, Execution, Persistence, Forced Auth, Defense Evasion")


if __name__ == "__main__":
    main()

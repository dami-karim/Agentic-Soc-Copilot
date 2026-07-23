import json
import os
import urllib.request
from src.tools.interfaces import AttackCorpusTool

STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
LOCAL_PATH = "lab/data/enterprise-attack.json"


class AttackStixTool(AttackCorpusTool):
    def __init__(self):
        if not os.path.exists(LOCAL_PATH):
            print("Downloading MITRE ATT&CK STIX data (~10MB)...")
            os.makedirs(os.path.dirname(LOCAL_PATH), exist_ok=True)
            urllib.request.urlretrieve(STIX_URL, LOCAL_PATH)
            print("Done.")
        with open(LOCAL_PATH) as f:
            stix = json.load(f)
        self.techniques = [
            o for o in stix["objects"]
            if o.get("type") == "attack-pattern" and not o.get("revoked")
        ]

    def query_techniques(self, data_component: str, top_k: int = 11) -> list[dict]:
        # Split into individual keywords — match any of them
        # Filters out short words (len <= 2) like "on", "in", "to"
        keywords = [w.lower() for w in data_component.split() if len(w) > 2]

        scored = []
        for t in self.techniques:
            name = t.get("name", "").lower()
            desc = t.get("description", "").lower()

            # Name match scores 2 per keyword, description match scores 1
            name_score = sum(2 for kw in keywords if kw in name)
            desc_score = sum(1 for kw in keywords if kw in desc)
            total_score = name_score + desc_score

            if total_score > 0:
                ext_id = next(
                    (r["external_id"] for r in t.get("external_references", [])
                     if r.get("source_name") == "mitre-attack"),
                    "T????"
                )
                scored.append({
                    "technique_id": ext_id,
                    "technique_name": t["name"],
                    "description": t.get("description", "")[:200],
                    "score": total_score,
                })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

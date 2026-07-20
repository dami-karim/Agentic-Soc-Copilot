import argparse
import json
import uuid
from datetime import datetime, timezone
from opensearchpy import OpenSearch, helpers

INDEX_NAME = "soc-alerts"

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "alert_id":   {"type": "keyword"},
            "_time":      {"type": "date"},
            "host":       {"type": "keyword"},
            "EventCode":  {"type": "keyword"},
            "src_ip":     {"type": "keyword"},
            "dest_ip":    {"type": "keyword"},
            "user":       {"type": "keyword"},
            "Logon_Type": {"type": "keyword"},
            "sourcetype": {"type": "keyword"},
            "signature":  {"type": "text"},
            "severity":   {"type": "keyword"},
        }
    }
}


def get_client():
    return OpenSearch(
        hosts=[{"host": "localhost", "port": 9200}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
    )


def ensure_index(client):
    if not client.indices.exists(index=INDEX_NAME):
        client.indices.create(index=INDEX_NAME, body=INDEX_MAPPING)
        print(f"Created index '{INDEX_NAME}'")
    else:
        print(f"Index '{INDEX_NAME}' already exists")


def normalize_event(raw):
    return {
        "alert_id":   str(uuid.uuid4()),
        "_time":      raw.get("_time", datetime.now(timezone.utc).isoformat()),
        "host":       raw.get("host", raw.get("dest", "unknown")),
        "EventCode":  str(raw.get("EventCode", raw.get("event_id", ""))),
        "src_ip":     raw.get("src_ip", raw.get("Source_Network_Address", "")),
        "dest_ip":    raw.get("dest_ip", raw.get("dest", "")),
        "user":       raw.get("user", raw.get("Account_Name", "")),
        "Logon_Type": str(raw.get("Logon_Type", "")),
        "sourcetype": raw.get("sourcetype", "WinEventLog:Security"),
        "signature":  raw.get("signature", raw.get("EventDescription", "")),
        "severity":   raw.get("severity", "medium"),
    }


def load_events(path, sample_size):
    events = []
    with open(path, "r", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= sample_size:
                break
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def bulk_index(client, events):
    actions = [
        {"_index": INDEX_NAME, "_id": e["alert_id"], "_source": e}
        for e in events
    ]
    success, errors = helpers.bulk(client, actions, raise_on_error=False)
    print(f"Indexed {success} documents, {len(errors)} errors")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to JSON event file")
    parser.add_argument("--sample-size", type=int, default=200)
    args = parser.parse_args()

    client = get_client()
    ensure_index(client)
    events = load_events(args.input, args.sample_size)
    print(f"Loaded {len(events)} raw events")
    normalized = [normalize_event(e) for e in events]
    bulk_index(client, normalized)
    client.indices.refresh(index=INDEX_NAME)
    count = client.count(index=INDEX_NAME)["count"]
    print(f"Total documents in '{INDEX_NAME}': {count}")


if __name__ == "__main__":
    main()
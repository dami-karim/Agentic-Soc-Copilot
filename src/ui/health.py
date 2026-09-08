"""
Live service health checks for the status bar.

Every check probes the REAL backend services used by the investigation
pipeline (same endpoints/credentials as src/tools/*) and reports actual
latency. Nothing here is simulated; if a service is down it is shown DOWN.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import httpx

# ── Endpoints (mirror src/tools/* defaults and .env) ─────────────────────────

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")
ATTACK_CORPUS_PATH = Path("lab/data/enterprise-attack.json")
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

CACHE_TTL_SECONDS = 30


def _cache_key(name: str) -> str:
    return f"_health_cache_{name}"


def _cached(st_module, name: str, fn):
    """Session-cached probe with a TTL so reruns don't hammer the services."""
    now = time.monotonic()
    entry = st_module.session_state.get(_cache_key(name))
    if entry and (now - entry["at"]) < CACHE_TTL_SECONDS:
        return entry["data"]
    data = fn()
    st_module.session_state[_cache_key(name)] = {"at": now, "data": data}
    return data


def check_opensearch() -> dict:
    t0 = time.perf_counter()
    try:
        r = httpx.get(OPENSEARCH_URL, timeout=2.5)
        ms = int((time.perf_counter() - t0) * 1000)
        if r.status_code < 500:
            version = r.json().get("version", {}).get("number", "?")
            return {"status": "online", "detail": f"v{version}", "ms": ms}
        return {"status": "degraded", "detail": f"HTTP {r.status_code}", "ms": ms}
    except Exception as e:
        return {"status": "offline", "detail": str(e)[:60], "ms": None}


def check_ollama() -> dict:
    t0 = time.perf_counter()
    try:
        r = httpx.get(f"{OLLAMA_URL}/api/version", timeout=2.5)
        ms = int((time.perf_counter() - t0) * 1000)
        version = r.json().get("version", "?")

        model_loaded = False
        try:
            tags = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=3).json()
            names = [m.get("name", "") for m in tags.get("models", [])]
            base = MODEL_NAME.split(":")[0]
            model_loaded = any(n == MODEL_NAME or n.startswith(base) for n in names)
        except Exception:
            pass

        detail = MODEL_NAME if model_loaded else f"{version} · model not pulled"
        return {
            "status": "online" if model_loaded else "degraded",
            "detail": detail,
            "ms": ms,
        }
    except Exception as e:
        return {"status": "offline", "detail": str(e)[:60], "ms": None}


def check_qdrant() -> dict:
    t0 = time.perf_counter()
    try:
        r = httpx.get(f"{QDRANT_URL}/collections", timeout=2.5)
        ms = int((time.perf_counter() - t0) * 1000)
        cols = [c.get("name") for c in r.json().get("result", {}).get("collections", [])]
        return {"status": "online", "detail": ", ".join(cols) or "no collections", "ms": ms}
    except Exception as e:
        return {"status": "offline", "detail": str(e)[:60], "ms": None}


def check_neo4j() -> dict:
    t0 = time.perf_counter()
    driver = None
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(
            NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD),
            connection_timeout=2.5,
        )
        driver.verify_connectivity()
        info = driver.get_server_info()
        ms = int((time.perf_counter() - t0) * 1000)
        agent = getattr(info, "agent", "") or ""
        # agent looks like "Neo4j/5.x.y ..."
        ver = agent.split()[0].replace("Neo4j/", "v") if agent else "online"
        return {"status": "online", "detail": ver, "ms": ms}
    except Exception as e:
        return {"status": "offline", "detail": str(e)[:60], "ms": None}
    finally:
        if driver:
            try:
                driver.close()
            except Exception:
                pass


def check_attack_corpus() -> dict:
    try:
        if not ATTACK_CORPUS_PATH.exists():
            return {"status": "missing", "detail": "STIX file not found", "ms": None}
        import json
        t0 = time.perf_counter()
        with open(ATTACK_CORPUS_PATH) as f:
            stix = json.load(f)
        ms = int((time.perf_counter() - t0) * 1000)
        count = sum(
            1 for o in stix.get("objects", [])
            if o.get("type") == "attack-pattern" and not o.get("revoked")
        )
        size_mb = ATTACK_CORPUS_PATH.stat().st_size / 1e6
        return {"status": "loaded", "detail": f"{count} techniques · {size_mb:.0f}MB", "ms": ms}
    except Exception as e:
        return {"status": "error", "detail": str(e)[:60], "ms": None}


def get_all_statuses(st_module) -> list[dict]:
    """Return cached statuses for every backend dependency."""
    out = []
    for key, label, fn in [
        ("llm", "LLM", check_ollama),
        ("opensearch", "OPENSEARCH", check_opensearch),
        ("neo4j", "NEO4J", check_neo4j),
        ("qdrant", "QDRANT", check_qdrant),
        ("corpus", "ATT&CK CORPUS", check_attack_corpus),
    ]:
        s = _cached(st_module, key, fn)
        out.append({"key": key, "label": label, **s})
    return out

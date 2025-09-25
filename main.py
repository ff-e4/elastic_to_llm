#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, time, re
import requests
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from elasticsearch import Elasticsearch

# =========================
# Config (env overrides)  |
# =========================
ES_URL    = os.getenv("ES_URL", "CHANGEME:9200")
ES_USER   = os.getenv("ES_USER", "CHANGEME")
ES_PASS   = os.getenv("ES_PASS", "CHANGEME")
ES_INDEX  = os.getenv("ES_INDEX", "logs-*")   # index or pattern
TIME_RANGE = os.getenv("TIME_RANGE", "now-1h")

PAGE_SIZE = int(os.getenv("PAGE_SIZE", "200"))     # ES docs per page
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "25"))    # docs per LM Studio call

LM_BASE_URL = os.getenv("LM_BASE_URL", "http://localhost:1234")
LM_MODEL    = os.getenv("LM_MODEL", "PUT-MODEL-ID-HERE") # i.e. meta-llama-3.1-8b-instruct
LM_MAX_TOKENS = int(os.getenv("LM_MAX_TOKENS", "256"))
LM_TEMPERATURE = float(os.getenv("LM_TEMPERATURE", "0.1"))

OUT_PATH = os.getenv("OUT_PATH", "anomalies.jsonl")

# Optional: set to your Kibana Discover base (e.g., "https://kibana.example.com/app/discover#/")
KIBANA_BASE = os.getenv("KIBANA_BASE")

# Testing knobs
BYPASS_FILTER = os.getenv("BYPASS_FILTER", "0") == "1"
PROMPT_CHAR_BUDGET = int(os.getenv("PROMPT_CHAR_BUDGET", "6000"))  # keep under model context

# =========================
# Fields to pull from ES
# =========================
FIELDS = [
    "@timestamp",
    "log.level",
    "message",
    "http.request.method",
    "http.response.status_code",
    "url.path",
    "url.query",
    "user_agent.original",
    "http.request.body.content",
    "referrer",
    "client.address",
    "client.ip",
    "source.ip",
    "destination.ip",
    "user.name",
    "event.category",
    "event.action",
    "service.name",
    "host.name"
]

# =========================
# Connect to Elasticsearch
# =========================
es = Elasticsearch(
    ES_URL,
    basic_auth=(ES_USER, ES_PASS),
    request_timeout=60
)

# =========================
# ES helpers
# =========================
def es_search(search_after=None):
    body = {
        "size": PAGE_SIZE,
        "_source": FIELDS,
        "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
        "query": {"range": {"@timestamp": {"gte": TIME_RANGE, "lte": "now"}}}
    }
    if search_after:
        body["search_after"] = search_after
    res = es.search(index=ES_INDEX, body=body)
    return res["hits"]["hits"]

def _first(*vals):
    for v in vals:
        if v not in (None, "", []):
            return v
    return None

def compact(hit):
    src = hit.get("_source", {})
    out = {f: src.get(f) for f in FIELDS}

    out["_id"] = hit.get("_id")
    out["_index"] = hit.get("_index")
    out["_sort"] = hit.get("sort")

    # normalized pivots
    out["ts"]     = out.get("@timestamp")
    out["ip"]     = _first(out.get("client.ip"), out.get("source.ip"), out.get("client.address"))
    out["path"]   = out.get("url.path")
    out["query"]  = out.get("url.query")
    out["method"] = out.get("http.request.method")
    out["status"] = out.get("http.response.status_code")
    out["ua"]     = out.get("user_agent.original")
    out["ref"]    = out.get("referrer")
    if not out.get("message"):
        out["message"] = json.dumps(src)[:500]
    return out

# =========================
# Prefilter (Step 2)
# =========================
SUSP_PATHS = re.compile(r"(\.\./|%2e%2e|/\.git|/wp-admin|/wp-login|/phpmyadmin|/etc/passwd|/admin|/shell|/id_rsa)", re.I)
SUSP_QUERY = re.compile(r"(union\s+select|sleep\(|benchmark\(|\bconcat\(|\bload_file\(|\boutfile\b|<script|%3cscript)", re.I)

def is_interesting(r):
    """Return True if the record looks worth sending to the LLM."""
    status = int(_first(r.get("status"), 0) or 0)
    path_q = (r.get("path") or "") + "?" + (r.get("query") or "")
    msg    = (r.get("message") or "")
    method = (r.get("method") or "").upper()

    if status >= 500:
        return True
    if status in (401, 403, 404) and (SUSP_PATHS.search(path_q) or SUSP_QUERY.search(path_q) or "admin" in path_q.lower()):
        return True
    if method in ("PUT","DELETE","PATCH"):
        return True
    if SUSP_PATHS.search(path_q) or SUSP_QUERY.search(path_q):
        return True
    if "failed password" in msg.lower() or "invalid user" in msg.lower():
        return True
    return False

# =========================
# LM Studio (context-safe)
# =========================
def _short(s, n):
    if s is None: return None
    s = str(s)
    return s if len(s) <= n else (s[:n] + "…")

def _as_compact_lines(records, msg_len=280):
    lines = []
    for r in records:
        lines.append({
            "id":   r.get("_id"),
            "t":    _short(r.get("ts"), 48),
            "lvl":  _short(r.get("log.level"), 16),
            "msg":  _short(r.get("message"), msg_len),
            "code": r.get("status"),
            "path": _short(r.get("path"), 96),
            "ip":   _short(r.get("ip"), 48),
            "user": _short(r.get("user.name"), 32),
            "evt":  _short(_first(r.get("event.action"), r.get("event.category")), 32),
            "svc":  _short(r.get("service.name"), 32),
            "meth": _short(r.get("method"), 12),
        })
    return lines

def _shrink_to_budget(records):
    """
    Reduce records/field lengths until the serialized prompt is <= PROMPT_CHAR_BUDGET.
    Strategy:
      1) Try with msg_len=280
      2) If too big: cut record count by half
      3) If still too big: shrink msg_len progressively
    """
    msg_len = 280
    cur = records[:]
    while True:
        lines = _as_compact_lines(cur, msg_len=msg_len)
        payload_text = "INPUT_RECORDS:\n" + json.dumps(lines, ensure_ascii=False)
        if len(payload_text) <= PROMPT_CHAR_BUDGET:
            return payload_text, len(cur)
        if len(cur) > 1:
            cur = cur[:max(1, len(cur)//2)]
            continue
        if msg_len > 120:
            msg_len = max(120, int(msg_len * 0.7))
            continue
        if msg_len > 64:
            msg_len = 64
            continue
        return payload_text[:PROMPT_CHAR_BUDGET], 1

def _parse_jsonl(text):
    out = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and "id" in obj:
                out.append(obj)
        except Exception:
            continue
    return out

SYSTEM_PROMPT = (
    "You are an incident analyst. For EACH input record, output exactly ONE JSON line with keys "
    "{id, anomaly, score, reason, tags}. "
    "anomaly: boolean (true only if security relevant), score: 0..1, "
    "reason: SHORT & ACTIONABLE citing indicators (ip, path, query, status, method, ua). "
    "tags: array of short labels like ['SQLi','Traversal','Bruteforce','5xx','AuthFail','Recon','SuspPath']. "
    "Non-security events like 301/302 or ordinary 200 responses are NOT anomalies unless combined with another indicator. "
    "Output JSONL only. No prose."
)

def call_lm_studio(records):
    # Build + shrink user payload
    user_prompt, used = _shrink_to_budget(records)
    if used < len(records):
        print(f"[LM] trimmed batch {len(records)} → {used} to fit context", file=sys.stderr)

    # Try /chat/completions first
    chat_payload = {
        "model": LM_MODEL,
        "temperature": LM_TEMPERATURE,
        "max_tokens": min(LM_MAX_TOKENS, 256),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt}
        ],
        "stream": False
    }
    try:
        resp = requests.post(f"{LM_BASE_URL}/v1/chat/completions", json=chat_payload, timeout=60)
    except Exception as e:
        raise RuntimeError(f"LM chat request failed: {e}")
    if resp.status_code == 200:
        try:
            data = resp.json()
        except Exception:
            raise RuntimeError(f"LM chat non-JSON: {resp.text[:1000]}")
        if isinstance(data, dict) and data.get("choices"):
            content = data["choices"][0].get("message", {}).get("content", "")
            parsed = _parse_jsonl(content)
            if parsed:
                return parsed
        elif "error" in data:
            print(f"[LM] chat error: {data['error']}", file=sys.stderr)
    else:
        # Print server message (e.g., context overflow) then try completions
        print(f"[LM] chat HTTP {resp.status_code}: {resp.text[:1000]}", file=sys.stderr)

    # Fallback: /completions
    comp_payload = {
        "model": LM_MODEL,
        "prompt": SYSTEM_PROMPT + "\n\n" + user_prompt,
        "temperature": LM_TEMPERATURE,
        "max_tokens": min(LM_MAX_TOKENS, 256),
        "stream": False
    }
    try:
        resp2 = requests.post(f"{LM_BASE_URL}/v1/completions", json=comp_payload, timeout=60)
    except Exception as e:
        raise RuntimeError(f"LM completions request failed: {e}")
    if resp2.status_code >= 400:
        raise RuntimeError(f"LM completions HTTP {resp2.status_code}: {resp2.text[:1000]}")
    try:
        data2 = resp2.json()
    except Exception:
        raise RuntimeError(f"LM completions non-JSON: {resp2.text[:1000]}")
    if isinstance(data2, dict) and data2.get("choices"):
        text = data2["choices"][0].get("text", "")
        parsed = _parse_jsonl(text)
        if parsed:
            return parsed
        raise RuntimeError(f"LM completions returned no parseable JSONL. First 500 chars:\n{text[:500]}")
    if "error" in data2:
        raise RuntimeError(f"LM completions error: {data2['error']}")
    raise RuntimeError(f"LM unexpected response: {json.dumps(data2)[:500]}")

# =========================
# Output helpers (Step 4)
# =========================
def _kql_time_range(ts_iso, minutes=10):
    try:
        ts = datetime.fromisoformat(ts_iso.replace("Z","+00:00"))
        start = (ts - timedelta(minutes=minutes)).isoformat()
        end   = (ts + timedelta(minutes=minutes)).isoformat()
        return start, end
    except Exception:
        return None, None

def _discover_kql(r):
    parts = []
    if r.get("ip"):     parts.append(f'client.ip: "{r["ip"]}"')
    if r.get("path"):   parts.append(f'url.path: "{r["path"]}"')
    if r.get("status") is not None: parts.append(f'http.response.status_code: {r["status"]}')
    if r.get("method"): parts.append(f'http.request.method: "{r["method"]}"')
    return " and ".join(parts) if parts else ""

def _discover_url(r):
    if not KIBANA_BASE:
        return None
    kql = _discover_kql(r)
    t0, t1 = _kql_time_range(r.get("ts") or "")
    if not (kql and t0 and t1):
        return None
    _g = quote(json.dumps({"time":{"from":t0,"to":t1,"mode":"absolute"}}))
    _a = quote(json.dumps({"query":{"language":"kuery","query":kql}}))
    return f'{KIBANA_BASE}?_g={_g}&_a={_a}'

def _doc_url(index_name, id_):
    # Use actual index from the hit when available; wildcard patterns can't be used here
    if not index_name or "*" in index_name or "?" in index_name:
        return None
    base = ES_URL.rstrip("/")
    return f"{base}/{index_name}/_doc/{quote(id_)}"

def write_results(batch, results, out_f):
    by_id = {r.get("id"): r for r in results}
    for item in batch:
        rid = item["_id"]
        res = by_id.get(rid, {}) or {}
        # Prefer normalized keys; fall back to raw source keys
        pivot_ip = _first(item.get("ip"), item.get("client.ip"), item.get("source.ip"), item.get("client.address"))
        pivot_met = _first(item.get("method"), item.get("http.request.method"))
        pivot_stat = _first(item.get("status"), item.get("http.response.status_code"))
        pivot_path = _first(item.get("path"), item.get("url.path"))
        pivot_query = _first(item.get("query"), item.get("url.query"))

        enriched = {
            "_id": rid,
            "_index": item.get("_index"),
            "@timestamp": _first(item.get("ts"), item.get("@timestamp")),
            "ip": pivot_ip,
            "method": pivot_met,
            "status": pivot_stat,
            "path": pivot_path,
            "query": pivot_query,
            "ua": _first(item.get("ua"), item.get("user_agent.original")),
            "referrer": _first(item.get("ref"), item.get("referrer")),
            "user": item.get("user.name"),
            "host": item.get("host.name"),
            # LLM verdict:
            "anomaly": res.get("anomaly"),
            "score": res.get("score"),
            "reason": res.get("reason"),
            "tags": res.get("tags"),
            # Ready-to-use pivots:
            "kql": _discover_kql({
                "ip": pivot_ip, "path": pivot_path, "status": pivot_stat, "method": pivot_met, "ts": item.get("ts")
            }),
            "kibana_discover": _discover_url({
                "ip": pivot_ip, "path": pivot_path, "status": pivot_stat, "method": pivot_met, "ts": item.get("ts")
            }),
            "es_doc": _doc_url(item.get("_index"), rid),
        }
        out_f.write(json.dumps(enriched, ensure_ascii=False) + "\n")
    out_f.flush()

# =========================
# Main
# =========================
def main():
    print(f"[+] Connected to {ES_URL} index={ES_INDEX}, sending to {LM_MODEL} @ {LM_BASE_URL}")
    out_f = open(OUT_PATH, "a", encoding="utf-8")
    sa = None
    batch = []

    while True:
        hits = es_search(search_after=sa)
        if not hits:
            time.sleep(5)
            continue

        passed = 0
        for h in hits:
            rec = compact(h)

            # Prefilter (can bypass for testing)
            if not BYPASS_FILTER and not is_interesting(rec):
                continue

            passed += 1
            batch.append(rec)

            if len(batch) >= BATCH_SIZE:
                try:
                    results = call_lm_studio(batch)
                    write_results(batch, results, out_f)
                except Exception as e:
                    print(f"[!] LLM call failed: {e}", file=sys.stderr)
                batch = []

            sa = h["sort"]  # advance search_after as we iterate

        if passed == 0 and not BYPASS_FILTER:
            print("[i] Page had 0 interesting records (prefilter).")

        # Flush any leftover items that didn't fill a whole batch
        if batch:
            try:
                results = call_lm_studio(batch)
                write_results(batch, results, out_f)
            except Exception as e:
                print(f"[!] LLM call failed (tail flush): {e}", file=sys.stderr)
            batch = []

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[+] Stopped.")

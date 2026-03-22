import json
import os
import re
import sqlite3
import subprocess
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

from flask import Flask, jsonify, request

APP = Flask(__name__)
CLI = os.environ.get("XDP_DDOS_CLI", "./xdp_ddos")
EVENT_LOG = Path(os.environ.get("XDP_DDOS_EVENT_LOG", "/var/log/xdp_ddos_events.jsonl"))
DB_PATH = Path(os.environ.get("XDP_DDOS_DB", "./xdp_ddos.db"))
AUTO_LEARN_ENABLED = os.environ.get("XDP_DDOS_AUTO_LEARN", "1") == "1"
AUTO_LEARN_INTERVAL = int(os.environ.get("XDP_DDOS_AUTO_LEARN_INTERVAL_SEC", "15"))

DB_LOCK = threading.Lock()
EVENT_OFFSET = 0


def now_ts():
    return int(time.time())


def run_cli(args):
    proc = subprocess.run([CLI] + args, capture_output=True, text=True)
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if proc.returncode != 0:
        raise RuntimeError(err or out or f"command failed: {args}")
    return out


def run_cli_json(args):
    out = run_cli(["--json"] + args)
    return json.loads(out)


def parse_kv_line(line):
    result = {}
    for token in line.split():
        if "=" in token:
            k, v = token.split("=", 1)
            try:
                result[k.strip()] = int(v.strip())
            except ValueError:
                result[k.strip()] = v.strip()
    return result


def parse_top_sources(text):
    rows = []
    patt = re.compile(
        r"^(?P<ip>\S+)\s+pps=(?P<pps>\d+)\s+bps=(?P<bps>\d+)\s+syn=(?P<syn>\d+)\s+rst=(?P<rst>\d+)\s+ack_only=(?P<ack>\d+)\s+udp=(?P<udp>\d+)\s+icmp=(?P<icmp>\d+)\s+offenses=(?P<offenses>\d+)\s+blocked=(?P<blocked>\w+)$"
    )
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("top_sources"):
            continue
        m = patt.match(line)
        if not m:
            continue
        g = m.groupdict()
        rows.append(
            {
                "ip": g["ip"],
                "pps": int(g["pps"]),
                "bps": int(g["bps"]),
                "syn": int(g["syn"]),
                "rst": int(g["rst"]),
                "ack_only": int(g["ack"]),
                "udp": int(g["udp"]),
                "icmp": int(g["icmp"]),
                "offenses": int(g["offenses"]),
                "blocked": g["blocked"].lower() == "yes",
            }
        )
    return rows


def parse_policy_lines(text, kind):
    rows = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.endswith(":"):
            continue
        parts = line.split()
        base = {"kind": kind}
        base["target"] = parts[0]
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                base[k] = v
        rows.append(base)
    return rows


def tail_jsonl(path, limit):
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    out = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def read_new_jsonl_events(path):
    global EVENT_OFFSET
    if not path.exists():
        return []

    data = path.read_text(encoding="utf-8", errors="ignore")
    if EVENT_OFFSET > len(data):
        EVENT_OFFSET = 0
    chunk = data[EVENT_OFFSET:]
    EVENT_OFFSET = len(data)

    out = []
    for line in chunk.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def db_init():
    with DB_LOCK:
        conn = db_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS defaults_cfg (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL,
                target TEXT NOT NULL,
                proto TEXT,
                port INTEGER,
                action TEXT NOT NULL,
                anomaly_mult_pct INTEGER NOT NULL,
                score_threshold INTEGER NOT NULL,
                block_ttl_sec INTEGER NOT NULL,
                ttl_sec INTEGER,
                source TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(scope, target, IFNULL(proto, ''), IFNULL(port, 0))
            );

            CREATE TABLE IF NOT EXISTS learning_state (
                ip TEXT PRIMARY KEY,
                suspicion REAL NOT NULL,
                trust REAL NOT NULL,
                last_event_ts INTEGER NOT NULL,
                auto_mode TEXT NOT NULL,
                notes TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS event_journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                src TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                score INTEGER NOT NULL,
                pps INTEGER NOT NULL,
                bytes INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kv_meta (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            );
            """
        )
        conn.commit()
        conn.close()


def db_set_defaults(payload):
    with DB_LOCK:
        conn = db_conn()
        conn.execute(
            """
            INSERT INTO defaults_cfg(id, payload, updated_at)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at
            """,
            (json.dumps(payload, separators=(",", ":")), now_ts()),
        )
        conn.commit()
        conn.close()


def db_get_defaults():
    with DB_LOCK:
        conn = db_conn()
        row = conn.execute("SELECT payload FROM defaults_cfg WHERE id=1").fetchone()
        conn.close()
    if not row:
        return None
    return json.loads(row["payload"])


def db_upsert_policy(scope, target, action, anomaly_mult_pct, score_threshold, block_ttl_sec, ttl_sec, source, proto=None, port=None):
    with DB_LOCK:
        conn = db_conn()
        conn.execute(
            """
            INSERT INTO policies(scope, target, proto, port, action, anomaly_mult_pct, score_threshold, block_ttl_sec, ttl_sec, source, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope, target, IFNULL(proto, ''), IFNULL(port, 0)) DO UPDATE SET
                action=excluded.action,
                anomaly_mult_pct=excluded.anomaly_mult_pct,
                score_threshold=excluded.score_threshold,
                block_ttl_sec=excluded.block_ttl_sec,
                ttl_sec=excluded.ttl_sec,
                source=excluded.source,
                updated_at=excluded.updated_at
            """,
            (scope, target, proto, port, action, anomaly_mult_pct, score_threshold, block_ttl_sec, ttl_sec, source, now_ts()),
        )
        conn.commit()
        conn.close()


def db_delete_policy(scope, target, proto=None, port=None):
    with DB_LOCK:
        conn = db_conn()
        conn.execute(
            "DELETE FROM policies WHERE scope=? AND target=? AND IFNULL(proto, '')=IFNULL(?, '') AND IFNULL(port, 0)=IFNULL(?, 0)",
            (scope, target, proto, port),
        )
        conn.commit()
        conn.close()


def db_list_policies(scope=None):
    with DB_LOCK:
        conn = db_conn()
        if scope:
            rows = conn.execute("SELECT * FROM policies WHERE scope=? ORDER BY updated_at DESC", (scope,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM policies ORDER BY updated_at DESC").fetchall()
        conn.close()
    return [dict(r) for r in rows]


def db_upsert_learning(ip, suspicion_delta=0.0, trust_delta=0.0, auto_mode="monitor", notes=""):
    with DB_LOCK:
        conn = db_conn()
        row = conn.execute("SELECT * FROM learning_state WHERE ip=?", (ip,)).fetchone()
        if row:
            suspicion = max(0.0, float(row["suspicion"]) + suspicion_delta)
            trust = max(0.0, float(row["trust"]) + trust_delta)
            conn.execute(
                "UPDATE learning_state SET suspicion=?, trust=?, last_event_ts=?, auto_mode=?, notes=? WHERE ip=?",
                (suspicion, trust, now_ts(), auto_mode, notes, ip),
            )
        else:
            conn.execute(
                "INSERT INTO learning_state(ip, suspicion, trust, last_event_ts, auto_mode, notes) VALUES (?, ?, ?, ?, ?, ?)",
                (ip, max(0.0, suspicion_delta), max(0.0, trust_delta), now_ts(), auto_mode, notes),
            )
        conn.commit()
        conn.close()


def db_learning_rows(limit=200):
    with DB_LOCK:
        conn = db_conn()
        rows = conn.execute(
            "SELECT * FROM learning_state ORDER BY suspicion DESC, trust DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def db_append_events(events):
    with DB_LOCK:
        conn = db_conn()
        for e in events:
            conn.execute(
                "INSERT INTO event_journal(ts, src, action, reason, score, pps, bytes) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    now_ts(),
                    str(e.get("src", "unknown")),
                    str(e.get("action", "unknown")),
                    str(e.get("reason", "none")),
                    int(e.get("score", 0)),
                    int(e.get("pps", 0)),
                    int(e.get("bytes", 0)),
                ),
            )
        conn.commit()
        conn.close()


def db_get_meta(key, default_value=None):
    with DB_LOCK:
        conn = db_conn()
        row = conn.execute("SELECT v FROM kv_meta WHERE k=?", (key,)).fetchone()
        conn.close()
    if not row:
        return default_value
    return row["v"]


def db_set_meta(key, value):
    with DB_LOCK:
        conn = db_conn()
        conn.execute(
            "INSERT INTO kv_meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, str(value)),
        )
        conn.commit()
        conn.close()


def apply_defaults_to_cli(payload):
    args = [
        "defaults",
        "set",
        str(payload.get("anomaly_mult_pct", 280)),
        str(payload.get("score_threshold", 140)),
        str(payload.get("block_ttl_sec", 120)),
        str(payload.get("offenses", 3)),
        str(payload.get("auto_mitigation", 1)),
        str(payload.get("warmup_windows", 3)),
        str(payload.get("ack_ratio_pct", 88)),
        str(payload.get("rst_ratio_pct", 70)),
        str(payload.get("syn_ratio_pct", 65)),
        str(payload.get("dns_ratio_pct", 60)),
        str(payload.get("dns_min_bytes", 700)),
        str(payload.get("udp_spread_bins", 12)),
        str(payload.get("scan_spread_bins", 18)),
        str(payload.get("udp_amp_ratio_pct", 45)),
        str(payload.get("icmp_ratio_pct", 55)),
        str(payload.get("block_min_score", 220)),
        str(payload.get("block_min_reasons", 3)),
        str(payload.get("emergency_cooldown_sec", 30)),
        str(payload.get("service_relax_dns_pct", 20)),
        str(payload.get("service_relax_http_pct", 12)),
        str(payload.get("service_relax_https_pct", 18)),
        str(payload.get("service_relax_ntp_pct", 0)),
    ]
    run_cli(args)


def apply_policy_to_cli(row):
    scope = row["scope"]
    action = row["action"]
    anomaly = int(row.get("anomaly_mult_pct") or 0)
    score = int(row.get("score_threshold") or 0)
    block_ttl = int(row.get("block_ttl_sec") or 0)
    ttl = row.get("ttl_sec")

    if scope == "ip":
        args = ["policy", "add", row["target"], action, str(anomaly), str(score), str(block_ttl)]
        if ttl is not None:
            args.append(str(ttl))
        run_cli(args)
        return

    if scope == "subnet":
        args = ["subnet", "add", row["target"], action, str(anomaly), str(score), str(block_ttl)]
        if ttl is not None:
            args.append(str(ttl))
        run_cli(args)
        return

    if scope == "port":
        args = ["port", "add", row["proto"], str(int(row["port"])), action, str(anomaly), str(score), str(block_ttl)]
        if ttl is not None:
            args.append(str(ttl))
        run_cli(args)
        return


def replay_from_db():
    defaults = db_get_defaults()
    if defaults:
        apply_defaults_to_cli(defaults)

    for row in db_list_policies():
        apply_policy_to_cli(row)


def set_ip_disabled(ip, ttl_sec=3600, source="manual"):
    run_cli(["policy", "add", ip, "pass", "0", "0", "0", str(ttl_sec)])
    db_upsert_policy("ip", ip, "pass", 0, 0, 0, ttl_sec, source)


def set_ip_enabled(ip):
    run_cli(["policy", "del", ip])
    db_delete_policy("ip", ip)


def auto_learning_tick():
    global EVENT_OFFSET

    if EVENT_OFFSET == 0:
        EVENT_OFFSET = int(db_get_meta("event_offset", 0) or 0)

    new_events = read_new_jsonl_events(EVENT_LOG)
    db_set_meta("event_offset", EVENT_OFFSET)

    if new_events:
        db_append_events(new_events)

    by_ip = defaultdict(lambda: {"count": 0, "high": 0, "drop": 0, "score_sum": 0})
    for e in new_events:
        ip = str(e.get("src", "unknown"))
        score = int(e.get("score", 0))
        act = str(e.get("action", "unknown"))
        by_ip[ip]["count"] += 1
        by_ip[ip]["score_sum"] += score
        if score >= 180:
            by_ip[ip]["high"] += 1
        if act == "drop":
            by_ip[ip]["drop"] += 1

    for ip, agg in by_ip.items():
        suspicion_delta = agg["count"] * 0.25 + agg["high"] * 0.8 + agg["drop"] * 1.2
        avg_score = agg["score_sum"] / max(agg["count"], 1)
        db_upsert_learning(ip, suspicion_delta=suspicion_delta, trust_delta=-0.1, auto_mode="monitor", notes=f"events={agg['count']} avg_score={avg_score:.1f}")

    try:
        top_rows = run_cli_json(["state", "top", "120"]).get("items", [])
    except Exception:
        top_rows = parse_top_sources(run_cli(["state", "top", "120"]))
    attacked_ips = set(by_ip.keys())
    for row in top_rows:
        ip = row["ip"]
        if ip in attacked_ips:
            continue
        if row["pps"] > 2000 and not row["blocked"]:
            db_upsert_learning(ip, suspicion_delta=-0.2, trust_delta=0.3, auto_mode="trusted", notes="high_traffic_no_attack_signals")

    learning = db_learning_rows(300)
    for row in learning:
        ip = row["ip"]
        suspicion = float(row["suspicion"])
        trust = float(row["trust"])

        if trust >= 10.0 and suspicion <= 2.0:
            try:
                set_ip_disabled(ip, ttl_sec=1800, source="auto-trust")
            except Exception:
                pass
            continue

        if suspicion >= 8.0 and trust < 6.0:
            anomaly = 190
            score = 95
            block_ttl = 240
            try:
                run_cli(["policy", "add", ip, "adaptive", str(anomaly), str(score), str(block_ttl), "3600"])
                db_upsert_policy("ip", ip, "adaptive", anomaly, score, block_ttl, 3600, "auto-learner")
            except Exception:
                pass


def auto_learning_loop():
    while True:
        try:
            auto_learning_tick()
        except Exception:
            pass
        time.sleep(max(5, AUTO_LEARN_INTERVAL))


@APP.get("/api/v1/health")
def health():
    return jsonify({"ok": True, "db": str(DB_PATH), "auto_learning": AUTO_LEARN_ENABLED})


@APP.get("/api/v1/stats")
def stats():
    try:
        return jsonify(run_cli_json(["stats"]))
    except Exception:
        out = run_cli(["stats"])
        return jsonify(parse_kv_line(out))


@APP.get("/api/v1/defaults")
def defaults_get():
    try:
        return jsonify(run_cli_json(["defaults", "show"]))
    except Exception:
        out = run_cli(["defaults", "show"])
        return jsonify(parse_kv_line(out))


@APP.put("/api/v1/defaults")
def defaults_put():
    body = request.get_json(force=True, silent=True) or {}
    try:
        current = run_cli_json(["defaults", "show"])
    except Exception:
        current = parse_kv_line(run_cli(["defaults", "show"]))
    merged = dict(current)
    merged.update(body)
    apply_defaults_to_cli(merged)
    db_set_defaults(merged)
    return jsonify({"ok": True})


@APP.get("/api/v1/sources/top")
def sources_top():
    limit = int(request.args.get("limit", 20))
    try:
        return jsonify(run_cli_json(["state", "top", str(limit)]))
    except Exception:
        out = run_cli(["state", "top", str(limit)])
        return jsonify({"items": parse_top_sources(out)})


@APP.post("/api/v1/policies/ip")
def policy_ip_add():
    body = request.get_json(force=True, silent=True) or {}
    ip = body["ip"]
    action = body.get("action", "adaptive")
    anomaly = int(body.get("anomaly_mult_pct", 0))
    score = int(body.get("score_threshold", 0))
    block_ttl = int(body.get("block_ttl_sec", 0))
    ttl = body.get("ttl_sec")

    args = ["policy", "add", ip, action, str(anomaly), str(score), str(block_ttl)]
    if ttl is not None:
        args.append(str(ttl))
    run_cli(args)

    db_upsert_policy("ip", ip, action, anomaly, score, block_ttl, ttl, "manual")
    return jsonify({"ok": True})


@APP.delete("/api/v1/policies/ip/<path:ip>")
def policy_ip_del(ip):
    set_ip_enabled(ip)
    return jsonify({"ok": True})


@APP.post("/api/v1/policies/subnet")
def policy_subnet_add():
    body = request.get_json(force=True, silent=True) or {}
    cidr = body["cidr"]
    action = body.get("action", "adaptive")
    anomaly = int(body.get("anomaly_mult_pct", 0))
    score = int(body.get("score_threshold", 0))
    block_ttl = int(body.get("block_ttl_sec", 0))
    ttl = body.get("ttl_sec")

    args = ["subnet", "add", cidr, action, str(anomaly), str(score), str(block_ttl)]
    if ttl is not None:
        args.append(str(ttl))
    run_cli(args)

    db_upsert_policy("subnet", cidr, action, anomaly, score, block_ttl, ttl, "manual")
    return jsonify({"ok": True})


@APP.delete("/api/v1/policies/subnet/<path:cidr>")
def policy_subnet_del(cidr):
    run_cli(["subnet", "del", cidr])
    db_delete_policy("subnet", cidr)
    return jsonify({"ok": True})


@APP.post("/api/v1/policies/port")
def policy_port_add():
    body = request.get_json(force=True, silent=True) or {}
    proto = body.get("proto", "udp")
    port = int(body["port"])
    action = body.get("action", "adaptive")
    anomaly = int(body.get("anomaly_mult_pct", 0))
    score = int(body.get("score_threshold", 0))
    block_ttl = int(body.get("block_ttl_sec", 0))
    ttl = body.get("ttl_sec")

    args = ["port", "add", proto, str(port), action, str(anomaly), str(score), str(block_ttl)]
    if ttl is not None:
        args.append(str(ttl))
    run_cli(args)

    db_upsert_policy("port", f"{proto}/{port}", action, anomaly, score, block_ttl, ttl, "manual", proto=proto, port=port)
    return jsonify({"ok": True})


@APP.delete("/api/v1/policies/port/<proto>/<int:port>")
def policy_port_del(proto, port):
    run_cli(["port", "del", proto, str(port)])
    db_delete_policy("port", f"{proto}/{port}", proto=proto, port=port)
    return jsonify({"ok": True})


@APP.get("/api/v1/policies")
def policies_list():
    scope = request.args.get("scope")
    return jsonify({"items": db_list_policies(scope=scope)})


@APP.post("/api/v1/ip/<path:ip>/disable")
def ip_disable(ip):
    body = request.get_json(force=True, silent=True) or {}
    ttl = int(body.get("ttl_sec", 3600))
    set_ip_disabled(ip, ttl_sec=ttl, source="manual-disable")
    return jsonify({"ok": True, "ip": ip, "disabled": True, "ttl_sec": ttl})


@APP.post("/api/v1/ip/<path:ip>/enable")
def ip_enable(ip):
    set_ip_enabled(ip)
    return jsonify({"ok": True, "ip": ip, "disabled": False})


@APP.get("/api/v1/learning/state")
def learning_state_get():
    return jsonify({"items": db_learning_rows(500)})


@APP.post("/api/v1/learning/tick")
def learning_tick():
    auto_learning_tick()
    return jsonify({"ok": True})


@APP.get("/api/v1/attacks/recent")
def attacks_recent():
    limit = int(request.args.get("limit", 100))
    return jsonify({"items": tail_jsonl(EVENT_LOG, limit)})


@APP.get("/api/v1/attacks/summary")
def attacks_summary():
    limit = int(request.args.get("limit", 1000))
    events = tail_jsonl(EVENT_LOG, limit)
    by_ip = Counter()
    by_reason = Counter()
    for e in events:
        ip = e.get("src", "unknown")
        by_ip[ip] += 1
        for reason in str(e.get("reason", "none")).split("|"):
            if reason:
                by_reason[reason] += 1

    return jsonify(
        {
            "events": len(events),
            "top_ips": [{"ip": ip, "count": count} for ip, count in by_ip.most_common(20)],
            "top_reasons": [{"reason": r, "count": c} for r, c in by_reason.most_common(20)],
        }
    )


@APP.get("/api/v1/db/export")
def db_export():
    payload = {
        "defaults": db_get_defaults(),
        "policies": db_list_policies(),
        "learning": db_learning_rows(10000),
    }
    return jsonify(payload)


@APP.post("/api/v1/db/import")
def db_import():
    body = request.get_json(force=True, silent=True) or {}
    mode = body.get("mode", "merge")

    if mode == "replace":
        with DB_LOCK:
            conn = db_conn()
            conn.execute("DELETE FROM defaults_cfg")
            conn.execute("DELETE FROM policies")
            conn.execute("DELETE FROM learning_state")
            conn.commit()
            conn.close()

    if body.get("defaults"):
        db_set_defaults(body["defaults"])

    for row in body.get("policies", []):
        db_upsert_policy(
            row["scope"],
            row["target"],
            row["action"],
            int(row.get("anomaly_mult_pct", 0)),
            int(row.get("score_threshold", 0)),
            int(row.get("block_ttl_sec", 0)),
            row.get("ttl_sec"),
            row.get("source", "import"),
            row.get("proto"),
            row.get("port"),
        )

    replay_from_db()
    return jsonify({"ok": True})


@APP.post("/api/v1/replay")
def replay_now():
    replay_from_db()
    return jsonify({"ok": True})


@APP.errorhandler(Exception)
def on_error(err):
    return jsonify({"ok": False, "error": str(err)}), 400


if __name__ == "__main__":
    db_init()
    try:
        replay_from_db()
    except Exception:
        pass

    if AUTO_LEARN_ENABLED:
        t = threading.Thread(target=auto_learning_loop, daemon=True)
        t.start()

    host = os.environ.get("XDP_DDOS_API_HOST", "0.0.0.0")
    port = int(os.environ.get("XDP_DDOS_API_PORT", "8080"))
    APP.run(host=host, port=port)

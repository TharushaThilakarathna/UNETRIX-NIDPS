"""
UNetrix NIDS — Updated Production nids_routes.py

Changes:
- absolute paths for sudo / nft / pgrep
- regex parsing for blocked IPs
- deduped alerts/stats
- attack distribution endpoint
- module health endpoint (Working / Stale / Down), not raw log tails
"""

import csv
import os
import re
import time
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from flask import Blueprint, jsonify, request

from shared import require_auth, log

BASE_DIR = Path(__file__).resolve().parent
ALERT_LOG = BASE_DIR / "alerts_log.csv"
FLOWS_CSV = BASE_DIR / "flows.csv"
PCAP_DIR = Path("/dev/shm/nids")

# absolute paths so Gunicorn does not depend on PATH
SUDO = "/usr/bin/sudo"
NFT = "/usr/sbin/nft"
PGREP = "/usr/bin/pgrep"
SAVE_RULES_SH = str(BASE_DIR / "save_nft_rules.sh")

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

nids_bp = Blueprint("nids", __name__)


# ============================================================
# HELPERS
# ============================================================
def get_blocked_ips():
    try:
        result = subprocess.run(
            [SUDO, "-n", NFT, "list", "set", "inet", "nids", "blocked_ips"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        ips = sorted(set(_IP_RE.findall(result.stdout)))
        return [{"ip_address": ip} for ip in ips]
    except Exception as e:
        log.error(f"Failed to get blocked IPs: {e}")
        return []


def unblock_ip(ip_address):
    try:
        subprocess.run(
            [
                SUDO, "-n", NFT, "delete", "element", "inet", "nids", "blocked_ips",
                f"{{ {ip_address} }}"
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )

        subprocess.run(
            [SUDO, "-n", SAVE_RULES_SH],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return True

    except Exception as e:
        log.error(f"Failed to unblock {ip_address}: {e}")
        return False


def read_alert_rows():
    try:
        if not ALERT_LOG.exists() or ALERT_LOG.stat().st_size == 0:
            return []

        with ALERT_LOG.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return list(reader)

    except Exception as e:
        log.error(f"Failed to read alerts log: {e}")
        return []


def dedupe_alert_rows(rows, blocked_now):
    """
    Newest-first dedupe:
    - remove exact duplicates
    - keep only newest BLOCKED row per source IP
    - if source IP is currently blocked, keep only newest row for that source
    """
    blocked_set = {item["ip_address"] for item in blocked_now}

    rows = list(rows)
    rows.reverse()  # newest first

    out = []
    seen_exact = set()
    seen_blocked_src = set()
    seen_live_blocked_src = set()

    for row in rows:
        ts = str(row.get("timestamp", ""))
        src = str(row.get("src_ip", ""))
        dst = str(row.get("dst_ip", ""))
        pred = str(row.get("prediction", ""))
        conf = str(row.get("confidence", ""))
        action = str(row.get("action", ""))

        exact_key = (ts, src, dst, pred, conf, action)
        if exact_key in seen_exact:
            continue
        seen_exact.add(exact_key)

        if action == "BLOCKED":
            if src in seen_blocked_src:
                continue
            seen_blocked_src.add(src)

        if src in blocked_set:
            if src in seen_live_blocked_src:
                continue
            seen_live_blocked_src.add(src)

        out.append(row)

    return out


def build_attack_distribution(rows):
    counter = Counter()

    for row in rows:
        label = str(row.get("prediction", "")).strip()
        if not label:
            continue
        counter[label] += 1

    total = sum(counter.values())
    if total == 0:
        return []

    data = []
    for label, count in counter.most_common():
        percentage = round((count / total) * 100, 2)
        data.append({
            "attack": label,
            "count": count,
            "percentage": percentage
        })

    return data


def _last_alert_time(rows):
    if not rows:
        return "-"
    return str(rows[0].get("timestamp", "-"))


# ============================================================
# MODULE HEALTH HELPERS
# ============================================================
def _proc_running(pattern: str) -> bool:
    try:
        r = subprocess.run(
            [PGREP, "-f", pattern],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def _latest_pcap_age():
    try:
        pcaps = list(PCAP_DIR.glob("*nids_capture*.pcap"))
        if not pcaps:
            return None
        newest = max(pcaps, key=lambda p: p.stat().st_mtime)
        return time.time() - newest.stat().st_mtime
    except Exception:
        return None


def _file_age(path: Path):
    try:
        if not path.exists():
            return None
        return time.time() - path.stat().st_mtime
    except Exception:
        return None


def build_module_health():
    pcap_age = _latest_pcap_age()
    flows_age = _file_age(FLOWS_CSV)

    dumpcap_ok = pcap_age is not None and pcap_age < 12
    converter_ok = (
        _proc_running("pcap_to_flows.py")
        and flows_age is not None
        and FLOWS_CSV.exists()
        and FLOWS_CSV.stat().st_size > 0
        and flows_age < 20
    )
    ids_ok = _proc_running("realtime_ids.py")

    return {
        "dumpcap": {
            "ok": dumpcap_ok,
            "label": "Working" if dumpcap_ok else "Stale/Down",
            "detail": f"latest pcap {pcap_age:.1f}s ago" if pcap_age is not None else "no pcaps",
        },
        "converter": {
            "ok": converter_ok,
            "label": "Working" if converter_ok else "Stale/Down",
            "detail": f"flows.csv {flows_age:.1f}s ago" if flows_age is not None else "no flows.csv",
        },
        "ids": {
            "ok": ids_ok,
            "label": "Working" if ids_ok else "Down",
            "detail": "realtime_ids.py running" if ids_ok else "process not found",
        },
    }


# ============================================================
# ROUTES
# ============================================================
@nids_bp.route("/api/nids/start", methods=["POST"])
@require_auth
def api_nids_start():
    return jsonify({
        "status": "already_running",
        "message": "NIDS is always running in production"
    })



@nids_bp.route("/api/nids/status", methods=["GET"])
@require_auth
def api_nids_status():
    blocked = get_blocked_ips()
    rows = read_alert_rows()
    deduped = dedupe_alert_rows(rows, blocked)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return jsonify({
        "online": True,
        "interface": "br0",
        "current_time": current_time,
        "session_status": "Production Mode",
        "session_info": f"Last alert: {_last_alert_time(deduped)}",
        "blocked_count": len(blocked)
    })


@nids_bp.route("/api/nids/alerts", methods=["GET"])
@require_auth
def api_nids_alerts():
    try:
        limit = int(request.args.get("limit", 100))
        blocked = get_blocked_ips()
        rows = read_alert_rows()
        rows = dedupe_alert_rows(rows, blocked)

        return jsonify({
            "status": "ok",
            "data": rows[:limit]
        })

    except Exception as e:
        log.error(f"Failed to serve alerts: {e}")
        return jsonify({"status": "ok", "data": []})


@nids_bp.route("/api/nids/blocked", methods=["GET"])
@require_auth
def api_nids_blocked():
    return jsonify({
        "status": "ok",
        "data": get_blocked_ips()
    })


@nids_bp.route("/api/nids/unblock", methods=["POST"])
@require_auth
def api_nids_unblock():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip_address")

    if not ip:
        return jsonify({"error": "ip_address required"}), 400

    if unblock_ip(ip):
        return jsonify({
            "status": "ok",
            "message": f"Unblocked {ip}"
        })

    return jsonify({"error": "Failed to unblock IP"}), 500


@nids_bp.route("/api/nids/stats", methods=["GET"])
@require_auth
def api_nids_stats():
    blocked = get_blocked_ips()
    rows = read_alert_rows()
    deduped = dedupe_alert_rows(rows, blocked)
    critical = sum(1 for a in deduped if a.get("severity") == "Critical")

    return jsonify({
        "status": "ok",
        "data": {
            "total_alerts": len(deduped),
            "blocked_count": len(blocked),
            "critical_alerts": critical
        }
    })


@nids_bp.route("/api/nids/distribution", methods=["GET"])
@require_auth
def api_nids_distribution():
    blocked = get_blocked_ips()
    rows = read_alert_rows()
    deduped = dedupe_alert_rows(rows, blocked)

    return jsonify({
        "status": "ok",
        "data": build_attack_distribution(deduped)
    })


@nids_bp.route("/api/nids/module-logs", methods=["GET"])
@require_auth
def api_nids_module_logs():
    return jsonify({
        "status": "ok",
        "data": build_module_health()
    })

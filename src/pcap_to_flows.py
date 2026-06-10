#!/usr/bin/env python3
import os
import re
import time
import glob
import subprocess
from datetime import datetime

BASE = "/home/unetrix/UNetrix/unetrix_production/NIDS"
PCAP_DIR = "/dev/shm/nids"
FLOWS_CSV = f"{BASE}/flows.csv"
TMP_FLOWS_CSV = f"{BASE}/flows.tmp.csv"
FAILED_DIR = f"{BASE}/failed_pcaps"
CICFLOWMETER = f"{BASE}/venv/bin/cicflowmeter"

# latency tuning
PCAP_MIN_AGE = 0.8
FAST_MIN_SIZE = 15000          # fast lane: attack-like chunks
SMALL_MIN_SIZE = 4000          # fallback lane: recon / bruteforce sized chunks
SMALL_PROCESS_INTERVAL = 6     # process one smaller chunk every 6 sec
STALE_BACKLOG_SEC = 10         # drop old backlog to stay near-real-time
REFRESH_BLOCKED_SEC = 3

os.makedirs(FAILED_DIR, exist_ok=True)

print("[INFO] pcap -> flows converter started...")

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
blocked_ips_cache = set()
_last_refresh = 0.0
last_small_process = 0.0


def tail_text(text: str, limit: int = 1200) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[-limit:]


def refresh_blocked_ips():
    global _last_refresh
    if time.monotonic() - _last_refresh < REFRESH_BLOCKED_SEC:
        return
    try:
        result = subprocess.run(
            ["sudo", "nft", "list", "set", "inet", "nids", "blocked_ips"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        blocked_ips_cache.clear()
        blocked_ips_cache.update(_IP_RE.findall(result.stdout))
        _last_refresh = time.monotonic()
    except Exception:
        pass


def pcap_contains_blocked_ip(pcap: str) -> bool:
    if not blocked_ips_cache:
        return False

    host_expr = " or ".join(f"host {ip}" for ip in blocked_ips_cache)
    bpf = f"({host_expr})"

    try:
        result = subprocess.run(
            ["tcpdump", "-r", pcap, "-nn", bpf, "-c", "1"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


def delete_pcap(pcap: str):
    try:
        subprocess.run(["sudo", "rm", "-f", pcap], check=True)
        print(f"   Deleted {os.path.basename(pcap)}")
    except Exception:
        pass


def move_failed_pcap(pcap: str):
    try:
        dst = os.path.join(FAILED_DIR, os.path.basename(pcap))
        subprocess.run(["sudo", "mv", pcap, dst], check=True)
        subprocess.run(["sudo", "chown", "unetrix:unetrix", dst], check=False)
        print(f"   Moved failed pcap -> {dst}")
    except Exception:
        delete_pcap(pcap)


while True:
    refresh_blocked_ips()

    pcaps = sorted(
        glob.glob(os.path.join(PCAP_DIR, "*nids_capture*.pcap")),
        key=os.path.getmtime,
        reverse=True,
    )

    # need at least one active + one closed file
    if len(pcaps) < 2:
        time.sleep(0.2)
        continue

    newest_active = pcaps[0]
    candidates = []

    for pcap in pcaps[1:]:   # skip newest active file
        if not os.path.exists(pcap):
            continue

        age = time.time() - os.path.getmtime(pcap)
        size = os.path.getsize(pcap)

        if age >= PCAP_MIN_AGE and size >= SMALL_MIN_SIZE:
            candidates.append((pcap, age, size))

    if not candidates:
        time.sleep(0.2)
        continue

    fast_candidates = [c for c in candidates if c[2] >= FAST_MIN_SIZE]
    small_candidates = [c for c in candidates if SMALL_MIN_SIZE <= c[2] < FAST_MIN_SIZE]

    selected = None
    now_ts = time.time()

    if fast_candidates:
        selected = fast_candidates[0]
    elif small_candidates and (now_ts - last_small_process >= SMALL_PROCESS_INTERVAL):
        selected = small_candidates[0]
        last_small_process = now_ts

    # prune stale backlog to keep low latency
    for old_pcap, old_age, _ in candidates[1:]:
        if old_age > STALE_BACKLOG_SEC:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Dropping stale backlog {os.path.basename(old_pcap)} (age={old_age:.1f}s)")
            delete_pcap(old_pcap)

    if selected is None:
        time.sleep(0.2)
        continue

    pcap, age, size = selected

    if pcap_contains_blocked_ip(pcap):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] BLOCKED-IP PCAP -> skipping {os.path.basename(pcap)}")
        delete_pcap(pcap)
        time.sleep(0.1)
        continue

    timeout_sec = max(20, int(size / 90000) + 10)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Converting {os.path.basename(pcap)} (size={size:,} bytes, age={age:.1f}s)")

    try:
        if os.path.exists(TMP_FLOWS_CSV):
            os.remove(TMP_FLOWS_CSV)
    except Exception:
        pass

    cmd = ["sudo", CICFLOWMETER, "-f", pcap, "-c", TMP_FLOWS_CSV]

    try:
        result = subprocess.run(
            cmd,
            timeout=timeout_sec,
            capture_output=True,
            text=True,
        )

        if result.returncode == 0 and os.path.exists(TMP_FLOWS_CSV) and os.path.getsize(TMP_FLOWS_CSV) > 0:
            os.replace(TMP_FLOWS_CSV, FLOWS_CSV)
            print("   SUCCESS -> flows.csv updated")
            delete_pcap(pcap)
        else:
            print(f"   FAILED (code {result.returncode})")
            if result.stderr.strip():
                print("   STDERR:")
                print(tail_text(result.stderr))
            if result.stdout.strip():
                print("   STDOUT:")
                print(tail_text(result.stdout))
            try:
                if os.path.exists(TMP_FLOWS_CSV):
                    os.remove(TMP_FLOWS_CSV)
            except Exception:
                pass
            move_failed_pcap(pcap)

    except subprocess.TimeoutExpired:
        print(f"   TIMEOUT after {timeout_sec}s")
        try:
            if os.path.exists(TMP_FLOWS_CSV):
                os.remove(TMP_FLOWS_CSV)
        except Exception:
            pass
        move_failed_pcap(pcap)

    except Exception as e:
        print(f"   ERROR: {e}")
        try:
            if os.path.exists(TMP_FLOWS_CSV):
                os.remove(TMP_FLOWS_CSV)
        except Exception:
            pass
        move_failed_pcap(pcap)

    time.sleep(0.1)

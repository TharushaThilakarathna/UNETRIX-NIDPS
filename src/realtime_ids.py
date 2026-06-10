#!/usr/bin/env python3

import json
import os
import re
import time
import ipaddress
import subprocess
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from ai_edge_litert.interpreter import Interpreter

# ============================================================
# PRODUCTION CONFIG
# ============================================================
BASE = "/home/unetrix/UNetrix/unetrix_production/NIDS"

FLOWS_CSV = f"{BASE}/flows.csv"
FEATURES_JSON = f"{BASE}/final_features.json"
SCALER_PKL = f"{BASE}/scaler.pkl"
LABEL_ENCODER_PKL = f"{BASE}/label_encoder.pkl"
MODEL_TFLITE = f"{BASE}/fine_tuned_model.tflite"
ALERT_LOG = f"{BASE}/alerts_log.csv"

# whitelist files
WHITELIST_FILE = f"{BASE}/whitelist_ips.txt"
SRC_WHITELIST_FILE = f"{BASE}/src_whitelist_ips.txt"

SAVE_RULES_SH = f"{BASE}/save_nft_rules.sh"

IFACE = "br0"
BLOCK_THRESHOLD = 0.95
BLOCK_TIMEOUT = "10m"
ALERT_COOLDOWN_SEC = 60
PRINT_ALL_FLOWS = False

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# ============================================================
# NETWORK / WHITELIST HELPERS
# ============================================================


def get_gateway_ip():
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True
        )
        parts = out.split()
        return parts[2] if len(parts) >= 3 else None
    except Exception:
        return None


def get_local_ipv4s():
    ips = set()
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show", "scope", "global"],
            text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[3].split("/")[0]
                if ip.count(".") == 3:
                    ips.add(ip)
    except Exception:
        pass
    return ips


GATEWAY_IP = get_gateway_ip()
LOCAL_IPS = get_local_ipv4s()


def _load_ip_list(file_path: str, include_local=False, include_gateway=False):
    exact_ips = set()
    cidrs = []

    if include_local:
        exact_ips.update(LOCAL_IPS)

    if include_gateway and GATEWAY_IP:
        exact_ips.add(GATEWAY_IP)

    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        if "/" in line:
                            cidrs.append(net)
                        else:
                            exact_ips.add(str(net.network_address))
                    except ValueError:
                        print(
                            f"[WARN] Invalid whitelist entry skipped: {line}")
        except Exception as e:
            print(f"[WARN] Failed to load whitelist file {file_path}: {e}")

    return exact_ips, cidrs


def load_whitelist():
    # main whitelist applies in either direction
    return _load_ip_list(
        WHITELIST_FILE,
        include_local=True,
        include_gateway=True,
    )


def load_src_whitelist():
    # source-only whitelist does NOT need local/gateway auto-added
    # those are already protected by the main whitelist
    return _load_ip_list(
        SRC_WHITELIST_FILE,
        include_local=False,
        include_gateway=False,
    )


WHITELIST_IPS, WHITELIST_CIDRS = load_whitelist()
SRC_WHITELIST_IPS, SRC_WHITELIST_CIDRS = load_src_whitelist()
_last_whitelist_refresh = 0.0


def refresh_whitelist():
    global WHITELIST_IPS, WHITELIST_CIDRS
    global SRC_WHITELIST_IPS, SRC_WHITELIST_CIDRS
    global _last_whitelist_refresh

    if time.time() - _last_whitelist_refresh < 5:
        return

    WHITELIST_IPS, WHITELIST_CIDRS = load_whitelist()
    SRC_WHITELIST_IPS, SRC_WHITELIST_CIDRS = load_src_whitelist()
    _last_whitelist_refresh = time.time()


def _ip_in_exact_or_cidr(ip_str: str, exact_ips: set, cidrs: list) -> bool:
    if not ip_str:
        return False

    if ip_str in exact_ips:
        return True

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception:
        return False

    for net in cidrs:
        if ip_obj in net:
            return True

    return False


def ip_in_whitelist(ip_str: str) -> bool:
    return _ip_in_exact_or_cidr(ip_str, WHITELIST_IPS, WHITELIST_CIDRS)


def ip_in_src_whitelist(ip_str: str) -> bool:
    return _ip_in_exact_or_cidr(ip_str, SRC_WHITELIST_IPS, SRC_WHITELIST_CIDRS)


def is_noise_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(ip_str))
    except Exception:
        return True

    if (
        ip.is_unspecified or
        ip.is_multicast or
        ip.is_loopback or
        ip.is_link_local or
        ip.is_reserved
    ):
        return True

    if str(ip) == "255.255.255.255":
        return True

    return False


def is_whitelisted_flow(src_ip: str, dst_ip: str) -> bool:
    # skip if:
    # 1) source in main whitelist
    # 2) destination in main whitelist
    # 3) source in source-only whitelist
    return (
        ip_in_whitelist(src_ip) or
        ip_in_whitelist(dst_ip) or
        ip_in_src_whitelist(src_ip)
    )


def is_blockable_ip(ip_str: str) -> bool:
    if not ip_str or is_noise_ip(ip_str):
        return False
    if ip_in_whitelist(ip_str):
        return False
    if ip_in_src_whitelist(ip_str):
        return False
    return True


print(f"[INFO] Gateway IP: {GATEWAY_IP}")
print(f"[INFO] Local Pi IPs: {sorted(LOCAL_IPS)}")
print(f"[INFO] Loaded whitelist exact IPs: {sorted(WHITELIST_IPS)}")
print(f"[INFO] Loaded whitelist CIDRs: {[str(x) for x in WHITELIST_CIDRS]}")
print(
    f"[INFO] Loaded src-only whitelist exact IPs: {sorted(SRC_WHITELIST_IPS)}")
print(
    f"[INFO] Loaded src-only whitelist CIDRs: {[str(x) for x in SRC_WHITELIST_CIDRS]}")

# ============================================================
# LOAD ARTIFACTS
# ============================================================
with open(FEATURES_JSON, "r") as f:
    final_features = json.load(f)

scaler = joblib.load(SCALER_PKL)
label_encoder = joblib.load(LABEL_ENCODER_PKL)

interpreter = Interpreter(model_path=MODEL_TFLITE)
interpreter.allocate_tensors()

input_details = interpreter.get_input_details()[0]
output_details = interpreter.get_output_details()[0]
input_index = input_details["index"]
output_index = output_details["index"]
input_dtype = input_details["dtype"]

if input_dtype != np.float32:
    raise RuntimeError(f"Expected float32 TFLite input, got {input_dtype}")

print("[INFO] Float32 fine-tuned model loaded successfully (Production).")

# ============================================================
# RAW CICFLOWMETER CSV -> TRAINING FEATURE NAMES
# ============================================================
feature_mapping = {
    "init_fwd_win_byts": "Init Fwd Win Bytes",
    "fwd_seg_size_min": "Fwd Seg Size Min",
    "fwd_header_len": "Fwd Header Length",
    "init_bwd_win_byts": "Init Bwd Win Bytes",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "totlen_fwd_pkts": "Fwd Packets Length Total",
    "bwd_header_len": "Bwd Header Length",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "bwd_pkts_s": "Bwd Packets/s",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "pkt_len_std": "Packet Length Std",
    "fwd_iat_tot": "Fwd IAT Total",
    "pkt_len_max": "Packet Length Max",
    "tot_fwd_pkts": "Total Fwd Packets",
    "pkt_size_avg": "Avg Packet Size",
}

# ============================================================
# NFT HELPERS
# ============================================================


def get_blocked_ips():
    try:
        result = subprocess.run(
            ["sudo", "nft", "list", "set", "inet", "nids", "blocked_ips"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return set(_IP_RE.findall(result.stdout))
    except Exception:
        return set()


def block_ip_nft(ip: str):
    try:
        subprocess.run(
            [
                "sudo", "nft", "add", "element", "inet", "nids", "blocked_ips",
                f"{{ {ip} timeout {BLOCK_TIMEOUT} }}"
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        subprocess.run(
            [SAVE_RULES_SH],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return "BLOCKED"
    except Exception as e:
        print(f"[ERROR] Failed to block {ip}: {e}")
        return "ALERT"

# ============================================================
# DATA HELPERS
# ============================================================


def normalize_and_rename_columns(df: pd.DataFrame) -> pd.DataFrame:
    lowered_lookup = {str(col).strip().lower(): col for col in df.columns}
    rename_pairs = {}

    for raw_name, final_name in feature_mapping.items():
        if raw_name in lowered_lookup:
            rename_pairs[lowered_lookup[raw_name]] = final_name

    passthrough = {
        "src_ip": "src_ip",
        "dst_ip": "dst_ip",
        "src_port": "src_port",
        "dst_port": "dst_port",
        "protocol": "protocol",
        "timestamp": "timestamp",
    }

    for raw_name, final_name in passthrough.items():
        if raw_name in lowered_lookup:
            rename_pairs[lowered_lookup[raw_name]] = final_name

    return df.rename(columns=rename_pairs)


def ensure_numeric_features(df: pd.DataFrame, feature_list):
    for col in feature_list:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def safe_save_alerts(rows):
    if not rows:
        return

    out_df = pd.DataFrame(rows)
    write_header = not os.path.exists(
        ALERT_LOG) or os.path.getsize(ALERT_LOG) == 0
    out_df.to_csv(ALERT_LOG, mode="a", header=write_header, index=False)


# ============================================================
# MAIN LOOP
# ============================================================
print("[INFO] Real-time IDS started (Production mode) — waiting for flows.csv...")

last_mtime = 0.0
last_blocked_refresh = 0.0
current_blocked = get_blocked_ips()
last_event_at = {}

while True:
    try:
        refresh_whitelist()

        if not os.path.exists(FLOWS_CSV) or os.path.getsize(FLOWS_CSV) == 0:
            time.sleep(0.3)
            continue

        if time.time() - last_blocked_refresh > 5:
            current_blocked = get_blocked_ips()
            last_blocked_refresh = time.time()

        mtime = os.path.getmtime(FLOWS_CSV)
        if mtime == last_mtime:
            time.sleep(0.3)
            continue
        last_mtime = mtime

        try:
            df = pd.read_csv(FLOWS_CSV)
        except Exception as e:
            print(f"[ERROR] Failed to read flows.csv: {e}")
            time.sleep(0.5)
            continue

        if df.empty:
            time.sleep(0.3)
            continue

        df = normalize_and_rename_columns(df)

        missing = [c for c in final_features if c not in df.columns]
        if missing:
            print("[ERROR] Missing features after rename:", missing)
            print("[DEBUG] Available columns:", df.columns.tolist())
            time.sleep(0.8)
            continue

        if "src_ip" not in df.columns or "dst_ip" not in df.columns:
            print("[ERROR] src_ip/dst_ip not found in flows.csv")
            time.sleep(0.8)
            continue

        df = df[
            ~df["src_ip"].astype(str).apply(is_noise_ip) &
            ~df["dst_ip"].astype(str).apply(is_noise_ip)
        ].copy()

        if df.empty:
            time.sleep(0.3)
            continue

        # Skip any flow if:
        # - source is in main whitelist
        # - destination is in main whitelist
        # - source is in source-only whitelist
        df = df[
            ~df.apply(
                lambda row: is_whitelisted_flow(
                    str(row.get("src_ip", "")),
                    str(row.get("dst_ip", ""))
                ),
                axis=1
            )
        ].copy()

        if df.empty:
            time.sleep(0.3)
            continue

        X = df[final_features].copy()
        X = ensure_numeric_features(X, final_features)
        X = X.replace([np.inf, -np.inf], 0).fillna(0)
        X_scaled = scaler.transform(X).astype(np.float32)

        alerts_to_save = []
        blocked_this_batch = set()

        for i in range(len(df)):
            src_ip = str(df.iloc[i].get("src_ip", ""))
            dst_ip = str(df.iloc[i].get("dst_ip", ""))

            if src_ip in current_blocked or src_ip in blocked_this_batch:
                continue

            x = X_scaled[i:i+1]
            interpreter.set_tensor(input_index, x)
            interpreter.invoke()
            output_data = interpreter.get_tensor(
                output_index)[0].astype(np.float32)

            pred_idx = int(np.argmax(output_data))
            confidence = float(np.max(output_data))
            pred_label = label_encoder.inverse_transform([pred_idx])[0]

            src_port = int(pd.to_numeric(df.iloc[i].get(
                "src_port", 0), errors="coerce") or 0)
            dst_port = int(pd.to_numeric(df.iloc[i].get(
                "dst_port", 0), errors="coerce") or 0)
            protocol = int(pd.to_numeric(df.iloc[i].get(
                "protocol", 0), errors="coerce") or 0)
            timestamp = str(df.iloc[i].get(
                "timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

            if PRINT_ALL_FLOWS:
                print(
                    f"[FLOW] {src_ip} -> {dst_ip} | pred={pred_label} | conf={confidence:.4f}")

            if pred_label == "Benign":
                continue

            severity = (
                "Critical" if confidence >= 0.95 else
                "High" if confidence >= 0.85 else
                "Medium" if confidence >= 0.70 else
                "Low"
            )

            event_key = (src_ip, dst_ip, pred_label)
            now_ts = time.time()

            if now_ts - last_event_at.get(event_key, 0) < ALERT_COOLDOWN_SEC:
                continue

            if not is_blockable_ip(src_ip):
                action = "ALERT"
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] SAFE  | {pred_label:15s} | {src_ip} -> {dst_ip} | conf={confidence:.4f}")

            elif confidence >= BLOCK_THRESHOLD:
                action = block_ip_nft(src_ip)

                if action == "BLOCKED":
                    current_blocked.add(src_ip)
                    blocked_this_batch.add(src_ip)

                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] BLOCK | {pred_label:15s} | {src_ip} -> {dst_ip} | conf={confidence:.4f}")

            else:
                action = "ALERT"
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] ALERT | {pred_label:15s} | {src_ip} -> {dst_ip} | conf={confidence:.4f}")

            last_event_at[event_key] = now_ts

            alerts_to_save.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "prediction": pred_label,
                "confidence": round(confidence, 4),
                "severity": severity,
                "action": action,
            })

        safe_save_alerts(alerts_to_save)
        time.sleep(0.3)

    except KeyboardInterrupt:
        print("\n[INFO] Real-time IDS stopped.")
        break
    except Exception as e:
        print(f"[ERROR] {e}")
        time.sleep(1)

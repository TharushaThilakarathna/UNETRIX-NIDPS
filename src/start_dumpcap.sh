#!/bin/bash
# ================================================
# UNetrix NIDS — Production dumpcap script
# ================================================

set -euo pipefail

IFACE="${1:-br0}"
CAP_DIR="/dev/shm/nids"
CAP_FILE="${CAP_DIR}/nids_capture.pcap"

mkdir -p "$CAP_DIR"
chmod 777 "$CAP_DIR" 2>/dev/null || true

GATEWAY_IP="$(ip route show default | awk '{print $3}' | head -n1 || true)"
LOCAL_IPS="$(ip -o -4 addr show scope global | awk '{split($4,a,"/"); print a[1]}' | sort -u || true)"

BASE_FILTER="ip and (tcp or udp)"
NOISE="not broadcast and not multicast and not dst net 224.0.0.0/4"
NOISY_PORTS="not (udp port 5353 or udp port 1900 or udp port 5355 or udp port 137 or udp port 138 or udp port 67 or udp port 68)"

FILTER="($BASE_FILTER) and ($NOISE) and ($NOISY_PORTS)"

if [ -n "$GATEWAY_IP" ]; then
    echo "[INFO] Detected gateway: $GATEWAY_IP"
    FILTER="$FILTER and not (src host $GATEWAY_IP or dst host $GATEWAY_IP)"
fi

if [ -n "$LOCAL_IPS" ]; then
    echo "[INFO] Detected local Pi IPs:"
    for ip in $LOCAL_IPS; do
        echo "  - $ip"
        FILTER="$FILTER and not (src host $ip or dst host $ip)"
    done
fi

echo "[INFO] Final BPF filter:"
echo "$FILTER"
echo "[INFO] Starting dumpcap on $IFACE ..."
echo "[INFO] Output pattern: $CAP_FILE"

exec sudo dumpcap \
    -i "$IFACE" \
    -f "$FILTER" \
    -P \
    -b duration:3 \
    -b files:30 \
    -w "$CAP_FILE" \
    -q

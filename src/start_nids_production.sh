#!/bin/bash
# ================================================
# UNetrix NIDS — Production Auto-Start Script
# Works reliably with venv + screen on boot
# ================================================

cd /home/unetrix/UNetrix/unetrix_production/NIDS

echo "[$(date '+%H:%M:%S')] Starting UNetrix NIDS production services..."

# Kill any old sessions
screen -X -S nids_dumpcap quit 2>/dev/null
screen -X -S nids_converter quit 2>/dev/null
screen -X -S nids_ids quit 2>/dev/null

# 1. Start dumpcap (no venv needed)
screen -dmS nids_dumpcap bash -c '
    cd /home/unetrix/UNetrix/unetrix_production/NIDS
    ./start_dumpcap.sh
    exec tail -f /dev/null
'

# 2. Start pcap_to_flows.py (with venv)
screen -dmS nids_converter bash -c '
    cd /home/unetrix/UNetrix/unetrix_production/NIDS
    source venv/bin/activate
    exec ./venv/bin/python3 pcap_to_flows.py
'

# 3. Start realtime_ids.py (with venv)
screen -dmS nids_ids bash -c '
    cd /home/unetrix/UNetrix/unetrix_production/NIDS
    source venv/bin/activate
    exec ./venv/bin/python3 realtime_ids.py
'

echo "[$(date '+%H:%M:%S')] All 3 screen sessions started successfully."
echo "Check with: screen -list"

# Keep systemd service alive
exec tail -f /dev/null

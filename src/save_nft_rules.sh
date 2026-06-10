#!/bin/bash
# ================================================
# UNetrix NIDS — Auto-save nftables rules (Fixed)
# ================================================

echo "[INFO] Auto-saving nftables rules to /etc/nftables.conf..."

# This is the correct and reliable way
sudo sh -c 'nft list ruleset > /etc/nftables.conf'

if [ $? -eq 0 ]; then
    echo "[INFO] nftables rules saved successfully (persistent on reboot)"
else
    echo "[ERROR] Failed to save nftables rules"
fi

#!/bin/bash
# Run Experiment 2 on COMPLETE VPN dataset (ALL 41 PCAPs)
set -e

SNORT_BIN="/home/maru/work/snortsharp/snort3/build/src/snort"
PLUGIN_PATH="/home/maru/work/snortsharp/snort3/build/src/plugins"
RESULTS_DIR="experiment_results/exp2_complete_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"/{community,packet_cheat,hybrid}

echo "======================================================================="
echo "EXPERIMENT 2 - COMPLETE VPN DATASET EVALUATION"
echo "======================================================================="
echo ""
echo "Testing ALL available PCAPs from ISCX2016 VPN-NonVPN dataset"
echo ""

# Collect ALL VPN PCAPs (29 total)
VPN_PCAPS=($(find datasets/VPN/PCAPs/VPN-PCAPS-01 datasets/VPN/PCAPs/VPN-PCAPS-02 -name "*.pcap" 2>/dev/null | sort))

# Collect ALL Non-VPN PCAPs (12 total)
NONVPN_PCAPS=($(find datasets/VPN/PCAPs/NonVPN-PCAPs-01 -name "*.pcap" 2>/dev/null | sort))

ALL_PCAPS=("${VPN_PCAPS[@]}" "${NONVPN_PCAPS[@]}")

echo "VPN PCAPs:     ${#VPN_PCAPS[@]}"
echo "Non-VPN PCAPs: ${#NONVPN_PCAPS[@]}"
echo "Total PCAPs:   ${#ALL_PCAPS[@]}"
echo ""
echo "======================================================================="
echo ""

# Track progress
pcap_count=0
total_pcaps=${#ALL_PCAPS[@]}

for pcap in "${ALL_PCAPS[@]}"; do
    pcap_count=$((pcap_count + 1))
    pcap_name=$(basename "$pcap")

    echo "[$pcap_count/$total_pcaps] Processing: $pcap_name"

    # Config 1: Vanilla Snort3 + Community Rules
    export FLOWSIGN_RULES_FILE="$(pwd)/empty_flowsign_rules.txt"
    cat > "$RESULTS_DIR/community/config.lua" <<LUAEOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
LUAEOF

    $SNORT_BIN -c "$RESULTS_DIR/community/config.lua" -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" -q > "$RESULTS_DIR/community/${pcap_name}.log" 2>&1

    # Config 2: Vanilla Snort3 + Packet Cheat Rules
    cat > "$RESULTS_DIR/packet_cheat/config.lua" <<LUAEOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = {
    enable_builtin_rules = false,
    rules = [[
        include snortsharp-rules/vpn_snort3_packet.rules
    ]]
}
LUAEOF

    $SNORT_BIN -c "$RESULTS_DIR/packet_cheat/config.lua" -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" -q > "$RESULTS_DIR/packet_cheat/${pcap_name}.log" 2>&1

    # Config 3: Snort3 + FlowSign (Hybrid)
    export FLOWSIGN_RULES_FILE="$(pwd)/snortsharp-rules/vpn_flowsign_rules_depth10.txt"
    cat > "$RESULTS_DIR/hybrid/config.lua" <<LUAEOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
LUAEOF

    $SNORT_BIN -c "$RESULTS_DIR/hybrid/config.lua" -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" -q > "$RESULTS_DIR/hybrid/${pcap_name}.log" 2>&1

    # Progress indicator
    if [ $((pcap_count % 5)) -eq 0 ]; then
        echo "   Progress: $pcap_count/$total_pcaps completed ($(echo "scale=1; $pcap_count*100/$total_pcaps" | bc)%)"
    fi
done

echo ""
echo "======================================================================="
echo "EXPERIMENT 2 COMPLETE!"
echo "======================================================================="
echo "Results saved to: $RESULTS_DIR"
echo ""
echo "Next steps:"
echo "1. Compute metrics: python3 compute_vpn_metrics.py $RESULTS_DIR"
echo "2. Compare with BAE-UQ-IDS results"
echo "3. Update EXPERIMENT2_VPN_COMPARISON_TABLE.md"
echo ""

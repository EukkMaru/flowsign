#!/bin/bash
# Run Experiment 2 on BALANCED dataset (VPN + Non-VPN)
set -e

SNORT_BIN="/home/maru/work/snortsharp/snort3/build/src/snort"
PLUGIN_PATH="/home/maru/work/snortsharp/snort3/build/src/plugins"
RESULTS_DIR="experiment_results/exp2_balanced_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"/{community,packet_cheat,hybrid}

# Test on BALANCED dataset: 3 VPN + 2 Non-VPN
VPN_PCAPS=(
    "datasets/VPN/PCAPs/VPN-PCAPS-01/vpn_email2a.pcap"
    "datasets/VPN/PCAPs/VPN-PCAPS-01/vpn_facebook_chat1a.pcap"
    "datasets/VPN/PCAPs/VPN-PCAPS-01/vpn_ftps_B.pcap"
)

NONVPN_PCAPS=(
    "datasets/VPN/PCAPs/NonVPN-PCAPs-01/facebook_audio1a.pcap"
    "datasets/VPN/PCAPs/NonVPN-PCAPs-01/email1a.pcap"
)

ALL_PCAPS=("${VPN_PCAPS[@]}" "${NONVPN_PCAPS[@]}")

echo "Testing ${#ALL_PCAPS[@]} PCAPs (${#VPN_PCAPS[@]} VPN + ${#NONVPN_PCAPS[@]} Non-VPN)"

for pcap in "${ALL_PCAPS[@]}"; do
    pcap_name=$(basename "$pcap")
    echo "Processing: $pcap_name"
    
    # Config 1: Community
    export FLOWSIGN_RULES_FILE="$(pwd)/empty_flowsign_rules.txt"
    cat > "$RESULTS_DIR/community/config.lua" <<LUAEOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
LUAEOF
    
    $SNORT_BIN -c "$RESULTS_DIR/community/config.lua" -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" -q > "$RESULTS_DIR/community/${pcap_name}.log" 2>&1
    
    # Config 2: Packet Cheat
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
    
    # Config 3: Hybrid
    export FLOWSIGN_RULES_FILE="$(pwd)/snortsharp-rules/vpn_flowsign_rules_depth10.txt"
    cat > "$RESULTS_DIR/hybrid/config.lua" <<LUAEOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
LUAEOF
    
    $SNORT_BIN -c "$RESULTS_DIR/hybrid/config.lua" -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" -q > "$RESULTS_DIR/hybrid/${pcap_name}.log" 2>&1
    
    echo "Completed: $pcap_name"
done

echo "Results saved to: $RESULTS_DIR"

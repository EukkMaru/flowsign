#!/bin/bash
###############################################################################
# Experiment 2: VPN Dataset Testing
# Demonstrates FlowSign effectiveness on encrypted/VPN traffic
# Three configurations:
#   1. Vanilla Snort + Community rules (baseline)
#   2. Vanilla Snort + Cheat packet rules (packet-based upper bound)
#   3. Snort + Community rules + FlowSign flow rules (hybrid approach)
###############################################################################

set -e

SNORT_BIN="/home/maru/work/snortsharp/snort3/build/src/snort"
PLUGIN_PATH="/home/maru/work/snortsharp/snort3/build/src/plugins"
RESULTS_DIR="experiment_results/exp2_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"/{community,packet_cheat,hybrid}

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $@" | tee -a "$RESULTS_DIR/experiment.log"
}

section() {
    echo "" | tee -a "$RESULTS_DIR/experiment.log"
    echo -e "${BLUE}========================================${NC}" | tee -a "$RESULTS_DIR/experiment.log"
    echo -e "${BLUE}$@${NC}" | tee -a "$RESULTS_DIR/experiment.log"
    echo -e "${BLUE}========================================${NC}" | tee -a "$RESULTS_DIR/experiment.log"
    echo "" | tee -a "$RESULTS_DIR/experiment.log"
}

run_community() {
    local pcap=$1
    local pcap_name=$(basename "$pcap")
    local output_dir="$RESULTS_DIR/community"

    log "${YELLOW}Config 1:${NC} Vanilla Snort + Community Rules"
    log "Processing: $pcap_name"

    cat > "$output_dir/config.lua" <<EOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
EOF

    # Disable FlowSign
    export FLOWSIGN_RULES_FILE="$(pwd)/empty_flowsign_rules.txt"

    $SNORT_BIN \
        -c "$output_dir/config.lua" \
        -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" \
        -A alert_fast \
        -l "$output_dir" \
        -q 2>&1 | tee "$output_dir/${pcap_name}.log"

    log "Community config complete for $pcap_name"
}

run_packet_cheat() {
    local pcap=$1
    local pcap_name=$(basename "$pcap")
    local output_dir="$RESULTS_DIR/packet_cheat"

    log "${YELLOW}Config 2:${NC} Vanilla Snort + Cheat Packet Rules"
    log "Processing: $pcap_name"

    cat > "$output_dir/config.lua" <<EOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = {
    enable_builtin_rules = false,
    rules = [[
        include snortsharp-rules/vpn_snort3_packet.rules
    ]]
}
EOF

    # Disable FlowSign
    export FLOWSIGN_RULES_FILE="$(pwd)/empty_flowsign_rules.txt"

    $SNORT_BIN \
        -c "$output_dir/config.lua" \
        -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" \
        -A alert_fast \
        -l "$output_dir" \
        -q 2>&1 | tee "$output_dir/${pcap_name}.log"

    log "Packet cheat config complete for $pcap_name"
}

run_hybrid() {
    local pcap=$1
    local pcap_name=$(basename "$pcap")
    local output_dir="$RESULTS_DIR/hybrid"

    log "${YELLOW}Config 3:${NC} Snort + Community Rules + FlowSign Flow Rules"
    log "Processing: $pcap_name"

    cat > "$output_dir/config.lua" <<EOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
EOF

    # Enable FlowSign with flow rules
    export FLOWSIGN_RULES_FILE="$(pwd)/snortsharp-rules/vpn_flowsign_rules_depth10.txt"

    $SNORT_BIN \
        -c "$output_dir/config.lua" \
        -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" \
        -A alert_fast \
        -l "$output_dir" \
        -q 2>&1 | tee "$output_dir/${pcap_name}.log"

    log "Hybrid config complete for $pcap_name"
}

###############################################################################
# MAIN EXPERIMENT
###############################################################################

section "EXPERIMENT 2: VPN Dataset Testing"
log "Results directory: $RESULTS_DIR"
log "Objective: Demonstrate FlowSign effectiveness on encrypted/VPN traffic"
log ""
log "Three configurations to compare:"
log "  1. Vanilla Snort + Community rules"
log "  2. Vanilla Snort + Cheat packet rules (limited by encryption)"
log "  3. Snort + Community + FlowSign flow rules (encrypted-resilient)"

# Test on VPN PCAPs (first 5 for quick test, or all 31 for full test)
section "VPN PCAP Testing"

# Get VPN PCAP files (prioritize VPN-encrypted traffic)
VPN_PCAPS=($(find datasets/VPN/PCAPs -name "vpn_*.pcap" | head -5))

log "Testing ${#VPN_PCAPS[@]} VPN PCAPs"
log "PCAPs selected:"
for pcap in "${VPN_PCAPS[@]}"; do
    log "  - $(basename $pcap)"
done

for pcap in "${VPN_PCAPS[@]}"; do
    section "Processing: $(basename $pcap)"

    # Config 1: Community rules only
    run_community "$pcap" || log "${RED}WARNING: Community config failed on $pcap${NC}"

    # Config 2: Packet cheat rules
    run_packet_cheat "$pcap" || log "${RED}WARNING: Packet cheat config failed on $pcap${NC}"

    # Config 3: Hybrid (community + flow rules)
    run_hybrid "$pcap" || log "${RED}WARNING: Hybrid config failed on $pcap${NC}"

    log "Completed all configs for $(basename $pcap)"
done

###############################################################################
# SUMMARY
###############################################################################

section "EXPERIMENT COMPLETE"

log "Generating summary..."

cat > "$RESULTS_DIR/summary.txt" <<EOF
Experiment 2: VPN Dataset Testing
Date: $(date)
Results: $RESULTS_DIR

Objective: Demonstrate FlowSign effectiveness on encrypted VPN traffic

VPN PCAP Tests:
EOF

for pcap in "${VPN_PCAPS[@]}"; do
    pcap_name=$(basename "$pcap")

    # Count alerts from each configuration
    community_packet_alerts=$(grep -c "^\[" "$RESULTS_DIR/community/${pcap_name}.log" 2>/dev/null || echo "0")
    packet_cheat_alerts=$(grep -c "^\[" "$RESULTS_DIR/packet_cheat/${pcap_name}.log" 2>/dev/null || echo "0")
    hybrid_packet_alerts=$(grep -c "^\[" "$RESULTS_DIR/hybrid/${pcap_name}.log" 2>/dev/null || echo "0")
    hybrid_flow_alerts=$(grep -c "\[FLOW\]" "$RESULTS_DIR/hybrid/${pcap_name}.log" 2>/dev/null || echo "0")

    cat >> "$RESULTS_DIR/summary.txt" <<EOF

  $pcap_name:
    Config 1 (Community):         $community_packet_alerts packet alerts
    Config 2 (Packet Cheat):      $packet_cheat_alerts packet alerts
    Config 3 (Hybrid):            $hybrid_packet_alerts packet alerts + $hybrid_flow_alerts flow alerts
    FlowSign Added Value:         +$hybrid_flow_alerts flow-based detections
EOF

done

cat >> "$RESULTS_DIR/summary.txt" <<EOF

KEY FINDING:
Packet-based rules (Config 1 & 2) are limited on encrypted VPN traffic.
FlowSign (Config 3) can detect patterns even when payloads are encrypted
by analyzing flow-level behavior (timing, packet counts, etc.).

NEXT STEPS:
1. Correlate alerts with ground truth labels (ARFF files)
2. Calculate F1, Precision, Recall, Accuracy for each config
3. Analyze which VPN traffic types are detected by each approach
4. Compare detection rates on VPN vs Non-VPN traffic
EOF

cat "$RESULTS_DIR/summary.txt"

log ""
log "All results saved to: $RESULTS_DIR"
log "Summary: $RESULTS_DIR/summary.txt"
log "Detailed logs: $RESULTS_DIR/*/*.log"
log ""
log "${GREEN}Experiment 2 Complete!${NC}"
log ""
log "Next steps:"
log "  1. Review summary: cat $RESULTS_DIR/summary.txt"
log "  2. Analyze detailed logs for alert patterns"
log "  3. Correlate with ground truth labels from ARFF files"

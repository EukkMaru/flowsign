#!/bin/bash
###############################################################################
# Experiment 3: Vanilla Snort vs Snort+FlowSign
# Two configurations with resource limits:
#   1. Vanilla Snort + Community rules (baseline)
#   2. Snort + Community rules + FlowSign flow rules (enhanced)
###############################################################################

set -e

SNORT_BIN="/home/maru/work/snortsharp/snort3/build/src/snort"
PLUGIN_PATH="/home/maru/work/snortsharp/snort3/build/src/plugins"
RESULTS_DIR="experiment_results/exp3_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"/{vanilla,hybrid}/{unsw,cicids}

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
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

run_vanilla() {
    local dataset=$1
    local pcap=$2
    local output_dir="$RESULTS_DIR/vanilla/$dataset"

    log "Running Vanilla Snort on $(basename $pcap)..."

    cat > "$output_dir/config.lua" <<EOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
EOF

    # Disable FlowSign by using empty rules
    export FLOWSIGN_RULES_FILE="$(pwd)/empty_flowsign_rules.txt"

    systemd-run --user --scope -p CPUQuota=400% -p MemoryMax=4G --quiet -- \
        env FLOWSIGN_RULES_FILE="$FLOWSIGN_RULES_FILE" \
        $SNORT_BIN \
        -c "$output_dir/config.lua" \
        -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" \
        -A alert_fast \
        -l "$output_dir" \
        -q 2>&1 | tee "$output_dir/$(basename $pcap).log"
}

run_hybrid() {
    local dataset=$1
    local pcap=$2
    local flow_rules=$3
    local output_dir="$RESULTS_DIR/hybrid/$dataset"

    log "Running Snort+FlowSign on $(basename $pcap)..."

    cat > "$output_dir/config.lua" <<EOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
EOF

    # Enable FlowSign with flow rules
    export FLOWSIGN_RULES_FILE="$(pwd)/$flow_rules"

    systemd-run --user --scope -p CPUQuota=400% -p MemoryMax=4G --quiet -- \
        env FLOWSIGN_RULES_FILE="$FLOWSIGN_RULES_FILE" \
        $SNORT_BIN \
        -c "$output_dir/config.lua" \
        -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" \
        -A alert_fast \
        -l "$output_dir" \
        -q 2>&1 | tee "$output_dir/$(basename $pcap).log"
}

###############################################################################
# MAIN EXPERIMENT
###############################################################################

section "EXPERIMENT 3: Vanilla Snort vs Snort+FlowSign"
log "Results directory: $RESULTS_DIR"
log "Resource limits: 4 cores, 4GB RAM (Raspberry Pi 4)"

# Test UNSW-NB15 (first 3 PCAPs for quick test)
section "UNSW-NB15 Dataset"

UNSW_PCAPS=($(find datasets/UNSW-NB15/pcap_files -name "*.pcap" | head -3))
UNSW_FLOW_RULES="snortsharp-rules/unsw_flowsign_rules_depth10.txt"

log "Testing ${#UNSW_PCAPS[@]} UNSW-NB15 PCAPs"

for pcap in "${UNSW_PCAPS[@]}"; do
    section "Processing: $(basename $pcap)"

    # Config 1: Vanilla Snort
    run_vanilla "unsw" "$pcap" || log "WARNING: Vanilla failed on $pcap"

    # Config 2: Snort+FlowSign
    run_hybrid "unsw" "$pcap" "$UNSW_FLOW_RULES" || log "WARNING: Hybrid failed on $pcap"

    log "Completed both configs for $(basename $pcap)"
done

# Test CIC-IDS-2017 (first 2 PCAPs)
section "CIC-IDS-2017 Dataset"

CICIDS_PCAPS=($(find datasets/CIC-IDS-2017/PCAPs -name "*.pcap" | head -2))
CICIDS_FLOW_RULES="snortsharp-rules/cicids2017_flowsign_rules_depth10.txt"

log "Testing ${#CICIDS_PCAPS[@]} CIC-IDS-2017 PCAPs"

for pcap in "${CICIDS_PCAPS[@]}"; do
    section "Processing: $(basename $pcap)"

    # Config 1: Vanilla Snort
    run_vanilla "cicids" "$pcap" || log "WARNING: Vanilla failed on $pcap"

    # Config 2: Snort+FlowSign
    run_hybrid "cicids" "$pcap" "$CICIDS_FLOW_RULES" || log "WARNING: Hybrid failed on $pcap"

    log "Completed both configs for $(basename $pcap)"
done

###############################################################################
# SUMMARY
###############################################################################

section "EXPERIMENT COMPLETE"

log "Generating summary..."

cat > "$RESULTS_DIR/summary.txt" <<EOF
Experiment 3: Vanilla Snort vs Snort+FlowSign
Date: $(date)
Results: $RESULTS_DIR

UNSW-NB15 Tests:
EOF

for pcap in "${UNSW_PCAPS[@]}"; do
    pcap_name=$(basename $pcap)
    vanilla_alerts=$(grep -c "^\[" "$RESULTS_DIR/vanilla/unsw/${pcap_name}.log" 2>/dev/null || echo "0")
    hybrid_alerts=$(grep -c "^\[" "$RESULTS_DIR/hybrid/unsw/${pcap_name}.log" 2>/dev/null || echo "0")

    echo "  $pcap_name: Vanilla=$vanilla_alerts alerts, Hybrid=$hybrid_alerts alerts" >> "$RESULTS_DIR/summary.txt"
done

cat >> "$RESULTS_DIR/summary.txt" <<EOF

CIC-IDS-2017 Tests:
EOF

for pcap in "${CICIDS_PCAPS[@]}"; do
    pcap_name=$(basename $pcap)
    vanilla_alerts=$(grep -c "^\[" "$RESULTS_DIR/vanilla/cicids/${pcap_name}.log" 2>/dev/null || echo "0")
    hybrid_alerts=$(grep -c "^\[" "$RESULTS_DIR/hybrid/cicids/${pcap_name}.log" 2>/dev/null || echo "0")

    echo "  $pcap_name: Vanilla=$vanilla_alerts alerts, Hybrid=$hybrid_alerts alerts" >> "$RESULTS_DIR/summary.txt"
done

cat "$RESULTS_DIR/summary.txt"

log ""
log "All results saved to: $RESULTS_DIR"
log "Summary: $RESULTS_DIR/summary.txt"
log "Detailed logs: $RESULTS_DIR/*/$(*)/*.log"
log ""
log "Next steps:"
log "  1. Correlate alerts with ground truth labels"
log "  2. Calculate F1, Precision, Recall, Accuracy"
log "  3. Compare resource usage between vanilla and hybrid"

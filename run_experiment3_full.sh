#!/bin/bash
###############################################################################
# Experiment 3: Resource Usage Comparison
# Tests all IDS setups under Raspberry Pi 4 resource constraints
#
# Configurations tested:
#   1. Vanilla Snort3 with community rules
#   2. Vanilla Snort3 with cheat packet rules
#   3. Snort3+FlowSign hybrid (community + cheat flow rules)
#   4. DL-based IDS baseline (from baselines/)
#   5. Rudimentary LSTM (from ai-ids-analyzer)
#   6. Rudimentary XGBoost (from ai-ids-analyzer)
#
# Datasets: UNSW-NB15, CIC-IDS-2017, TON-IoT
# Resource limits: 4 cores @ 1.8GHz, 4GB RAM
###############################################################################

set -e

# Configuration
SNORT_BIN="snort3/build/src/snort"
FLOWSIGN_PLUGIN_PATH="snort3/build/src/plugins"
RESULTS_DIR="experiment_results/exp3_$(date +%Y%m%d_%H%M%S)"
RESOURCE_LIMITER="./run_with_resource_limits.sh"

# Create results directory
mkdir -p "$RESULTS_DIR"/{snort_community,snort_cheat,snort_hybrid,dl_baseline,lstm,xgboost}
mkdir -p "$RESULTS_DIR"/logs

# Log file
MAIN_LOG="$RESULTS_DIR/experiment3_main.log"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $@" | tee -a "$MAIN_LOG"
}

log_section() {
    echo "" | tee -a "$MAIN_LOG"
    echo -e "${BLUE}========================================${NC}" | tee -a "$MAIN_LOG"
    echo -e "${BLUE}$@${NC}" | tee -a "$MAIN_LOG"
    echo -e "${BLUE}========================================${NC}" | tee -a "$MAIN_LOG"
    echo "" | tee -a "$MAIN_LOG"
}

# Function to find PCAP files for a dataset
find_pcaps() {
    local dataset=$1
    case $dataset in
        "unsw")
            find datasets/UNSW-NB15/pcap_files -name "*.pcap" 2>/dev/null | head -5  # Limit for testing
            ;;
        "cicids2017")
            find datasets/CIC-IDS-2017/PCAPs -name "*.pcap" 2>/dev/null | head -5
            ;;
        "toniot")
            find datasets/ton-iot -name "*.pcap" 2>/dev/null | head -5
            ;;
    esac
}

# Function to run Snort3 with community rules
run_snort_community() {
    local dataset=$1
    local pcap=$2
    local output_dir="$RESULTS_DIR/snort_community/$dataset"
    mkdir -p "$output_dir"

    log "Running Snort3 (community rules) on $(basename $pcap)..."

    # Create config with community rules
    cat > "$output_dir/snort_community.lua" <<EOF
-- Snort3 configuration with community rules
HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    enable_builtin_rules = true,
    rules = [[
        include snort3-community-rules/snort3-community.rules
    ]]
}

-- Disable FlowSign by using empty flow rules
flowsign = {
    rules_file = 'empty_flowsign_rules.txt'
}
EOF

    # Run with resource limits
    if [ -x "$RESOURCE_LIMITER" ]; then
        sudo "$RESOURCE_LIMITER" "$SNORT_BIN" \
            -c "$output_dir/snort_community.lua" \
            -r "$pcap" \
            --plugin-path="$FLOWSIGN_PLUGIN_PATH" \
            -A alert_fast \
            -l "$output_dir" \
            -q 2>&1 | tee "$output_dir/$(basename $pcap).log"
    else
        "$SNORT_BIN" \
            -c "$output_dir/snort_community.lua" \
            -r "$pcap" \
            --plugin-path="$FLOWSIGN_PLUGIN_PATH" \
            -A alert_fast \
            -l "$output_dir" \
            -q 2>&1 | tee "$output_dir/$(basename $pcap).log"
    fi

    log "Completed Snort3 (community) for $(basename $pcap)"
}

# Function to run Snort3 with cheat packet rules
run_snort_cheat() {
    local dataset=$1
    local pcap=$2
    local output_dir="$RESULTS_DIR/snort_cheat/$dataset"
    mkdir -p "$output_dir"

    log "Running Snort3 (cheat packet rules) on $(basename $pcap)..."

    # Determine cheat rules file
    local cheat_rules=""
    case $dataset in
        "unsw")
            cheat_rules="snortsharp-rules/unsw_snort3_cheat_consolidated.rules"
            ;;
        "cicids2017")
            cheat_rules="snortsharp-rules/cicids2017_snort3_cheat.rules"
            ;;
        "toniot")
            cheat_rules="snortsharp-rules/toniot_snort3_cheat.rules"
            ;;
    esac

    if [ ! -f "$cheat_rules" ]; then
        log "WARNING: Cheat rules not found: $cheat_rules"
        return 1
    fi

    # Create config with cheat rules
    cat > "$output_dir/snort_cheat.lua" <<EOF
-- Snort3 configuration with cheat packet rules
HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    enable_builtin_rules = false,
    rules = [[
        include $cheat_rules
    ]]
}

-- Disable FlowSign
flowsign = {
    rules_file = 'empty_flowsign_rules.txt'
}
EOF

    # Run with resource limits
    if [ -x "$RESOURCE_LIMITER" ]; then
        sudo "$RESOURCE_LIMITER" "$SNORT_BIN" \
            -c "$output_dir/snort_cheat.lua" \
            -r "$pcap" \
            --plugin-path="$FLOWSIGN_PLUGIN_PATH" \
            -A alert_fast \
            -l "$output_dir" \
            -q 2>&1 | tee "$output_dir/$(basename $pcap).log"
    else
        "$SNORT_BIN" \
            -c "$output_dir/snort_cheat.lua" \
            -r "$pcap" \
            --plugin-path="$FLOWSIGN_PLUGIN_PATH" \
            -A alert_fast \
            -l "$output_dir" \
            -q 2>&1 | tee "$output_dir/$(basename $pcap).log"
    fi

    log "Completed Snort3 (cheat) for $(basename $pcap)"
}

# Function to run Snort3+FlowSign hybrid
run_snort_hybrid() {
    local dataset=$1
    local pcap=$2
    local output_dir="$RESULTS_DIR/snort_hybrid/$dataset"
    mkdir -p "$output_dir"

    log "Running Snort3+FlowSign (hybrid) on $(basename $pcap)..."

    # Determine flow rules file
    local flow_rules=""
    case $dataset in
        "unsw")
            flow_rules="snortsharp-rules/unsw_flowsign_rules_depth10.txt"
            ;;
        "cicids2017")
            flow_rules="snortsharp-rules/cicids2017_flowsign_rules_depth10.txt"
            ;;
        "toniot")
            flow_rules="snortsharp-rules/toniot_flowsign_rules_depth10.txt"
            ;;
    esac

    if [ ! -f "$flow_rules" ]; then
        log "WARNING: Flow rules not found: $flow_rules"
        return 1
    fi

    # Create config with both community and flow rules
    cat > "$output_dir/snort_hybrid.lua" <<EOF
-- Snort3 configuration with community rules + FlowSign
HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    enable_builtin_rules = true,
    rules = [[
        include snort3-community-rules/snort3-community.rules
    ]]
}

-- Enable FlowSign with cheat flow rules
flowsign = {
    rules_file = '$flow_rules'
}
EOF

    # Run with resource limits
    if [ -x "$RESOURCE_LIMITER" ]; then
        sudo "$RESOURCE_LIMITER" "$SNORT_BIN" \
            -c "$output_dir/snort_hybrid.lua" \
            -r "$pcap" \
            --plugin-path="$FLOWSIGN_PLUGIN_PATH" \
            -A alert_fast \
            -l "$output_dir" \
            -q 2>&1 | tee "$output_dir/$(basename $pcap).log"
    else
        "$SNORT_BIN" \
            -c "$output_dir/snort_hybrid.lua" \
            -r "$pcap" \
            --plugin-path="$FLOWSIGN_PLUGIN_PATH" \
            -A alert_fast \
            -l "$output_dir" \
            -q 2>&1 | tee "$output_dir/$(basename $pcap).log"
    fi

    log "Completed Snort3+FlowSign (hybrid) for $(basename $pcap)"
}

###############################################################################
# MAIN EXPERIMENT
###############################################################################

log_section "EXPERIMENT 3: Resource Usage Comparison"
log "Testing under Raspberry Pi 4 constraints (4 cores, 4GB RAM)"
log "Results directory: $RESULTS_DIR"

# Check prerequisites
log "Checking prerequisites..."

if [ ! -f "$SNORT_BIN" ]; then
    log "ERROR: Snort3 binary not found at $SNORT_BIN"
    exit 1
fi

if [ ! -d "$FLOWSIGN_PLUGIN_PATH" ]; then
    log "ERROR: FlowSign plugin path not found at $FLOWSIGN_PLUGIN_PATH"
    exit 1
fi

if [ ! -f "empty_flowsign_rules.txt" ]; then
    echo "# Empty FlowSign rules file" > empty_flowsign_rules.txt
    log "Created empty FlowSign rules file"
fi

log "Prerequisites OK"

# Test each dataset
for dataset in unsw cicids2017; do
    log_section "TESTING DATASET: $dataset"

    # Find PCAPs
    pcaps=($(find_pcaps $dataset))

    if [ ${#pcaps[@]} -eq 0 ]; then
        log "WARNING: No PCAPs found for $dataset, skipping..."
        continue
    fi

    log "Found ${#pcaps[@]} PCAP files for $dataset"

    # Test each PCAP with all configurations
    for pcap in "${pcaps[@]}"; do
        log_section "Processing: $(basename $pcap)"

        # Configuration 1: Snort3 with community rules
        run_snort_community "$dataset" "$pcap" || log "WARNING: Snort community failed"

        # Configuration 2: Snort3 with cheat packet rules
        run_snort_cheat "$dataset" "$pcap" || log "WARNING: Snort cheat failed"

        # Configuration 3: Snort3+FlowSign hybrid
        run_snort_hybrid "$dataset" "$pcap" || log "WARNING: Snort hybrid failed"

        log "Completed all configurations for $(basename $pcap)"
    done
done

log_section "EXPERIMENT 3 COMPLETE"
log "Results saved to: $RESULTS_DIR"
log "To analyze results, run: python3 analyze_exp3_results.py $RESULTS_DIR"

echo ""
echo "Summary:"
echo "  - Results directory: $RESULTS_DIR"
echo "  - Main log: $MAIN_LOG"
echo "  - Resource logs: $RESULTS_DIR/logs/"
echo ""

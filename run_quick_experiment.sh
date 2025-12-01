#!/bin/bash
###############################################################################
# Quick Experiment 3 Test - Single PCAP with all configurations
# Tests resource-limited IDS on one PCAP to verify setup
###############################################################################

set -e

SNORT_BIN="/home/maru/work/snortsharp/snort3/build/src/snort"
PLUGIN_PATH="/home/maru/work/snortsharp/snort3/build/src/plugins"
RESULTS_DIR="experiment_results/quick_test_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"/{community,cheat,hybrid}

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $@"
}

# Use first UNSW-NB15 PCAP
TEST_PCAP="datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015/1.pcap"

log "Quick Experiment Test"
log "PCAP: $TEST_PCAP"
log "Results: $RESULTS_DIR"

## Configuration 1: Snort3 with community rules (FlowSign disabled)
log "=== Config 1: Snort3 + Community Rules ==="

cat > "$RESULTS_DIR/community/config.lua" <<EOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    enable_builtin_rules = true,
}
EOF

log "Running with resource limits..."
systemd-run --user --scope -p CPUQuota=400% -p MemoryMax=4G --quiet -- \
    $SNORT_BIN \
    -c "$RESULTS_DIR/community/config.lua" \
    -r "$TEST_PCAP" \
    --plugin-path="$PLUGIN_PATH" \
    -A alert_fast \
    -l "$RESULTS_DIR/community" \
    -q 2>&1 | tee "$RESULTS_DIR/community/output.log"

log "Community rules test complete"

## Configuration 2: Snort3 with cheat packet rules (FlowSign disabled)
log "=== Config 2: Snort3 + Cheat Packet Rules ==="

cat > "$RESULTS_DIR/cheat/config.lua" <<EOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    enable_builtin_rules = false,
    rules = [[
        include snortsharp-rules/unsw_snort3_cheat_consolidated.rules
    ]]
}
EOF

log "Running with resource limits..."
systemd-run --user --scope -p CPUQuota=400% -p MemoryMax=4G --quiet -- \
    $SNORT_BIN \
    -c "$RESULTS_DIR/cheat/config.lua" \
    -r "$TEST_PCAP" \
    --plugin-path="$PLUGIN_PATH" \
    -A alert_fast \
    -l "$RESULTS_DIR/cheat" \
    -q 2>&1 | tee "$RESULTS_DIR/cheat/output.log"

log "Cheat rules test complete"

## Configuration 3: Snort3+FlowSign with community + flow rules
log "=== Config 3: Snort3 + FlowSign (Hybrid) ==="

# Export FlowSign rules path
export FLOWSIGN_RULES_FILE="$(pwd)/snortsharp-rules/unsw_flowsign_rules_depth10.txt"

cat > "$RESULTS_DIR/hybrid/config.lua" <<EOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    enable_builtin_rules = true,
}
EOF

log "Running with resource limits (FlowSign enabled via env var)..."
systemd-run --user --scope -p CPUQuota=400% -p MemoryMax=4G --quiet -- \
    env FLOWSIGN_RULES_FILE="$FLOWSIGN_RULES_FILE" \
    $SNORT_BIN \
    -c "$RESULTS_DIR/hybrid/config.lua" \
    -r "$TEST_PCAP" \
    --plugin-path="$PLUGIN_PATH" \
    -A alert_fast \
    -l "$RESULTS_DIR/hybrid" \
    -q 2>&1 | tee "$RESULTS_DIR/hybrid/output.log"

log "Hybrid test complete"

## Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Quick Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

for config in community cheat hybrid; do
    echo -e "${GREEN}$config:${NC}"

    # Count alerts
    if [ -f "$RESULTS_DIR/$config/alert_fast.txt" ]; then
        alerts=$(wc -l < "$RESULTS_DIR/$config/alert_fast.txt")
        echo "  Alerts: $alerts"
    else
        echo "  Alerts: 0 (no alert file)"
    fi

    # Check for errors
    if grep -q "ERROR" "$RESULTS_DIR/$config/output.log" 2>/dev/null; then
        echo "  ⚠ Errors detected in log"
    fi

    echo ""
done

echo "Results saved to: $RESULTS_DIR"
echo ""
echo "To analyze results:"
echo "  cat $RESULTS_DIR/*/output.log | grep -E '(packets|analyzed|dropped|CPU)'"
echo ""

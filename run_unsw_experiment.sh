#!/bin/bash
#
# UNSW-NB15 PCAP-Based Evaluation
# Proper experimental design per WRONG.md guidelines
#

echo "========================================================================"
echo "UNSW-NB15 PCAP-Based Evaluation"
echo "Test 1: Snort3 Baseline (0 flow rules)"
echo "Test 3: Snort3 + FlowSign (527 depth=10 rules)"
echo "========================================================================"

# Configuration
SNORT_BIN="/home/maru/work/snortsharp/snort3/build/src/snort"
CONFIG="test1_config.lua"
PLUGIN_PATH="/home/maru/work/snortsharp/snort3/build/src/plugins"
PCAP_DIR="unsw_pcaps"
RESULTS_DIR="experiment_results/unsw_nb15"
EMPTY_RULES="empty_flow_rules.txt"
FLOW_RULES="snortsharp-rules/unsw_flowsign_rules_depth10.txt"

# Create results directory
mkdir -p "$RESULTS_DIR"

# Get list of PCAP files (symlinks to avoid space issues)
PCAP_FILES=(
    "$PCAP_DIR/10.pcap"
    "$PCAP_DIR/11.pcap"
    "$PCAP_DIR/12.pcap"
)

echo ""
echo "Processing ${#PCAP_FILES[@]} PCAP files..."
echo ""

# TEST 1: Baseline (0 flow rules)
echo "========================================================================"
echo "TEST 1: Snort3 Baseline (0 flow rules)"
echo "========================================================================"

export FLOWSIGN_RULES_FILE="$EMPTY_RULES"

for pcap in "${PCAP_FILES[@]}"; do
    pcap_name=$(basename "$pcap" .pcap)
    echo "Processing $pcap_name with baseline config..."

    timeout 300 "$SNORT_BIN" -c "$CONFIG" -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" -q \
        > "$RESULTS_DIR/test1_baseline_${pcap_name}.log" 2>&1

    echo "  Completed $pcap_name (baseline)"
done

echo ""
echo "TEST 1 complete. Collecting statistics..."
echo ""

# Count Snort3 alerts from CSV (if alert_csv is enabled)
test1_alerts=$(cat "$RESULTS_DIR"/test1_baseline_*.log 2>/dev/null | grep -c "FlowSign Alert" || echo "0")
echo "TEST 1 FlowSign Alerts: $test1_alerts (expected 0 with 0 rules)"

echo ""
echo "========================================================================"
echo "TEST 3: Snort3 + FlowSign (527 flow rules)"
echo "========================================================================"

export FLOWSIGN_RULES_FILE="$FLOW_RULES"

for pcap in "${PCAP_FILES[@]}"; do
    pcap_name=$(basename "$pcap" .pcap)
    echo "Processing $pcap_name with FlowSign rules..."

    timeout 300 "$SNORT_BIN" -c "$CONFIG" -r "$pcap" \
        --plugin-path="$PLUGIN_PATH" -q \
        > "$RESULTS_DIR/test3_flowsign_${pcap_name}.log" 2>&1

    echo "  Completed $pcap_name (FlowSign)"
done

echo ""
echo "TEST 3 complete. Collecting statistics..."
echo ""

# Count FlowSign alerts from stdout
test3_alerts=$(cat "$RESULTS_DIR"/test3_flowsign_*.log 2>/dev/null | grep -c "FlowSign Alert" || echo "0")
echo "TEST 3 FlowSign Alerts: $test3_alerts"

echo ""
echo "========================================================================"
echo "Experiment Complete"
echo "========================================================================"
echo "Results saved to: $RESULTS_DIR"
echo ""
echo "TEST 1 (Baseline): $test1_alerts FlowSign alerts"
echo "TEST 3 (FlowSign): $test3_alerts FlowSign alerts"
echo ""
echo "Next: Evaluate alerts against ground truth labels"
echo "========================================================================"

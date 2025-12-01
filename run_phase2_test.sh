#!/bin/bash
# Phase 2 Quick Test - Single PCAP (27.pcap)

set -e

PCAP="test_sample.pcap"
SNORT="./snort3/build/src/snort"
CONFIG="snort3/lua/snort.lua"
OUTPUT_DIR="phase2_test_results"

mkdir -p "$OUTPUT_DIR"

echo "================================================================================"
echo "PHASE 2 TEST: Snort++ vs Snort++ + FlowSign"
echo "Test PCAP: 27.pcap (569MB, ~1M packets)"
echo "================================================================================"
echo ""

# Test 1: Snort++ Only
echo "[TEST 1] Running Snort++ Only (FlowSign disabled)..."
echo "--------------------------------------------------------------------------------"

# Disable FlowSign
if [ -f "unsw_nb15_rules.txt" ]; then
    mv unsw_nb15_rules.txt unsw_nb15_rules.txt.backup
    echo "[INFO] FlowSign rules disabled"
fi

START_TIME=$(date +%s)
"$SNORT" -c "$CONFIG" -r "$PCAP" -A cmg -q \
    > "$OUTPUT_DIR/snort_only_output.log" 2>&1
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo "[COMPLETE] Snort++ Only finished in ${ELAPSED}s"

# Extract statistics
SNORT_PACKETS=$(grep -o "Packets received: [0-9]*" "$OUTPUT_DIR/snort_only_output.log" | grep -o "[0-9]*" | head -1)
SNORT_ALERTS=$(grep -c "\[Priority:" "$OUTPUT_DIR/snort_only_output.log" || echo "0")

echo "  Packets: $SNORT_PACKETS"
echo "  Alerts: $SNORT_ALERTS"
echo ""

# Test 2: Snort++ + FlowSign
echo "[TEST 2] Running Snort++ + FlowSign (Hybrid mode)..."
echo "--------------------------------------------------------------------------------"

# Re-enable FlowSign
if [ -f "unsw_nb15_rules.txt.backup" ]; then
    mv unsw_nb15_rules.txt.backup unsw_nb15_rules.txt
    echo "[INFO] FlowSign rules enabled"
fi

START_TIME=$(date +%s)
"$SNORT" -c "$CONFIG" -r "$PCAP" -A cmg -q \
    > "$OUTPUT_DIR/hybrid_output.log" 2>&1
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo "[COMPLETE] Hybrid mode finished in ${ELAPSED}s"

# Extract statistics
HYBRID_PACKETS=$(grep -o "Packets received: [0-9]*" "$OUTPUT_DIR/hybrid_output.log" | grep -o "[0-9]*" | head -1)
HYBRID_PACKET_ALERTS=$(grep -c "\[Priority:" "$OUTPUT_DIR/hybrid_output.log" || echo "0")
HYBRID_FLOW_ALERTS=$(grep -c "\[FLOW\] SID:" "$OUTPUT_DIR/hybrid_output.log" || echo "0")
HYBRID_TOTAL=$((HYBRID_PACKET_ALERTS + HYBRID_FLOW_ALERTS))

echo "  Packets: $HYBRID_PACKETS"
echo "  Packet Alerts: $HYBRID_PACKET_ALERTS"
echo "  Flow Alerts: $HYBRID_FLOW_ALERTS"
echo "  Total Alerts: $HYBRID_TOTAL"
echo ""

# Comparison
echo "================================================================================"
echo "RESULTS COMPARISON"
echo "================================================================================"
echo ""
echo "Snort++ Only:"
echo "  Packets: $SNORT_PACKETS"
echo "  Alerts: $SNORT_ALERTS"
echo ""
echo "Snort++ + FlowSign:"
echo "  Packets: $HYBRID_PACKETS"
echo "  Packet Alerts: $HYBRID_PACKET_ALERTS"
echo "  Flow Alerts: $HYBRID_FLOW_ALERTS"
echo "  Total Alerts: $HYBRID_TOTAL"
echo ""

if [ "$HYBRID_TOTAL" -gt "$SNORT_ALERTS" ]; then
    INCREASE=$((HYBRID_TOTAL - SNORT_ALERTS))
    PERCENT=$(awk "BEGIN {printf \"%.2f\", ($INCREASE / $SNORT_ALERTS) * 100}")
    echo "Additional Coverage: +$INCREASE alerts (+${PERCENT}%)"
else
    echo "No additional coverage detected"
fi

echo ""
echo "Results saved to: $OUTPUT_DIR/"
echo "  - snort_only_output.log"
echo "  - hybrid_output.log"
echo ""
echo "================================================================================"

#!/bin/bash
# Simple performance measurement without perf
SNORT_BIN="/home/maru/work/snortsharp/snort3/build/src/snort"
PLUGIN_PATH="/home/maru/work/snortsharp/snort3/build/src/plugins"
TEST_PCAP="datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015/27.pcap"

echo "=== Simple Performance Measurement ==="

# Vanilla Snort
echo "Timing Vanilla Snort..."
export FLOWSIGN_RULES_FILE="$(pwd)/empty_flowsign_rules.txt"
/usr/bin/time -v $SNORT_BIN -c /dev/null -r "$TEST_PCAP" --plugin-path="$PLUGIN_PATH" \
    -q 2>&1 | grep -E "Elapsed|Maximum resident|Percent of CPU"

# Snort+FlowSign  
echo ""
echo "Timing Snort+FlowSign..."
export FLOWSIGN_RULES_FILE="$(pwd)/snortsharp-rules/unsw_flowsign_rules_depth10.txt"
/usr/bin/time -v $SNORT_BIN -c /dev/null -r "$TEST_PCAP" --plugin-path="$PLUGIN_PATH" \
    -q 2>&1 | grep -E "Elapsed|Maximum resident|Percent of CPU"

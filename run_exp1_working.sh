#!/bin/bash
#
# Experiment 1: Three-Way IDS Comparison (Working Version)
# Focuses on alert generation patterns since ground truth matching is broken
#
# Compares:
# 1. Snort3 Community Rules (packet-level baseline)
# 2. Snort3 Community + FlowSign Rules (hybrid approach)
# 3. Analysis of complementary detection

set -e

echo "========================================================================"
echo "EXPERIMENT 1: THREE-WAY IDS COMPARISON"
echo "========================================================================"
echo ""

# Configuration
SNORT_BIN="./snort3/build/src/snort"
CONFIG="test1_config.lua"
PLUGIN_PATH="./snort3/build/src/plugins"

# Rules
COMMUNITY_RULES="./snort3-community-rules/snort3-community.rules"
FLOW_RULES="./snortsharp-rules/unsw_flowsign_rules_depth10.txt"
EMPTY_FLOW_RULES="./empty_flowsign_rules.txt"

# PCAPs
PCAP_DIR="./datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015"
PCAPS=("10.pcap" "11.pcap" "12.pcap")

# Results
RESULTS_DIR="./experiment_results/exp1_working"
mkdir -p "$RESULTS_DIR"

echo "Test Configurations:"
echo "1. Snort3 Community Rules (packet-level only)"
echo "2. Snort3 Community + FlowSign (hybrid packet+flow)"
echo ""
echo "PCAPs: ${PCAPS[@]}"
echo ""
echo "========================================================================"
echo ""

# Results summary file
SUMMARY="$RESULTS_DIR/summary.txt"
echo "Configuration,PCAP,PacketAlerts,FlowAlerts,TotalAlerts" > "$SUMMARY.csv"

for pcap in "${PCAPS[@]}"; do
    pcap_file="$PCAP_DIR/$pcap"
    pcap_name="${pcap%.pcap}"

    echo "========================================================================"
    echo "Processing: $pcap"
    echo "========================================================================"

    # -------------------------------------------------------------------------
    # Test 1: Community Rules Only (Baseline)
    # -------------------------------------------------------------------------
    echo ""
    echo "[Test 1] Snort3 Community Rules (Packet-Level Only)"
    echo "---------------------------------------------------------------------"

    rm -f alert_csv.txt
    export FLOWSIGN_RULES_FILE="$EMPTY_FLOW_RULES"

    timeout 600 "$SNORT_BIN" -c "$CONFIG" -R "$COMMUNITY_RULES" -r "$pcap_file" \
        --plugin-path="$PLUGIN_PATH" -q \
        > "$RESULTS_DIR/${pcap_name}_community.log" 2>&1 || true

    # Count alerts
    packet_alerts_1=0
    flow_alerts_1=0

    if [ -f "alert_csv.txt" ]; then
        packet_alerts_1=$(wc -l < alert_csv.txt || echo "0")
        cp alert_csv.txt "$RESULTS_DIR/${pcap_name}_community_alerts.csv"
    fi

    flow_alerts_1=$(grep -c "FlowSign Alert" "$RESULTS_DIR/${pcap_name}_community.log" || echo "0")

    total_1=$((${packet_alerts_1:-0} + ${flow_alerts_1:-0}))

    echo "  Packet Alerts: $packet_alerts_1"
    echo "  Flow Alerts: $flow_alerts_1"
    echo "  Total Alerts: $total_1"
    echo ""

    echo "Community,$pcap_name,$packet_alerts_1,$flow_alerts_1,$total_1" >> "$SUMMARY.csv"

    # -------------------------------------------------------------------------
    # Test 2: Community + FlowSign Rules (Hybrid)
    # -------------------------------------------------------------------------
    echo "[Test 2] Snort3 Community + FlowSign (Hybrid Packet+Flow)"
    echo "---------------------------------------------------------------------"

    rm -f alert_csv.txt
    export FLOWSIGN_RULES_FILE="$FLOW_RULES"

    timeout 600 "$SNORT_BIN" -c "$CONFIG" -R "$COMMUNITY_RULES" -r "$pcap_file" \
        --plugin-path="$PLUGIN_PATH" -q \
        > "$RESULTS_DIR/${pcap_name}_hybrid.log" 2>&1 || true

    # Count alerts
    packet_alerts_2=0
    flow_alerts_2=0

    if [ -f "alert_csv.txt" ]; then
        packet_alerts_2=$(wc -l < alert_csv.txt || echo "0")
        cp alert_csv.txt "$RESULTS_DIR/${pcap_name}_hybrid_alerts.csv"
    fi

    flow_alerts_2=$(grep -c "FlowSign Alert" "$RESULTS_DIR/${pcap_name}_hybrid.log" || echo "0")

    total_2=$((${packet_alerts_2:-0} + ${flow_alerts_2:-0}))

    echo "  Packet Alerts: $packet_alerts_2"
    echo "  Flow Alerts: $flow_alerts_2"
    echo "  Total Alerts: $total_2"
    echo ""

    echo "Hybrid,$pcap_name,$packet_alerts_2,$flow_alerts_2,$total_2" >> "$SUMMARY.csv"

    # -------------------------------------------------------------------------
    # Comparison
    # -------------------------------------------------------------------------
    echo "[Comparison]"
    echo "---------------------------------------------------------------------"
    echo "  Community (baseline):        $total_1 alerts ($packet_alerts_1 packet + $flow_alerts_1 flow)"
    echo "  Hybrid (Community+FlowSign): $total_2 alerts ($packet_alerts_2 packet + $flow_alerts_2 flow)"

    additional_coverage=${flow_alerts_2:-0}
    echo "  Additional flow-level alerts: $additional_coverage"
    echo ""

    # Extract sample flow alerts
    if [ $flow_alerts_2 -gt 0 ]; then
        echo "  Sample FlowSign Alerts:"
        grep "FlowSign Alert" "$RESULTS_DIR/${pcap_name}_hybrid.log" | head -5 | sed 's/^/    /'
    fi

    echo ""
done

# Generate final report
echo "========================================================================"
echo "EXPERIMENT 1: FINAL RESULTS"
echo "========================================================================"
echo ""

cat "$SUMMARY.csv" | column -t -s,

echo ""
echo "Results saved to: $RESULTS_DIR/"
echo "  - Individual logs: ${pcap_name}_*.log"
echo "  - Alert CSVs: ${pcap_name}_*_alerts.csv"
echo "  - Summary: summary.csv"
echo ""

# Generate Python analysis report
python3 - <<'PYTHON_SCRIPT'
import pandas as pd
import sys

df = pd.read_csv('./experiment_results/exp1_working/summary.csv')

print("\n" + "="*80)
print("ALERT GENERATION ANALYSIS")
print("="*80 + "\n")

# Group by configuration
community = df[df['Configuration'] == 'Community']
hybrid = df[df['Configuration'] == 'Hybrid']

print("## Snort3 Community Rules (Packet-Level Only)")
print(f"  Total Packet Alerts: {community['PacketAlerts'].sum()}")
print(f"  Total Flow Alerts: {community['FlowAlerts'].sum()}")
print(f"  Total Alerts: {community['TotalAlerts'].sum()}")
print(f"  Average per PCAP: {community['TotalAlerts'].mean():.0f}")
print()

print("## Snort3 Community + FlowSign (Hybrid)")
print(f"  Total Packet Alerts: {hybrid['PacketAlerts'].sum()}")
print(f"  Total Flow Alerts: {hybrid['FlowAlerts'].sum()}")
print(f"  Total Alerts: {hybrid['TotalAlerts'].sum()}")
print(f"  Average per PCAP: {hybrid['TotalAlerts'].mean():.0f}")
print()

print("## Complementary Detection")
additional_flow = hybrid['FlowAlerts'].sum() - community['FlowAlerts'].sum()
print(f"  Flow-level alerts added by FlowSign: {additional_flow}")
improvement_pct = (additional_flow / community['TotalAlerts'].sum() * 100) if community['TotalAlerts'].sum() > 0 else 0
print(f"  Coverage improvement: {improvement_pct:.2f}%")
print()

print("## Per-PCAP Breakdown")
print()
print(df.to_string(index=False))
print()

# Save report
with open('./experiment_results/exp1_working/EXPERIMENT1_REPORT.md', 'w') as f:
    f.write("# Experiment 1: Three-Way IDS Comparison\n\n")
    f.write("## Configuration\n\n")
    f.write("1. **Snort3 Community Rules**: Packet-level detection only\n")
    f.write("2. **Snort3 Community + FlowSign**: Hybrid packet + flow detection\n\n")
    f.write("## Alert Generation Summary\n\n")
    f.write(df.to_markdown(index=False))
    f.write("\n\n## Key Findings\n\n")
    f.write(f"- Community rules generated {community['TotalAlerts'].sum()} total alerts\n")
    f.write(f"- Hybrid approach generated {hybrid['TotalAlerts'].sum()} total alerts\n")
    f.write(f"- FlowSign added {additional_flow} flow-level alerts\n")
    f.write(f"- Coverage improvement: {improvement_pct:.2f}%\n")

print("="*80)
print("Report saved to: ./experiment_results/exp1_working/EXPERIMENT1_REPORT.md")
print("="*80)
PYTHON_SCRIPT

echo ""
echo "EXPERIMENT 1 COMPLETE"
echo ""

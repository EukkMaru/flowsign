#!/bin/bash
#
# Experiment 1: Simplified Three-Way Comparison
#

set -e

echo "=========================================================================="
echo "EXPERIMENT 1: SNORT3 COMMUNITY vs SNORT3+FLOWSIGN COMPARISON"
echo "=========================================================================="
echo ""

# Config
SNORT="./snort3/build/src/snort"
CONFIG="test1_config.lua"
PLUGIN="./snort3/build/src/plugins"
COMM_RULES="./snort3-community-rules/snort3-community.rules"
FLOW_RULES="./snortsharp-rules/unsw_flowsign_rules_depth10.txt"
EMPTY_RULES="./empty_flowsign_rules.txt"

PCAP_DIR="./datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015"
RES_DIR="./experiment_results/exp1_simple"
mkdir -p "$RES_DIR"

# Results CSV
CSV="$RES_DIR/results.csv"
echo "Config,PCAP,PacketAlerts,FlowAlerts,Total" > "$CSV"

process_pcap() {
    local pcap_num=$1
    local pcap_file="$PCAP_DIR/${pcap_num}.pcap"
    local pcap_name="${pcap_num}"

    echo "========================================================================"
    echo "Processing PCAP: ${pcap_num}.pcap"
    echo "========================================================================"

    # Test 1: Community only
    echo "[1/2] Running Snort3 Community (packet-level only)..."
    rm -f alert_csv.txt
    export FLOWSIGN_RULES_FILE="$EMPTY_RULES"

    timeout 600 "$SNORT" -c "$CONFIG" -R "$COMM_RULES" -r "$pcap_file" \
        --plugin-path="$PLUGIN" -q > "$RES_DIR/${pcap_name}_comm.log" 2>&1 || true

    # Count packet alerts
    comm_packet=0
    if [ -f alert_csv.txt ]; then
        comm_packet=$(wc -l < alert_csv.txt)
        cp alert_csv.txt "$RES_DIR/${pcap_name}_comm.csv"
    fi

    # Count flow alerts (should be 0)
    comm_flow=$(grep "\[FLOW\] SID:" "$RES_DIR/${pcap_name}_comm.log" 2>/dev/null | wc -l)
    comm_total=$((comm_packet + comm_flow))

    echo "  Packet alerts: $comm_packet"
    echo "  Flow alerts: $comm_flow"
    echo "  Total: $comm_total"
    echo ""

    # Test 2: Community + FlowSign
    echo "[2/2] Running Snort3 + FlowSign (hybrid packet+flow)..."
    rm -f alert_csv.txt
    export FLOWSIGN_RULES_FILE="$FLOW_RULES"

    timeout 600 "$SNORT" -c "$CONFIG" -R "$COMM_RULES" -r "$pcap_file" \
        --plugin-path="$PLUGIN" -q > "$RES_DIR/${pcap_name}_hybrid.log" 2>&1 || true

    # Count packet alerts
    hybrid_packet=0
    if [ -f alert_csv.txt ]; then
        hybrid_packet=$(wc -l < alert_csv.txt)
        cp alert_csv.txt "$RES_DIR/${pcap_name}_hybrid.csv"
    fi

    # Count flow alerts
    hybrid_flow=$(grep "\[FLOW\] SID:" "$RES_DIR/${pcap_name}_hybrid.log" 2>/dev/null | wc -l)
    hybrid_total=$((hybrid_packet + hybrid_flow))

    echo "  Packet alerts: $hybrid_packet"
    echo "  Flow alerts: $hybrid_flow"
    echo "  Total: $hybrid_total"
    echo ""

    # Summary
    echo "  SUMMARY:"
    echo "    Community: $comm_total alerts"
    echo "    Hybrid: $hybrid_total alerts"
    echo "    FlowSign contribution: $hybrid_flow additional alerts"
    echo ""

    # Save to CSV
    echo "Community,$pcap_name,$comm_packet,$comm_flow,$comm_total" >> "$CSV"
    echo "Hybrid,$pcap_name,$hybrid_packet,$hybrid_flow,$hybrid_total" >> "$CSV"
}

# Process each PCAP
for pcap in 10 11 12; do
    process_pcap "$pcap"
done

echo "=========================================================================="
echo "EXPERIMENT COMPLETE"
echo "=========================================================================="
echo ""

# Show results
echo "RESULTS:"
column -t -s, < "$CSV"
echo ""

# Generate analysis
python3 << 'EOF'
import pandas as pd

df = pd.read_csv('./experiment_results/exp1_simple/results.csv')

comm = df[df['Config'] == 'Community']
hybrid = df[df['Config'] == 'Hybrid']

print("\n" + "="*80)
print("ANALYSIS")
print("="*80)
print()

print("Community Rules (Packet-Level Only):")
print(f"  Total Packet Alerts: {comm['PacketAlerts'].sum():,}")
print(f"  Total Flow Alerts: {comm['FlowAlerts'].sum():,}")
print(f"  Total Alerts: {comm['Total'].sum():,}")
print()

print("Hybrid (Community + FlowSign):")
print(f"  Total Packet Alerts: {hybrid['PacketAlerts'].sum():,}")
print(f"  Total Flow Alerts: {hybrid['FlowAlerts'].sum():,}")
print(f"  Total Alerts: {hybrid['Total'].sum():,}")
print()

flow_added = hybrid['FlowAlerts'].sum()
improvement = (flow_added / comm['Total'].sum() * 100) if comm['Total'].sum() > 0 else 0

print("Complementary Detection:")
print(f"  Flow-level alerts added: {flow_added:,}")
print(f"  Coverage improvement: {improvement:.2f}%")
print()

# Save report
with open('./experiment_results/exp1_simple/REPORT.md', 'w') as f:
    f.write("# Experiment 1: Three-Way IDS Comparison Results\n\n")
    f.write("## Configuration\n\n")
    f.write("- **Community**: Snort3 with community rules (packet-level detection)\n")
    f.write("- **Hybrid**: Snort3 + FlowSign (packet + flow detection)\n\n")
    f.write("## Results\n\n")
    f.write(df.to_markdown(index=False))
    f.write("\n\n## Summary\n\n")
    f.write(f"- Community rules: {comm['Total'].sum():,} total alerts\n")
    f.write(f"- Hybrid approach: {hybrid['Total'].sum():,} total alerts\n")
    f.write(f"- FlowSign added: {flow_added:,} flow-level alerts ({improvement:.2f}% improvement)\n")

print("="*80)
print("Report saved to: ./experiment_results/exp1_simple/REPORT.md")
print("="*80)
EOF

echo ""
echo "All results saved to: $RES_DIR/"
echo ""

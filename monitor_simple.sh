#!/bin/bash
# Simple monitoring without systemd-run constraints
# Just monitor actual resource usage

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/experiment_results/resource_monitoring"
mkdir -p "$RESULTS_DIR"

TEST_PCAP="datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015/27.pcap"

echo "=== Monitoring Vanilla Snort3 ==="
$SCRIPT_DIR/snort3/build/src/snort -c test1_config.lua -r $TEST_PCAP --plugin-path=$SCRIPT_DIR/snort3/build/src/plugins -q > /dev/null 2>&1 &
SNORT_PID=$!
python3 monitor_resource_usage.py --pid $SNORT_PID --output "$RESULTS_DIR/vanilla_snort3.csv" --interval 0.05 || true
wait $SNORT_PID

echo ""
echo "=== Monitoring Snort3+FlowSign ==="
export FLOWSIGN_RULES_FILE="$SCRIPT_DIR/snortsharp-rules/unsw_flowsign_rules_depth10.txt"
$SCRIPT_DIR/snort3/build/src/snort -c test1_config.lua -r $TEST_PCAP --plugin-path=$SCRIPT_DIR/snort3/build/src/plugins -q > /dev/null 2>&1 &
SNORT_FLOWSIGN_PID=$!
python3 monitor_resource_usage.py --pid $SNORT_FLOWSIGN_PID --output "$RESULTS_DIR/snort3_flowsign.csv" --interval 0.05 || true
wait $SNORT_FLOWSIGN_PID
unset FLOWSIGN_RULES_FILE

echo ""
echo "=== Monitoring BAE-UQ-IDS (without memory limit) ==="
cd "$SCRIPT_DIR/baselines/BAE-UQ-IDS"
python3 run_bae_fixed_nosave.py > /dev/null 2>&1 &
BAE_PID=$!
python3 "$SCRIPT_DIR/monitor_resource_usage.py" --pid $BAE_PID --output "$RESULTS_DIR/bae_uq_ids.csv" --interval 0.1 || true
wait $BAE_PID
cd "$SCRIPT_DIR"

echo ""
echo "=== Generating comparison ==="
python3 - <<'PYCODE'
import pandas as pd
import os

results_dir = "experiment_results/resource_monitoring"

experiments = {
    "Vanilla Snort3": "vanilla_snort3.csv",
    "Snort3+FlowSign": "snort3_flowsign.csv",
    "BAE-UQ-IDS": "bae_uq_ids.csv"
}

print("\n" + "="*80)
print("RESOURCE USAGE COMPARISON")
print("="*80)

summary = []

for name, filename in experiments.items():
    filepath = os.path.join(results_dir, filename)
    if not os.path.exists(filepath):
        print(f"\nWarning: {filepath} not found")
        continue

    df = pd.read_csv(filepath)
    if len(df) == 0:
        print(f"\nWarning: {filename} has no data")
        continue

    print(f"\n{name}:")
    print(f"  Duration: {df['elapsed_sec'].max():.2f}s")
    print(f"  CPU%:  Mean={df['cpu_percent'].mean():.2f}%, Max={df['cpu_percent'].max():.2f}%, Std={df['cpu_percent'].std():.2f}%")
    print(f"  Memory: Mean={df['rss_mb'].mean():.2f}MB, Max={df['rss_mb'].max():.2f}MB")
    print(f"  Samples: {len(df)}")

    summary.append({
        'System': name,
        'Duration (s)': df['elapsed_sec'].max(),
        'CPU Mean (%)': df['cpu_percent'].mean(),
        'CPU Max (%)': df['cpu_percent'].max(),
        'Memory Mean (MB)': df['rss_mb'].mean(),
        'Memory Max (MB)': df['rss_mb'].max()
    })

summary_df = pd.DataFrame(summary)
summary_path = os.path.join(results_dir, "comparison_summary.csv")
summary_df.to_csv(summary_path, index=False)

print(f"\n\nSummary saved to: {summary_path}")
print("\n" + "="*80)
print(summary_df.to_string(index=False))
print("="*80)
PYCODE

echo "Complete! Results in: $RESULTS_DIR"

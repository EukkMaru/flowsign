#!/bin/bash
# Run IDS experiments under Raspberry Pi-like resource constraints
# Hardware constraints: 4 cores, 4GB RAM

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/experiment_results/resource_constrained"
mkdir -p "$RESULTS_DIR"

# Resource limits (Raspberry Pi 4 specs)
CPU_QUOTA="400%"  # 4 cores (100% per core)
MEMORY_LIMIT="4G"  # 4GB RAM

# Test PCAP file
TEST_PCAP="datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015/27.pcap"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to run command under resource constraints with monitoring
run_constrained() {
    local name="$1"
    local command="$2"
    local output_csv="$RESULTS_DIR/${name}_resources.csv"
    local log_file="$RESULTS_DIR/${name}_output.log"

    log_info "Running: $name"
    log_info "Resource limits: CPU=$CPU_QUOTA, Memory=$MEMORY_LIMIT"
    log_info "CSV output: $output_csv"
    log_info "Log output: $log_file"

    # Start the process in background with resource limits
    systemd-run --user --scope --slice=ids-test \
        -p CPUQuota="$CPU_QUOTA" \
        -p MemoryMax="$MEMORY_LIMIT" \
        -p MemorySwapMax=0 \
        bash -c "$command" > "$log_file" 2>&1 &

    local systemd_pid=$!

    # Wait a bit for process to start
    sleep 0.5

    # Get the actual process PID (look for the command, not systemd-run wrapper)
    local actual_pid=""
    if echo "$command" | grep -q "snort"; then
        # For snort processes
        actual_pid=$(pgrep -f "snort.*$TEST_PCAP" | head -1)
    elif echo "$command" | grep -q "python3"; then
        # For Python processes
        actual_pid=$(pgrep -f "run_bae_fixed_nosave.py" | head -1)
    fi

    if [ -z "$actual_pid" ]; then
        log_error "Failed to find PID for $name"
        wait $systemd_pid || true
        return 1
    fi

    log_info "Started process with PID: $actual_pid"

    # Monitor the process
    python3 "$SCRIPT_DIR/monitor_resource_usage.py" \
        --pid "$actual_pid" \
        --output "$output_csv" \
        --interval 0.1 &

    local monitor_pid=$!

    # Wait for systemd-run to complete
    wait $systemd_pid || true

    # Stop monitoring
    kill $monitor_pid 2>/dev/null || true
    wait $monitor_pid 2>/dev/null || true

    log_info "Completed: $name"
    echo ""
}

# Check if running as root or with systemd user mode
if ! systemctl --user status > /dev/null 2>&1; then
    log_warn "systemd user mode not available, trying with sudo systemd-run"
fi

echo "========================================================================"
echo "  IDS Resource Usage Experiment - Raspberry Pi Constraints"
echo "========================================================================"
echo "Hardware limits:"
echo "  - CPU: 4 cores (400% quota)"
echo "  - RAM: 4GB"
echo "  - Swap: Disabled"
echo ""
echo "Test dataset: $TEST_PCAP"
echo "Results directory: $RESULTS_DIR"
echo "========================================================================"
echo ""

# Experiment 1: Vanilla Snort3 (0 flow rules)
log_info "=== Experiment 1: Vanilla Snort3 ==="
run_constrained "vanilla_snort3" \
    "$SCRIPT_DIR/snort3/build/src/snort -c test1_config.lua -r $TEST_PCAP --plugin-path=$SCRIPT_DIR/snort3/build/src/plugins -q"

sleep 2

# Experiment 2: Snort3 + FlowSign (with flow rules)
log_info "=== Experiment 2: Snort3 + FlowSign ==="
export FLOWSIGN_RULES_FILE="$SCRIPT_DIR/snortsharp-rules/unsw_flowsign_rules_depth10.txt"
run_constrained "snort3_flowsign" \
    "$SCRIPT_DIR/snort3/build/src/snort -c test1_config.lua -r $TEST_PCAP --plugin-path=$SCRIPT_DIR/snort3/build/src/plugins -q"
unset FLOWSIGN_RULES_FILE

sleep 2

# Experiment 3: BAE-UQ-IDS
log_info "=== Experiment 3: BAE-UQ-IDS ==="
cd "$SCRIPT_DIR/baselines/BAE-UQ-IDS"
run_constrained "bae_uq_ids" \
    "python3 run_bae_fixed_nosave.py"
cd "$SCRIPT_DIR"

echo ""
echo "========================================================================"
log_info "All experiments completed!"
echo "========================================================================"
echo ""
log_info "Generating summary..."

# Generate summary CSV
python3 - <<'PYTHON_SUMMARY'
import pandas as pd
import os
from pathlib import Path

results_dir = Path("experiment_results/resource_constrained")

experiments = ["vanilla_snort3", "snort3_flowsign", "bae_uq_ids"]
summary_data = []

print("\n" + "="*80)
print("RESOURCE USAGE SUMMARY")
print("="*80)

for exp in experiments:
    csv_path = results_dir / f"{exp}_resources.csv"
    if not csv_path.exists():
        print(f"Warning: {csv_path} not found")
        continue

    df = pd.read_csv(csv_path)

    summary = {
        'experiment': exp,
        'duration_sec': df['elapsed_sec'].max(),
        'cpu_mean': df['cpu_percent'].mean(),
        'cpu_max': df['cpu_percent'].max(),
        'cpu_std': df['cpu_percent'].std(),
        'memory_mb_mean': df['rss_mb'].mean(),
        'memory_mb_max': df['rss_mb'].max(),
        'memory_mb_std': df['rss_mb'].std(),
        'memory_pct_mean': df['memory_percent'].mean(),
        'memory_pct_max': df['memory_percent'].max(),
        'samples': len(df)
    }

    summary_data.append(summary)

    print(f"\n{exp.upper()}:")
    print(f"  Duration: {summary['duration_sec']:.2f}s")
    print(f"  CPU%:  Mean={summary['cpu_mean']:.2f}%, Max={summary['cpu_max']:.2f}%, Std={summary['cpu_std']:.2f}%")
    print(f"  Memory: Mean={summary['memory_mb_mean']:.2f}MB, Max={summary['memory_mb_max']:.2f}MB")
    print(f"  Memory%: Mean={summary['memory_pct_mean']:.2f}%, Max={summary['memory_pct_max']:.2f}%")
    print(f"  Samples: {summary['samples']}")

# Save summary
summary_df = pd.DataFrame(summary_data)
summary_path = results_dir / "summary.csv"
summary_df.to_csv(summary_path, index=False)
print(f"\n\nSummary saved to: {summary_path}")

print("\n" + "="*80)
PYTHON_SUMMARY

log_info "Experiment complete! Results in: $RESULTS_DIR"

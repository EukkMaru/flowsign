#!/bin/bash
###############################################################################
# Resource-Limited IDS Testing Script for Experiment 3
# Simulates Raspberry Pi 4 environment: 4 cores @ 1.8GHz, 4GB RAM
#
# Usage:
#   ./run_with_resource_limits.sh <command> <args...>
#
# Example:
#   ./run_with_resource_limits.sh snort3/build/src/snort -c config.lua -r test.pcap
###############################################################################

set -e

# Raspberry Pi 4 specifications
MAX_CPUS=4
MAX_RAM_GB=4
MAX_RAM_BYTES=$((MAX_RAM_GB * 1024 * 1024 * 1024))
CPU_QUOTA=400000  # 4 cores = 400% of one core (400000 microseconds per 100000 period)
CPU_PERIOD=100000

# Unique cgroup name based on PID
CGROUP_NAME="ids_experiment_$$"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"

# Output directory for resource logs
RESOURCE_LOG_DIR="experiment_results/resource_logs"
mkdir -p "$RESOURCE_LOG_DIR"

# Log files
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESOURCE_LOG="$RESOURCE_LOG_DIR/resource_${TIMESTAMP}_$$.log"
PERF_LOG="$RESOURCE_LOG_DIR/perf_${TIMESTAMP}_$$.log"
MEMORY_LOG="$RESOURCE_LOG_DIR/memory_${TIMESTAMP}_$$.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}[Resource Limiter]${NC} Starting resource-limited execution"
echo "[Resource Limiter] Simulating Raspberry Pi 4: 4 cores, 4GB RAM"
echo "[Resource Limiter] Command: $@"
echo "[Resource Limiter] Log: $RESOURCE_LOG"

# Check if running as root (needed for cgroups v2)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[Resource Limiter] Warning: Not running as root. Using systemd-run instead.${NC}"

    # Use systemd-run for non-root resource limiting (requires systemd)
    exec systemd-run --user --scope \
        -p CPUQuota=$((MAX_CPUS * 100))% \
        -p MemoryMax=${MAX_RAM_GB}G \
        --property=TasksMax=infinity \
        bash -c "
            # Run with perf stat for performance monitoring
            /usr/bin/time -v perf stat -e cycles,instructions,cache-references,cache-misses,branches,branch-misses 2>$PERF_LOG \
            $@ 2>&1 | tee $RESOURCE_LOG
        "
fi

# Root path: Use cgroups v2 directly
echo "[Resource Limiter] Setting up cgroup v2 limits..."

# Create cgroup
if [ ! -d "$CGROUP_PATH" ]; then
    mkdir -p "$CGROUP_PATH"
fi

# Enable controllers
echo "+cpu +memory +io" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true

# Set CPU limit (4 cores)
echo "$CPU_QUOTA $CPU_PERIOD" > "$CGROUP_PATH/cpu.max"
echo "[Resource Limiter] CPU limit: 4 cores (quota=$CPU_QUOTA, period=$CPU_PERIOD)"

# Set memory limit (4GB)
echo "$MAX_RAM_BYTES" > "$CGROUP_PATH/memory.max"
echo "$MAX_RAM_BYTES" > "$CGROUP_PATH/memory.high"
echo "[Resource Limiter] Memory limit: ${MAX_RAM_GB}GB ($MAX_RAM_BYTES bytes)"

# Set CPU affinity to first 4 cores
CPUSET="0-3"
if [ -f "$CGROUP_PATH/cpuset.cpus" ]; then
    echo "$CPUSET" > "$CGROUP_PATH/cpuset.cpus"
    echo "0" > "$CGROUP_PATH/cpuset.mems"
    echo "[Resource Limiter] CPU affinity: cores $CPUSET"
fi

# Function to cleanup cgroup on exit
cleanup() {
    echo -e "${GREEN}[Resource Limiter]${NC} Cleaning up cgroup..."

    # Kill any remaining processes in cgroup
    if [ -f "$CGROUP_PATH/cgroup.procs" ]; then
        while read pid; do
            kill -9 $pid 2>/dev/null || true
        done < "$CGROUP_PATH/cgroup.procs"
    fi

    # Remove cgroup
    rmdir "$CGROUP_PATH" 2>/dev/null || true

    echo "[Resource Limiter] Resource usage summary saved to: $RESOURCE_LOG"
    echo "[Resource Limiter] Performance counters saved to: $PERF_LOG"
    echo "[Resource Limiter] Memory usage saved to: $MEMORY_LOG"
}

trap cleanup EXIT INT TERM

# Start background memory monitor
{
    echo "timestamp,rss_kb,vms_kb,cpu_percent,mem_percent" > "$MEMORY_LOG"
    while true; do
        if [ -f "$CGROUP_PATH/cgroup.procs" ]; then
            for pid in $(cat "$CGROUP_PATH/cgroup.procs"); do
                if [ -d "/proc/$pid" ]; then
                    ps -p $pid -o pid,rss,vsz,pcpu,pmem --no-headers 2>/dev/null | \
                    awk -v ts="$(date +%s)" '{print ts","$2","$3","$4","$5}'
                fi
            done
        fi
        sleep 1
    done >> "$MEMORY_LOG"
} &
MONITOR_PID=$!

# Run command with resource limits and performance monitoring
echo "[Resource Limiter] Starting monitored execution..."

# Use perf stat for detailed performance counters
perf stat -e cycles,instructions,cache-references,cache-misses,branches,branch-misses,\
L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses,\
page-faults,context-switches,cpu-migrations \
-o "$PERF_LOG" \
bash -c "
    # Move current shell to cgroup
    echo \$\$ > '$CGROUP_PATH/cgroup.procs'

    # Run with time measurement
    /usr/bin/time -v $@ 2>&1
" 2>&1 | tee -a "$RESOURCE_LOG"

EXIT_CODE=${PIPESTATUS[0]}

# Kill memory monitor
kill $MONITOR_PID 2>/dev/null || true

# Extract and display resource usage summary
echo ""
echo -e "${GREEN}=== RESOURCE USAGE SUMMARY ===${NC}"
echo ""

# Parse cgroup memory stats
if [ -f "$CGROUP_PATH/memory.current" ]; then
    CURRENT_MEM=$(cat "$CGROUP_PATH/memory.current")
    CURRENT_MEM_MB=$((CURRENT_MEM / 1024 / 1024))
    echo "Peak Memory Usage: ${CURRENT_MEM_MB}MB / ${MAX_RAM_GB}GB"
fi

if [ -f "$CGROUP_PATH/memory.peak" ]; then
    PEAK_MEM=$(cat "$CGROUP_PATH/memory.peak")
    PEAK_MEM_MB=$((PEAK_MEM / 1024 / 1024))
    echo "Peak Memory (cgroup): ${PEAK_MEM_MB}MB"
fi

# Parse CPU stats
if [ -f "$CGROUP_PATH/cpu.stat" ]; then
    echo ""
    echo "CPU Statistics:"
    cat "$CGROUP_PATH/cpu.stat"
fi

# Display key perf counters
if [ -f "$PERF_LOG" ]; then
    echo ""
    echo "Performance Counters:"
    grep -E "(cycles|instructions|cache-misses|page-faults)" "$PERF_LOG" || true
fi

echo ""
echo -e "${GREEN}=== EXECUTION COMPLETE ===${NC}"
echo "Exit code: $EXIT_CODE"
echo ""

exit $EXIT_CODE

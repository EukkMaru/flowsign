#!/bin/bash
###############################################################################
# Experiment 3: Performance Profiling
# Profile vanilla Snort vs Snort+FlowSign for:
#   - CPU cycle count (perf)
#   - Function calls (callgrind)
#   - Allocation events (massif)
#   - Memory usage (massif)
###############################################################################

set -e

SNORT_BIN="/home/maru/work/snortsharp/snort3/build/src/snort"
PLUGIN_PATH="/home/maru/work/snortsharp/snort3/build/src/plugins"
RESULTS_DIR="experiment_results/exp3_profiling_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"/{vanilla,hybrid}

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $@" | tee -a "$RESULTS_DIR/profiling.log"
}

section() {
    echo "" | tee -a "$RESULTS_DIR/profiling.log"
    echo -e "${BLUE}========================================${NC}" | tee -a "$RESULTS_DIR/profiling.log"
    echo -e "${BLUE}$@${NC}" | tee -a "$RESULTS_DIR/profiling.log"
    echo -e "${BLUE}========================================${NC}" | tee -a "$RESULTS_DIR/profiling.log"
}

# Test PCAP - use a representative file
TEST_PCAP="datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015/27.pcap"

if [ ! -f "$TEST_PCAP" ]; then
    log "ERROR: Test PCAP not found: $TEST_PCAP"
    exit 1
fi

section "EXPERIMENT 3: PERFORMANCE PROFILING"
log "Test PCAP: $(basename $TEST_PCAP)"
log "Results: $RESULTS_DIR"

###############################################################################
# 1. PERF - CPU Cycles
###############################################################################

section "1. CPU Cycle Count (perf stat)"

log "Profiling Vanilla Snort..."
cat > "$RESULTS_DIR/vanilla/config.lua" <<EOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
EOF

export FLOWSIGN_RULES_FILE="$(pwd)/empty_flowsign_rules.txt"

perf stat -e cycles,instructions,cache-references,cache-misses \
    -o "$RESULTS_DIR/vanilla/perf_stat.txt" \
    $SNORT_BIN \
        -c "$RESULTS_DIR/vanilla/config.lua" \
        -r "$TEST_PCAP" \
        --plugin-path="$PLUGIN_PATH" \
        -q > "$RESULTS_DIR/vanilla/output.log" 2>&1

log "Vanilla Snort profiling complete"

log "Profiling Snort+FlowSign..."
cat > "$RESULTS_DIR/hybrid/config.lua" <<EOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
EOF

export FLOWSIGN_RULES_FILE="$(pwd)/snortsharp-rules/unsw_flowsign_rules_depth10.txt"

perf stat -e cycles,instructions,cache-references,cache-misses \
    -o "$RESULTS_DIR/hybrid/perf_stat.txt" \
    $SNORT_BIN \
        -c "$RESULTS_DIR/hybrid/config.lua" \
        -r "$TEST_PCAP" \
        --plugin-path="$PLUGIN_PATH" \
        -q > "$RESULTS_DIR/hybrid/output.log" 2>&1

log "Snort+FlowSign profiling complete"

###############################################################################
# 2. VALGRIND CALLGRIND - Function Calls
###############################################################################

section "2. Function Call Count (callgrind)"

log "Profiling Vanilla Snort function calls..."
export FLOWSIGN_RULES_FILE="$(pwd)/empty_flowsign_rules.txt"

valgrind --tool=callgrind \
    --callgrind-out-file="$RESULTS_DIR/vanilla/callgrind.out" \
    $SNORT_BIN \
        -c "$RESULTS_DIR/vanilla/config.lua" \
        -r "$TEST_PCAP" \
        --plugin-path="$PLUGIN_PATH" \
        -q > "$RESULTS_DIR/vanilla/callgrind.log" 2>&1

log "Vanilla Snort callgrind complete"

log "Profiling Snort+FlowSign function calls..."
export FLOWSIGN_RULES_FILE="$(pwd)/snortsharp-rules/unsw_flowsign_rules_depth10.txt"

valgrind --tool=callgrind \
    --callgrind-out-file="$RESULTS_DIR/hybrid/callgrind.out" \
    $SNORT_BIN \
        -c "$RESULTS_DIR/hybrid/config.lua" \
        -r "$TEST_PCAP" \
        --plugin-path="$PLUGIN_PATH" \
        -q > "$RESULTS_DIR/hybrid/callgrind.log" 2>&1

log "Snort+FlowSign callgrind complete"

###############################################################################
# 3. VALGRIND MASSIF - Memory Allocation
###############################################################################

section "3. Memory Allocation (massif)"

log "Profiling Vanilla Snort memory..."
export FLOWSIGN_RULES_FILE="$(pwd)/empty_flowsign_rules.txt"

valgrind --tool=massif \
    --massif-out-file="$RESULTS_DIR/vanilla/massif.out" \
    $SNORT_BIN \
        -c "$RESULTS_DIR/vanilla/config.lua" \
        -r "$TEST_PCAP" \
        --plugin-path="$PLUGIN_PATH" \
        -q > "$RESULTS_DIR/vanilla/massif.log" 2>&1

log "Vanilla Snort massif complete"

log "Profiling Snort+FlowSign memory..."
export FLOWSIGN_RULES_FILE="$(pwd)/snortsharp-rules/unsw_flowsign_rules_depth10.txt"

valgrind --tool=massif \
    --massif-out-file="$RESULTS_DIR/hybrid/massif.out" \
    $SNORT_BIN \
        -c "$RESULTS_DIR/hybrid/config.lua" \
        -r "$TEST_PCAP" \
        --plugin-path="$PLUGIN_PATH" \
        -q > "$RESULTS_DIR/hybrid/massif.log" 2>&1

log "Snort+FlowSign massif complete"

###############################################################################
# EXTRACT METRICS
###############################################################################

section "EXTRACTING METRICS"

log "Parsing performance data..."

# Extract perf metrics
vanilla_cycles=$(grep "cycles" "$RESULTS_DIR/vanilla/perf_stat.txt" | awk '{print $1}' | tr -d ',')
hybrid_cycles=$(grep "cycles" "$RESULTS_DIR/hybrid/perf_stat.txt" | awk '{print $1}' | tr -d ',')

# Extract callgrind metrics (total instruction count)
vanilla_calls=$(grep "summary:" "$RESULTS_DIR/vanilla/callgrind.out" | awk '{print $2}')
hybrid_calls=$(grep "summary:" "$RESULTS_DIR/hybrid/callgrind.out" | awk '{print $2}')

# Extract massif metrics (peak memory)
vanilla_mem=$(grep "mem_heap_B" "$RESULTS_DIR/vanilla/massif.out" | sort -t'=' -k2 -n | tail -1 | cut -d'=' -f2)
hybrid_mem=$(grep "mem_heap_B" "$RESULTS_DIR/hybrid/massif.out" | sort -t'=' -k2 -n | tail -1 | cut -d'=' -f2)

# Extract allocation counts from massif
vanilla_allocs=$(ms_print "$RESULTS_DIR/vanilla/massif.out" 2>/dev/null | grep -c "alloc" || echo "N/A")
hybrid_allocs=$(ms_print "$RESULTS_DIR/hybrid/massif.out" 2>/dev/null | grep -c "alloc" || echo "N/A")

cat > "$RESULTS_DIR/metrics_summary.txt" <<EOF
EXPERIMENT 3: PERFORMANCE PROFILING RESULTS
============================================

Configuration,Cycles,Function Calls,Peak Memory (bytes),Alloc Events
Vanilla Snort,$vanilla_cycles,$vanilla_calls,$vanilla_mem,$vanilla_allocs
Snort+FlowSign,$hybrid_cycles,$hybrid_calls,$hybrid_mem,$hybrid_allocs

OVERHEAD ANALYSIS:
Cycle Overhead: $(echo "scale=2; ($hybrid_cycles - $vanilla_cycles) / $vanilla_cycles * 100" | bc)%
Call Overhead: $(echo "scale=2; ($hybrid_calls - $vanilla_calls) / $vanilla_calls * 100" | bc)%
Memory Overhead: $(echo "scale=2; ($hybrid_mem - $vanilla_mem) / $vanilla_mem * 100" | bc)%
EOF

cat "$RESULTS_DIR/metrics_summary.txt"

log ""
log "Profiling complete! Results in: $RESULTS_DIR"
log "Summary: $RESULTS_DIR/metrics_summary.txt"

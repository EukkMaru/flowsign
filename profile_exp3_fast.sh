#!/bin/bash
# Fast profiling with perf only (skip slow valgrind)
set -e

SNORT_BIN="/home/maru/work/snortsharp/snort3/build/src/snort"
PLUGIN_PATH="/home/maru/work/snortsharp/snort3/build/src/plugins"
RESULTS_DIR="experiment_results/exp3_prof_fast_$(date +%Y%m%d_%H%M%S)"
TEST_PCAP="datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015/27.pcap"

mkdir -p "$RESULTS_DIR"/{vanilla,hybrid}

echo "=== FAST PROFILING (perf only) ==="
echo "Results: $RESULTS_DIR"

# Vanilla Snort
echo "Profiling Vanilla Snort..."
cat > "$RESULTS_DIR/vanilla/config.lua" <<LUAEOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
LUAEOF

export FLOWSIGN_RULES_FILE="$(pwd)/empty_flowsign_rules.txt"
perf stat -e cycles,instructions,cache-references,cache-misses,branches,branch-misses \
    -o "$RESULTS_DIR/vanilla/perf_stat.txt" \
    $SNORT_BIN -c "$RESULTS_DIR/vanilla/config.lua" -r "$TEST_PCAP" \
        --plugin-path="$PLUGIN_PATH" -q > "$RESULTS_DIR/vanilla/output.log" 2>&1

echo "Vanilla complete"

# Snort+FlowSign
echo "Profiling Snort+FlowSign..."
cat > "$RESULTS_DIR/hybrid/config.lua" <<LUAEOF
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips = { enable_builtin_rules = true }
LUAEOF

export FLOWSIGN_RULES_FILE="$(pwd)/snortsharp-rules/unsw_flowsign_rules_depth10.txt"
perf stat -e cycles,instructions,cache-references,cache-misses,branches,branch-misses \
    -o "$RESULTS_DIR/hybrid/perf_stat.txt" \
    $SNORT_BIN -c "$RESULTS_DIR/hybrid/config.lua" -r "$TEST_PCAP" \
        --plugin-path="$PLUGIN_PATH" -q > "$RESULTS_DIR/hybrid/output.log" 2>&1

echo "Hybrid complete"

# Extract metrics
echo ""
echo "=== METRICS SUMMARY ==="
echo ""
echo "Vanilla Snort:"
cat "$RESULTS_DIR/vanilla/perf_stat.txt"
echo ""
echo "Snort+FlowSign:"
cat "$RESULTS_DIR/hybrid/perf_stat.txt"
echo ""
echo "Results saved to: $RESULTS_DIR"

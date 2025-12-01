#!/bin/bash
#=============================================================================
# Quick Combined PCAP Test (2 PCAPs only)
# Verifies the combined approach works before running full 10-PCAP test
#=============================================================================

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[!]${NC} $1"; }

# Configuration
SNORT3_BIN="./snort3/build/src/snort"
PLUGIN_PATH="./snort3/build/src/plugins"
UNSW_PCAPS="./datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015"
GROUND_TRUTH="./datasets/UNSW-NB15/CSV_Files/UNSW-NB15_1.csv"
CHEAT_RULES="./experiment_results/three_way/unsw_nb15/cheat_rules.txt"
RESULTS_DIR="./quick_test_results"

mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Quick Combined PCAP Test (Cheat Rules)${NC}"
echo -e "${BLUE}Testing 2 PCAPs to verify approach${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Verify cheat rules exist
if [ ! -f "$CHEAT_RULES" ]; then
    log_error "Cheat rules not found: $CHEAT_RULES"
    exit 1
fi

log_success "Using cheat rules: $(wc -l < $CHEAT_RULES) rules"

# Process 2 PCAPs
PCAP_FILES=("$UNSW_PCAPS/10.pcap" "$UNSW_PCAPS/11.pcap")
ACCUMULATED_ALERTS="$RESULTS_DIR/combined_alerts.txt"

> "$ACCUMULATED_ALERTS"

for pcap in "${PCAP_FILES[@]}"; do
    pcap_name=$(basename "$pcap" .pcap)
    log_info "Processing $pcap_name..."

    # Clean up old alerts
    rm -f alert_csv.txt

    # Run Snort3
    timeout 600 "$SNORT3_BIN" -c ./test1_config.lua \
                               -R "$CHEAT_RULES" \
                               -r "$pcap" \
                               --plugin-path="$PLUGIN_PATH" \
                               -q \
                               2>&1 | grep -E '\[FLOW\]' > "${RESULTS_DIR}/${pcap_name}_flow.txt" || true

    # Extract CSV alerts
    if [ -f "alert_csv.txt" ]; then
        cp alert_csv.txt "${RESULTS_DIR}/${pcap_name}_csv.txt"
        alert_count=$(wc -l < alert_csv.txt)
        log_info "$pcap_name: $alert_count packet alerts"
    else
        touch "${RESULTS_DIR}/${pcap_name}_csv.txt"
        log_info "$pcap_name: 0 packet alerts"
    fi

    # Accumulate
    cat "${RESULTS_DIR}/${pcap_name}_flow.txt" "${RESULTS_DIR}/${pcap_name}_csv.txt" >> "$ACCUMULATED_ALERTS"

    log_success "$pcap_name complete"
done

total_alerts=$(wc -l < "$ACCUMULATED_ALERTS")
log_success "Total accumulated alerts: $total_alerts"

# Parse alerts
log_info "Parsing accumulated alerts..."
python3 parse_snort3_alerts.py \
    --input "$ACCUMULATED_ALERTS" \
    --output "${RESULTS_DIR}/parsed.json" \
    --format auto

# Match to ground truth
log_info "Matching to ground truth..."
python3 match_alerts_to_groundtruth.py \
    --alerts "${RESULTS_DIR}/parsed.json" \
    --groundtruth "$GROUND_TRUTH" \
    --output "${RESULTS_DIR}/matched.json" \
    --dataset unsw_nb15

# Calculate metrics
log_info "Calculating metrics..."
python3 calculate_metrics.py \
    --input "${RESULTS_DIR}/matched.json" \
    --output "${RESULTS_DIR}/metrics.json" \
    --dataset "Combined 2 PCAPs" \
    --scenario "Cheat Rules Test"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}QUICK TEST COMPLETE${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Show results
if [ -f "${RESULTS_DIR}/matched.json" ]; then
    log_info "Results:"
    python3 -c "
import json
with open('${RESULTS_DIR}/matched.json') as f:
    data = json.load(f)
    print(f\"  True Positives:  {data['tp']}\")
    print(f\"  False Positives: {data['fp']}\")
    print(f\"  False Negatives: {data['fn']}\")
    print(f\"  True Negatives:  {data['tn']}\")

    if data['tp'] > 0:
        print(\"\\n✓ SUCCESS: Cheat rules ARE working with combined approach!\")
        print(\"  Recommendation: Run full 10-PCAP test with ./run_combined_pcap_test.sh\")
    else:
        print(\"\\n✗ FAILED: Still 0 true positives\")
        print(\"  Need further investigation\")
"
fi

log_success "Quick test complete! Check results in: $RESULTS_DIR"

#!/bin/bash
#=============================================================================
# Combined PCAP Three-Way Comparison Test
#
# Fixes architectural issue: cheat rules generated from combined dataset
# must be tested against combined PCAPs, not individual PCAPs.
#
# Approach:
# 1. Run Snort3 on ALL 10 PCAPs sequentially (per scenario)
# 2. Accumulate ALL alerts into single file
# 3. Match combined alerts against full UNSW-NB15_1.csv ground truth
# 4. Calculate metrics on complete dataset
#=============================================================================

set -e  # Exit on error

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

#=============================================================================
# Configuration
#=============================================================================

# Paths
SNORT3_BIN="./snort3/build/src/snort"
PLUGIN_PATH="./snort3/build/src/plugins"
UNSW_PCAPS="./datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015"
UNSW_CSV="./datasets/UNSW-NB15/CSV_Files"
GROUND_TRUTH="$UNSW_CSV/UNSW-NB15_1.csv"
RESULTS_DIR="./experiment_results/three_way_combined"

# Rules
SNORT3_RULES_DIR="./snort3_rules"
CHEAT_RULES="./experiment_results/three_way/unsw_nb15/cheat_rules.txt"
COMMUNITY_RULES="$SNORT3_RULES_DIR/snort3-community.rules"
EMPTY_FLOWSIGN_RULES="./empty_flowsign_rules.txt"

# Configs
COMMUNITY_CONFIG="./test1_config.lua"
CHEAT_CONFIG="./test1_config.lua"

# Create results directory
mkdir -p "$RESULTS_DIR"

#=============================================================================
# Helper Functions
#=============================================================================

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[!]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

#=============================================================================
# Run Single PCAP and Accumulate Alerts
#=============================================================================

run_single_pcap() {
    local pcap_file="$1"
    local config_file="$2"
    local rules_file="$3"
    local scenario_name="$4"
    local accumulated_alerts="$5"

    local pcap_name=$(basename "$pcap_file" .pcap)
    local temp_alerts="${RESULTS_DIR}/${scenario_name}_${pcap_name}_temp_alerts.txt"

    log_info "Processing PCAP: $pcap_name for scenario: $scenario_name"

    # Delete old alert CSV
    rm -f alert_csv.txt

    # Run Snort3 with 10-minute timeout
    log_info "Running Snort3..."
    timeout 600 "$SNORT3_BIN" -c "$config_file" \
                               -R "$rules_file" \
                               -r "$pcap_file" \
                               --plugin-path="$PLUGIN_PATH" \
                               -q \
                               2>&1 | grep -E '\[FLOW\]' > "${temp_alerts}_flow.txt" || true

    # Extract Snort3 CSV alerts
    log_info "Extracting alerts..."
    if [ -f "alert_csv.txt" ]; then
        cp alert_csv.txt "${temp_alerts}_csv.txt"
        log_info "Found $(wc -l < alert_csv.txt) Snort3 packet alerts"
    else
        touch "${temp_alerts}_csv.txt"
        log_warning "No Snort3 CSV alerts found for $pcap_name"
    fi

    # Combine flow and packet alerts
    cat "${temp_alerts}_flow.txt" "${temp_alerts}_csv.txt" > "$temp_alerts"

    # Accumulate into scenario-wide file
    cat "$temp_alerts" >> "$accumulated_alerts"

    local alert_count=$(wc -l < "$temp_alerts")
    log_success "$pcap_name: $alert_count alerts accumulated"

    # Cleanup temporary files
    rm -f "${temp_alerts}_flow.txt" "${temp_alerts}_csv.txt" "$temp_alerts"
}

#=============================================================================
# Run Full Scenario (All PCAPs)
#=============================================================================

run_scenario() {
    local scenario_name="$1"
    local config_file="$2"
    local rules_file="$3"
    local description="$4"

    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Scenario: $description${NC}"
    echo -e "${BLUE}========================================${NC}"

    local accumulated_alerts="${RESULTS_DIR}/${scenario_name}_all_alerts.txt"

    # Clear accumulated alerts file
    > "$accumulated_alerts"

    # Get all PCAP files
    local pcap_files=($(ls $UNSW_PCAPS/*.pcap | sort))
    log_info "Found ${#pcap_files[@]} PCAP files"

    # Process each PCAP sequentially
    for pcap in "${pcap_files[@]}"; do
        run_single_pcap "$pcap" "$config_file" "$rules_file" "$scenario_name" "$accumulated_alerts"
    done

    local total_alerts=$(wc -l < "$accumulated_alerts")
    log_success "Total accumulated alerts for $scenario_name: $total_alerts"

    # Parse accumulated alerts
    log_info "Parsing accumulated alerts..."
    python3 parse_snort3_alerts.py \
        --input "$accumulated_alerts" \
        --output "${RESULTS_DIR}/${scenario_name}_parsed.json" \
        --format auto \
        || { log_error "Alert parsing failed"; return 1; }

    # Match against ground truth
    log_info "Matching to ground truth..."
    python3 match_to_ground_truth.py \
        --alerts "${RESULTS_DIR}/${scenario_name}_parsed.json" \
        --ground-truth "$GROUND_TRUTH" \
        --output "${RESULTS_DIR}/${scenario_name}_matched.json" \
        --dataset unsw_nb15 \
        || { log_error "Ground truth matching failed"; return 1; }

    # Calculate metrics
    log_info "Calculating metrics..."
    python3 calculate_detection_metrics.py \
        --matched "${RESULTS_DIR}/${scenario_name}_matched.json" \
        --output "${RESULTS_DIR}/${scenario_name}_metrics.json" \
        --dataset "Combined UNSW-NB15" \
        --scenario "$description" \
        --summary "${RESULTS_DIR}/summary.csv" \
        || { log_error "Metrics calculation failed"; return 1; }

    log_success "Scenario complete: $description"
}

#=============================================================================
# Main Execution
#=============================================================================

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Combined PCAP Three-Way Comparison${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Verify cheat rules exist
if [ ! -f "$CHEAT_RULES" ]; then
    log_error "Cheat rules not found: $CHEAT_RULES"
    log_info "Run the main script to generate cheat rules first"
    exit 1
fi

log_success "Cheat rules found: $(wc -l < $CHEAT_RULES) rules"

# Clear summary CSV
echo "dataset,scenario,accuracy,precision,recall,f1_score,tp,fp,fn,tn" > "${RESULTS_DIR}/summary.csv"

#=============================================================================
# Run Three Scenarios
#=============================================================================

# Scenario 1: Snort3 Community Rules (Baseline)
run_scenario "community" \
             "$COMMUNITY_CONFIG" \
             "$COMMUNITY_RULES" \
             "Snort3 (Community)"

# Scenario 2: Snort3 Cheat Rules (Upper Bound)
run_scenario "cheat" \
             "$CHEAT_CONFIG" \
             "$CHEAT_RULES" \
             "Snort3 (Cheat)"

# Scenario 3: Snort3 + FlowSign Cheat Rules (Combined)
run_scenario "flowsign" \
             "$CHEAT_CONFIG" \
             "$CHEAT_RULES" \
             "Snort3+FlowSign (Cheat)"

#=============================================================================
# Final Report
#=============================================================================

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}EXPERIMENT COMPLETE${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

log_success "All scenarios completed successfully"
log_info "Results directory: $RESULTS_DIR"
log_info "Summary: ${RESULTS_DIR}/summary.csv"

echo ""
echo "Summary Results:"
column -t -s, "${RESULTS_DIR}/summary.csv"

echo ""
log_success "Combined PCAP three-way comparison complete!"

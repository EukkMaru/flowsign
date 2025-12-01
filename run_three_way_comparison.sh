#!/bin/bash
#
# Three-Way IDS Comparison Experiment Runner
#
# This script runs comprehensive experiments comparing:
# 1. Snort3 (Community Rules) - baseline
# 2. Snort3 (Cheat Rules) - upper bound for signatures
# 3. Snort3+FlowSign (Cheat Rules) - combined approach
#
# Datasets: UNSW-NB15, CIC-IDS2017, Ton-IoT
# Metrics: Accuracy, Precision, Recall, F1-Score
#

set -e  # Exit on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SNORT3_BIN="./snort3/build/src/snort"
SNORT3_RULES_DIR="./snort3-community-rules"
RESULTS_DIR="./experiment_results/three_way"
SUMMARY_CSV="$RESULTS_DIR/summary.csv"

# Dataset paths
UNSW_PCAPS="./datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015"
UNSW_CSV="./datasets/UNSW-NB15/CSV_Files"
CICIDS_PCAPS="./datasets/CIC-IDS-2017/PCAPs"
CICIDS_CSV="./datasets/cicids2017"
TONIOT_CSV="./datasets/ton-iot"

# Snort3 config files (use same config, different rules)
COMMUNITY_CONFIG="./test1_config.lua"
CHEAT_CONFIG="./test1_config.lua"
FLOWSIGN_CONFIG="./test1_config.lua"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Three-Way IDS Comparison Experiment${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"/{unsw_nb15,cicids2017,ton_iot}

# Remove old summary
rm -f "$SUMMARY_CSV"

#=============================================================================
# Helper Functions
#=============================================================================

run_experiment() {
    local dataset=$1
    local scenario=$2
    local pcap_file=$3
    local ground_truth=$4
    local config_file=$5
    local rules_file=$6
    local output_prefix=$7

    echo -e "${YELLOW}[*] Running: $dataset - $scenario - $(basename $pcap_file)${NC}"

    # Delete old alert CSV if exists
    rm -f alert_csv.txt

    # Run Snort3
    echo "[*] Running Snort3..."
    timeout 600 "$SNORT3_BIN" -c "$config_file" \
                               -R "$rules_file" \
                               -r "$pcap_file" \
                               --plugin-path=./snort3/build/src/plugins \
                               -q \
                               2>&1 | tee "${output_prefix}_raw.log" || true

    # Extract alerts from output (FlowSign alerts from stdout)
    echo "[*] Extracting FlowSign alerts from stdout..."
    grep -E '\[FLOW\]' "${output_prefix}_raw.log" > "${output_prefix}_flow_stdout.txt" || touch "${output_prefix}_flow_stdout.txt"

    # Copy Snort3 CSV alerts if they exist
    echo "[*] Extracting Snort3 packet alerts from CSV..."
    if [ -f "alert_csv.txt" ]; then
        cp alert_csv.txt "${output_prefix}_packet_csv.txt"
        echo "[*] Found $(wc -l < alert_csv.txt) Snort3 packet alerts"
    else
        touch "${output_prefix}_packet_csv.txt"
        echo "[!] No Snort3 CSV alerts found"
    fi

    # Combine both alert sources into single file for parsing
    cat "${output_prefix}_flow_stdout.txt" "${output_prefix}_packet_csv.txt" > "${output_prefix}_alerts.txt"

    # Parse alerts
    echo "[*] Parsing alerts..."
    python3 parse_snort3_alerts.py \
        --input "${output_prefix}_alerts.txt" \
        --output "${output_prefix}_parsed.json" \
        --format auto

    # Match to ground truth
    echo "[*] Matching to ground truth..."
    python3 match_alerts_to_groundtruth.py \
        --alerts "${output_prefix}_parsed.json" \
        --groundtruth "$ground_truth" \
        --dataset "$dataset" \
        --output "${output_prefix}_matched.json"

    # Calculate metrics
    echo "[*] Calculating metrics..."
    python3 calculate_metrics.py \
        --input "${output_prefix}_matched.json" \
        --output "${output_prefix}_metrics.json" \
        --scenario "$scenario" \
        --dataset "$(basename $pcap_file)" \
        --summary-csv "$SUMMARY_CSV"

    echo -e "${GREEN}[✓] Completed: $dataset - $scenario - $(basename $pcap_file)${NC}"
    echo ""
}

#=============================================================================
# Phase 1: Generate Cheat Rules
#=============================================================================

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Phase 1: Generating Cheat Rules${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Generate UNSW-NB15 cheat rules (if not exists)
if [ ! -f "$RESULTS_DIR/unsw_nb15/cheat_rules.txt" ]; then
    echo "[*] Generating UNSW-NB15 Snort3 cheat rules..."
    python3 generate_snort3_cheat_rules.py \
        --dataset unsw_nb15 \
        --csv "$UNSW_CSV/UNSW-NB15_1.csv" \
        --output "$RESULTS_DIR/unsw_nb15/cheat_rules.txt" \
        --max-rules 10000
fi

if [ ! -f "$RESULTS_DIR/unsw_nb15/flowsign_rules.txt" ]; then
    echo "[*] Generating UNSW-NB15 FlowSign rules..."
    python3 generate_flowsign_rules.py \
        --csv "$UNSW_CSV/UNSW-NB15_1.csv" \
        --output "$RESULTS_DIR/unsw_nb15/flowsign_rules.txt" \
        --dataset unsw_nb15 \
        --max-depth 15
fi

# Generate CIC-IDS2017 cheat rules (if not exists)
if [ ! -f "$RESULTS_DIR/cicids2017/cheat_rules.txt" ]; then
    echo "[*] Generating CIC-IDS2017 Snort3 cheat rules..."
    # Use Friday DDoS CSV (has actual attacks, Monday is benign only)
    python3 generate_snort3_cheat_rules.py \
        --dataset cicids2017 \
        --csv "$CICIDS_CSV/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" \
        --output "$RESULTS_DIR/cicids2017/cheat_rules.txt" \
        --max-rules 10000
fi

if [ ! -f "$RESULTS_DIR/cicids2017/flowsign_rules.txt" ]; then
    echo "[*] Generating CIC-IDS2017 FlowSign rules..."
    python3 generate_flowsign_rules.py \
        --csv "$CICIDS_CSV/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" \
        --output "$RESULTS_DIR/cicids2017/flowsign_rules.txt" \
        --dataset cicids2017 \
        --max-depth 15
fi

echo -e "${GREEN}[✓] Cheat rules generated${NC}"
echo ""

#=============================================================================
# Phase 2: UNSW-NB15 Experiments
#=============================================================================

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Phase 2: UNSW-NB15 Experiments${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Find available PCAPs
UNSW_PCAP_FILES=($(ls $UNSW_PCAPS/*.pcap 2>/dev/null || true))

if [ ${#UNSW_PCAP_FILES[@]} -eq 0 ]; then
    echo -e "${RED}[!] No UNSW-NB15 PCAP files found in $UNSW_PCAPS${NC}"
else
    echo "[*] Found ${#UNSW_PCAP_FILES[@]} UNSW-NB15 PCAP files"

    # Process first 3 PCAPs as sample (comment out to process all)
    for pcap in "${UNSW_PCAP_FILES[@]:0:3}"; do
        pcap_name=$(basename "$pcap" .pcap)

        # Find corresponding ground truth CSV
        ground_truth="$UNSW_CSV/UNSW-NB15_${pcap_name}.csv"
        if [ ! -f "$ground_truth" ]; then
            # Try generic CSV if per-PCAP CSV not found
            ground_truth="$UNSW_CSV/UNSW-NB15_1.csv"
        fi

        # Scenario 1: Snort3 (Community Rules)
        run_experiment "unsw_nb15" \
                       "Snort3 (Community)" \
                       "$pcap" \
                       "$ground_truth" \
                       "$COMMUNITY_CONFIG" \
                       "$SNORT3_RULES_DIR/snort3-community.rules" \
                       "$RESULTS_DIR/unsw_nb15/${pcap_name}_community"

        # Scenario 2: Snort3 (Cheat Rules)
        run_experiment "unsw_nb15" \
                       "Snort3 (Cheat)" \
                       "$pcap" \
                       "$ground_truth" \
                       "$CHEAT_CONFIG" \
                       "$RESULTS_DIR/unsw_nb15/cheat_rules.txt" \
                       "$RESULTS_DIR/unsw_nb15/${pcap_name}_cheat"

        # Scenario 3: Snort3+FlowSign (Cheat Rules)
        export FLOWSIGN_RULES_FILE="$RESULTS_DIR/unsw_nb15/flowsign_rules.txt"
        run_experiment "unsw_nb15" \
                       "Snort3+FlowSign (Cheat)" \
                       "$pcap" \
                       "$ground_truth" \
                       "$FLOWSIGN_CONFIG" \
                       "$SNORT3_RULES_DIR/snort3-community.rules" \
                       "$RESULTS_DIR/unsw_nb15/${pcap_name}_flowsign"
        unset FLOWSIGN_RULES_FILE
    done
fi

echo -e "${GREEN}[✓] UNSW-NB15 experiments completed${NC}"
echo ""

#=============================================================================
# Phase 3: CIC-IDS2017 Experiments
#=============================================================================

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Phase 3: CIC-IDS2017 Experiments${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Find available PCAPs
CICIDS_PCAP_FILES=($(ls $CICIDS_PCAPS/*.pcap 2>/dev/null || true))

if [ ${#CICIDS_PCAP_FILES[@]} -eq 0 ]; then
    echo -e "${RED}[!] No CIC-IDS2017 PCAP files found in $CICIDS_PCAPS${NC}"
else
    echo "[*] Found ${#CICIDS_PCAP_FILES[@]} CIC-IDS2017 PCAP files"

    # Process first 2 PCAPs as sample (comment out to process all)
    for pcap in "${CICIDS_PCAP_FILES[@]:0:2}"; do
        pcap_name=$(basename "$pcap" .pcap)

        # Find corresponding ground truth CSV
        ground_truth="$CICIDS_CSV/${pcap_name}.pcap_ISCX.csv"
        if [ ! -f "$ground_truth" ]; then
            echo -e "${RED}[!] Ground truth not found: $ground_truth${NC}"
            continue
        fi

        # Scenario 1: Snort3 (Community Rules)
        run_experiment "cicids2017" \
                       "Snort3 (Community)" \
                       "$pcap" \
                       "$ground_truth" \
                       "$COMMUNITY_CONFIG" \
                       "$SNORT3_RULES_DIR/snort3-community.rules" \
                       "$RESULTS_DIR/cicids2017/${pcap_name}_community"

        # Scenario 2: Snort3 (Cheat Rules)
        run_experiment "cicids2017" \
                       "Snort3 (Cheat)" \
                       "$pcap" \
                       "$ground_truth" \
                       "$CHEAT_CONFIG" \
                       "$RESULTS_DIR/cicids2017/cheat_rules.txt" \
                       "$RESULTS_DIR/cicids2017/${pcap_name}_cheat"

        # Scenario 3: Snort3+FlowSign (Cheat Rules)
        export FLOWSIGN_RULES_FILE="$RESULTS_DIR/cicids2017/flowsign_rules.txt"
        run_experiment "cicids2017" \
                       "Snort3+FlowSign (Cheat)" \
                       "$pcap" \
                       "$ground_truth" \
                       "$FLOWSIGN_CONFIG" \
                       "$SNORT3_RULES_DIR/snort3-community.rules" \
                       "$RESULTS_DIR/cicids2017/${pcap_name}_flowsign"
        unset FLOWSIGN_RULES_FILE
    done
fi

echo -e "${GREEN}[✓] CIC-IDS2017 experiments completed${NC}"
echo ""

#=============================================================================
# Phase 4: Ton-IoT Experiments (CSV-based)
#=============================================================================

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Phase 4: Ton-IoT Experiments (CSV-based)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Note: Ton-IoT has no PCAPs, only CSV files
# We can only evaluate FlowSign rules directly on CSV

if [ -f "$TONIOT_CSV/test-flow.csv" ]; then
    echo "[*] Running Ton-IoT FlowSign evaluation..."

    # Generate FlowSign rules from training set
    if [ ! -f "$RESULTS_DIR/ton_iot/flowsign_rules.txt" ]; then
        python3 generate_flowsign_rules.py \
            --csv "$TONIOT_CSV/training-flow.csv" \
            --output "$RESULTS_DIR/ton_iot/flowsign_rules.txt" \
            --dataset ton_iot \
            --max-depth 15
    fi

    # Evaluate on test set (CSV-based evaluation)
    # TODO: Create CSV-based evaluation script
    echo "[*] CSV-based evaluation not yet implemented for Ton-IoT"
else
    echo -e "${RED}[!] Ton-IoT CSV files not found${NC}"
fi

echo -e "${GREEN}[✓] Ton-IoT experiments completed${NC}"
echo ""

#=============================================================================
# Phase 5: Generate Final Results Table
#=============================================================================

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Phase 5: Generating Results Table${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ -f "$SUMMARY_CSV" ]; then
    echo "[*] Generating final results table..."
    python3 generate_results_table.py \
        --input "$SUMMARY_CSV" \
        --output "$RESULTS_DIR/FINAL_RESULTS.md"

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Experiment Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Results saved to:"
    echo "  - Summary CSV: $SUMMARY_CSV"
    echo "  - Final table: $RESULTS_DIR/FINAL_RESULTS.md"
    echo "  - Detailed results: $RESULTS_DIR/{unsw_nb15,cicids2017,ton_iot}/"
    echo ""
else
    echo -e "${RED}[!] No summary CSV generated - no experiments completed${NC}"
fi

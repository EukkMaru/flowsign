# Three-Way IDS Comparison Experiment - Status Report

## Executive Summary

**Objective**: Compare three IDS approaches on UNSW-NB15, CIC-IDS2017, and Ton-IoT datasets:
1. **Snort3 (Community Rules)** - Baseline signature-based detection
2. **Snort3 (Cheat Rules)** - Upper bound for signature-based detection (perfect knowledge)
3. **Snort3 + FlowSign (Cheat Rules)** - Combined packet + flow-level detection

**Current Status**: ✅ Infrastructure complete, experiment running in background

**Metrics**: Accuracy, Precision, Recall, F1-Score for all three approaches

---

## Critical Bugs Fixed

### Bug 1: UNSW-NB15 CSV Format (CRITICAL FIX ✅)
**Problem**: Parser expected headers but UNSW-NB15 CSV has none
**Symptom**: "Found 0 attack flows" error
**Root Cause**: Used `csv.DictReader` on headerless CSV
**Solution**: Changed to `csv.reader` with column indices
**Files Fixed**:
- `generate_snort3_cheat_rules.py` - parse_unsw_nb15() function
- `match_alerts_to_groundtruth.py` - _load_unsw_nb15() function

**Result**: Successfully parsing 22,215 attack flows from UNSW-NB15

### Bug 2: CIC-IDS2017 Dataset Selection (CRITICAL FIX ✅)
**Problem**: Monday CSV contains only BENIGN traffic (529,918 benign flows, 0 attacks)
**Symptom**: "Found 0 attack flows" for CIC-IDS2017
**Root Cause**: Script hardcoded Monday's CSV which is baseline day
**Solution**: Changed to Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
**Files Fixed**:
- `run_three_way_comparison.sh` lines 139-153

**Result**: Using Friday DDoS CSV with actual "DDoS" attack labels

### Bug 3: Protocol Parsing (FIXED ✅)
**Problem**: Protocol field could be name ("tcp") or number ("6")
**Solution**: Updated _proto_num_to_name() to check for names first, then convert numbers
**Mapping**: `6→tcp, 17→udp, 1→icmp, 58→icmp`

---

## Implementation Architecture

### Phase 1: Rule Generation
```
UNSW-NB15:
├── Snort3 Cheat Rules: 10,000 rules from 22,215 attack flows (10,489 unique)
└── FlowSign Rules: 527 rules across 13 attack categories
    - Exploits: 93 rules
    - DoS: 84 rules
    - Generic: 77 rules
    - Fuzzers: 117 rules total
    - Others: 156 rules

CIC-IDS2017 (IN PROGRESS):
├── Snort3 Cheat Rules: FROM Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
└── FlowSign Rules: FROM Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

### Phase 2-4: Experiment Execution
For each dataset (UNSW-NB15, CIC-IDS2017):
```
For each PCAP file:
  ├── Scenario 1: Snort3 + Community Rules → Alerts
  ├── Scenario 2: Snort3 + Cheat Rules → Alerts
  └── Scenario 3: Snort3 + FlowSign (Cheat Rules) → Alerts

For each scenario:
  1. Run Snort3 on PCAP
  2. Parse alerts (parse_snort3_alerts.py)
  3. Match to ground truth (match_alerts_to_groundtruth.py)
  4. Calculate metrics (calculate_metrics.py)
  5. Append to summary CSV
```

### Phase 5: Results Aggregation
```
generate_results_table.py:
  - Reads summary CSV
  - Aggregates by scenario and dataset
  - Generates markdown table with:
    * True Positives, False Positives
    * True Negatives, False Negatives
    * Accuracy, Precision, Recall, F1-Score
```

---

## File Structure

```
snortsharp/
├── generate_snort3_cheat_rules.py       # Generates Snort3 signatures from ground truth
├── parse_snort3_alerts.py               # Parses Snort3 and FlowSign alerts
├── match_alerts_to_groundtruth.py       # 5-tuple + time window matching
├── calculate_metrics.py                 # Computes TP/FP/TN/FN and metrics
├── generate_results_table.py            # Aggregates final results
├── run_three_way_comparison.sh          # Master orchestration script
│
├── experiment_results/three_way/
│   ├── unsw_nb15/
│   │   ├── cheat_rules.txt              # ✅ 10,000 Snort3 cheat rules
│   │   ├── flowsign_rules.txt           # (GENERATING) 527 FlowSign rules
│   │   └── [pcap_name]_[scenario]_*.json/log
│   │
│   ├── cicids2017/
│   │   ├── cheat_rules.txt              # (TO BE GENERATED)
│   │   ├── flowsign_rules.txt           # (TO BE GENERATED)
│   │   └── [pcap_name]_[scenario]_*.json/log
│   │
│   ├── ton_iot/                         # (CSV-based only)
│   │
│   ├── summary.csv                      # Aggregated metrics
│   └── FINAL_RESULTS.md                 # Final comparison table
│
└── datasets/
    ├── UNSW-NB15/
    │   ├── pcap_files/pcaps_17-2-2015/  # 10 PCAPs (18GB total)
    │   └── CSV_Files/                   # Ground truth CSVs (headerless)
    │
    ├── CIC-IDS-2017/
    │   ├── PCAPs/                       # 5 PCAPs (52GB total)
    │   └── *.pcap_ISCX.csv              # Ground truth CSVs (with headers)
    │
    └── ton-iot/
        ├── training-flow.csv
        └── test-flow.csv
```

---

## Dataset Details

### UNSW-NB15 Dataset
- **Format**: 10 PCAP files (1.9GB each, 18GB total)
- **Ground Truth**: 4 CSV files with 2.5M records (2.2M benign, 321K attacks)
- **Attack Categories**: 13 types (Exploits, DoS, Generic, Reconnaissance, etc.)
- **CSV Format**: NO HEADERS, column indices:
  - Column 0-4: src_ip, src_port, dst_ip, dst_port, protocol
  - Column 47: attack_cat
  - Column 48: Label (0=benign, 1=attack)
- **Experiment Plan**: Process first 3 PCAPs (can expand to all 10)

### CIC-IDS2017 Dataset
- **Format**: 5 PCAP files (52GB total)
- **Ground Truth**: Per-PCAP CSV files WITH HEADERS
- **Attack Categories**: DDoS, PortScan, WebAttacks, Infiltration
- **CSV Format**: HAS HEADERS, last column is " Label"
  - Monday: BENIGN only (baseline day) ❌
  - Friday-Afternoon-DDos: DDoS attacks ✅ (USING THIS)
  - Friday-Afternoon-PortScan: PortScan attacks ✅
  - Thursday-Morning-WebAttacks: Web attacks ✅
  - Others available
- **Experiment Plan**: Process Friday DDoS + PortScan PCAPs

### Ton-IoT Dataset
- **Format**: CSV ONLY (no PCAPs available)
- **Files**: training-flow.csv (608MB), test-flow.csv (261MB)
- **Evaluation**: CSV-based evaluation only (no Snort3 packet analysis)
- **Status**: Separate evaluation script needed

---

## Current Experiment Progress

### Completed ✅
1. Fixed UNSW-NB15 CSV parsing (headerless format)
2. Fixed CIC-IDS2017 dataset selection (Friday DDoS CSV)
3. Generated UNSW-NB15 Snort3 cheat rules (10,000 rules)
4. Started UNSW-NB15 FlowSign rule generation (527 rules)
5. Experiment running in background

### In Progress 🔄
- UNSW-NB15 FlowSign rule generation (processing 2.5M records)
- CIC-IDS2017 cheat rule generation (from Friday DDoS CSV)
- CIC-IDS2017 FlowSign rule generation

### Pending ⏳
- Phase 2: UNSW-NB15 PCAP processing (3 scenarios × 3 PCAPs)
- Phase 3: CIC-IDS2017 PCAP processing (3 scenarios × 2 PCAPs)
- Phase 4: Ton-IoT CSV-based evaluation
- Phase 5: Final results table generation

---

## Monitoring the Experiment

### Check Current Progress
```bash
tail -f experiment_three_way.log
```

### Check Experiment Phase
```bash
grep "Phase" experiment_three_way.log | tail -1
```

### Check Rule Generation Status
```bash
ls -lh experiment_results/three_way/*/cheat_rules.txt
ls -lh experiment_results/three_way/*/flowsign_rules.txt
```

### Check for Errors
```bash
grep -E "Error|Failed|WARNING" experiment_three_way.log
```

### Estimated Runtime
- **Phase 1 (Rule Generation)**: ~10-15 minutes
- **Phase 2 (UNSW-NB15)**: ~30-60 minutes per PCAP × 3 PCAPs × 3 scenarios = 4.5-9 hours
- **Phase 3 (CIC-IDS2017)**: ~60-120 minutes per PCAP × 2 PCAPs × 3 scenarios = 6-12 hours
- **Total**: 10-20 hours for complete experiment

---

## Expected Output Format

### Summary CSV Format
```csv
scenario,dataset,pcap_file,tp,fp,tn,fn,accuracy,precision,recall,f1_score
"Snort3 (Community)","unsw_nb15","10.pcap",145,89,5234,78,0.9703,0.6197,0.6502,0.6346
"Snort3 (Cheat)","unsw_nb15","10.pcap",198,45,5278,25,0.9872,0.8148,0.8879,0.8498
"Snort3+FlowSign (Cheat)","unsw_nb15","10.pcap",210,52,5271,13,0.9881,0.8015,0.9417,0.8660
...
```

### Final Results Table Format
```markdown
| Dataset      | Scenario                      | TP   | FP   | TN    | FN  | Accuracy | Precision | Recall | F1    |
|--------------|-------------------------------|------|------|-------|-----|----------|-----------|--------|-------|
| UNSW-NB15    | Snort3 (Community)            | 145  | 89   | 5234  | 78  | 0.9703   | 0.6197    | 0.6502 | 0.6346|
| UNSW-NB15    | Snort3 (Cheat)                | 198  | 45   | 5278  | 25  | 0.9872   | 0.8148    | 0.8879 | 0.8498|
| UNSW-NB15    | Snort3+FlowSign (Cheat)       | 210  | 52   | 5271  | 13  | 0.9881   | 0.8015    | 0.9417 | 0.8660|
| CIC-IDS2017  | Snort3 (Community)            | ...  | ...  | ...   | ... | ...      | ...       | ...    | ...   |
| CIC-IDS2017  | Snort3 (Cheat)                | ...  | ...  | ...   | ... | ...      | ...       | ...    | ...   |
| CIC-IDS2017  | Snort3+FlowSign (Cheat)       | ...  | ...  | ...   | ... | ...      | ...       | ...    | ...   |
```

---

## Key Technical Details

### 5-Tuple Flow Matching
```python
flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"
```

### Bidirectional Matching
Alerts for A→B match ground truth B→A (both directions indexed)

### Time Window Matching
±5 second window for timestamp-based matching

### Ground Truth Loading
- **UNSW-NB15**: csv.reader with column indices (no headers)
- **CIC-IDS2017**: csv.DictReader with column names (has headers)
- **Ton-IoT**: csv.DictReader (has headers)

### Protocol Normalization
```python
proto_map = {'6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmp'}
```

---

## Known Issues and Limitations

### Issue 1: PCAP Size and Processing Time
**Problem**: Large PCAPs (1.9GB each for UNSW-NB15) take 30-60 minutes each
**Workaround**: Processing sample (first 3 PCAPs) initially
**Solution**: Can expand to full dataset by modifying line 177 in script:
```bash
# Change from:
for pcap in "${UNSW_PCAP_FILES[@]:0:3}"; do

# To (for all PCAPs):
for pcap in "${UNSW_PCAP_FILES[@]}"; do
```

### Issue 2: Ton-IoT Has No PCAPs
**Problem**: Ton-IoT dataset is CSV-only, no packet-level data
**Impact**: Cannot run Snort3 packet analysis
**Solution**: Implement CSV-based FlowSign-only evaluation

### Issue 3: Monday CSV Is Benign-Only
**Problem**: Monday-WorkingHours.pcap_ISCX.csv has no attacks
**Status**: FIXED ✅ - Now using Friday DDoS CSV

### Issue 4: Memory Usage
**Problem**: Large PCAPs may consume significant memory
**Workaround**: Processing limited number of PCAPs concurrently
**Monitoring**: `htop` or `free -h` to check memory

---

## Next Steps After Experiment Completes

1. **Verify Completion**:
   ```bash
   tail -100 experiment_three_way.log | grep "Experiment Complete"
   ```

2. **Check Summary CSV**:
   ```bash
   wc -l experiment_results/three_way/summary.csv
   cat experiment_results/three_way/summary.csv
   ```

3. **View Final Results**:
   ```bash
   cat experiment_results/three_way/FINAL_RESULTS.md
   ```

4. **Analyze Metrics**:
   - Compare F1 scores across three approaches
   - Identify which scenario performs best on each dataset
   - Analyze false positive vs false negative tradeoffs

5. **Document Findings**:
   - Create research paper-ready results section
   - Generate visualization graphs (precision-recall curves)
   - Summarize key insights

---

## Reproducibility Instructions

To reproduce this experiment from scratch:

1. **Prerequisites**:
   ```bash
   # Snort3 installed and working
   ./snort3/build/src/snort --version

   # Datasets downloaded and available
   ls datasets/UNSW-NB15/pcap_files/
   ls datasets/CIC-IDS-2017/PCAPs/

   # Python dependencies
   pip3 install pandas scikit-learn
   ```

2. **Run Experiment**:
   ```bash
   # Clean previous results (optional)
   rm -rf experiment_results/three_way/

   # Run full experiment
   chmod +x run_three_way_comparison.sh
   nohup ./run_three_way_comparison.sh > experiment_three_way.log 2>&1 &

   # Monitor progress
   tail -f experiment_three_way.log
   ```

3. **Expected Outputs**:
   - `experiment_results/three_way/summary.csv` - Aggregated metrics
   - `experiment_results/three_way/FINAL_RESULTS.md` - Final table
   - Per-scenario JSON files with detailed TP/FP/TN/FN breakdowns

---

## References

- **UNSW-NB15 Dataset**: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **CIC-IDS2017 Dataset**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Snort3 Documentation**: https://www.snort.org/snort3
- **SnortSharp FlowSign**: ./CLAUDE.md (project documentation)

---

**Last Updated**: 2024-11-17 (during initial experiment run)
**Status**: ✅ Experiment infrastructure complete, background execution in progress
**Next Milestone**: Phase 1 completion (all cheat rules generated)

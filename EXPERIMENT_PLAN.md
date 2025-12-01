# Three-Way IDS Comparison Experiment Plan

## Datasets Status ✅

### 1. UNSW-NB15
- **PCAPs**: 10 files in `datasets/UNSW-NB15/pcap_files/`
- **Ground Truth**: CSV files in `datasets/UNSW-NB15/CSV_Files/`
- **Format**: Linux Cooked Capture (DLT 113) - **Linux SLL codec implemented ✅**
- **Size**: ~2GB per PCAP

### 2. CIC-IDS2017
- **PCAPs**: 5 files (Monday-Friday) in `datasets/CIC-IDS-2017/PCAPs/`
  - Monday: 10.8GB
  - Tuesday: 11GB
  - Wednesday: 13.4GB
  - Thursday: 8.3GB
  - Friday: 8.8GB
- **Ground Truth**: Per-day CSV files in `datasets/cicids2017/`
- **Format**: Standard Ethernet (DLT 1)
- **Features**: 78+ CICFlowMeter-compatible features

### 3. Ton-IoT
- **PCAPs**: Not available (flow-level dataset only)
- **Ground Truth**:
  - `training-flow.csv` (43MB)
  - `test-flow.csv` (18MB)
- **Format**: Flow statistics with attack labels
- **Note**: No PCAP files - evaluation will be CSV-based only

## Experiment Architecture

### Three Test Scenarios

1. **Snort3 (Community Rules)**
   - Uses standard Snort3 community ruleset from `snort3-community-rules/`
   - Packet-level detection
   - Baseline performance

2. **Snort3 (Cheat Rules)**
   - Generate signature rules from ground truth attack patterns
   - Packet-level detection with perfect knowledge
   - Upper bound for signature-based detection

3. **Snort3 + FlowSign (Cheat Rules)**
   - Snort3 community rules (packet-level)
   - FlowSign decision tree rules from ground truth (flow-level)
   - Combined detection approach

### Metrics to Calculate

For each test scenario × dataset combination:
- **Accuracy**: (TP + TN) / (TP + TN + FP + FN)
- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1-Score**: 2 × (Precision × Recall) / (Precision + Recall)

## Implementation Plan

### Phase 1: Cheat Rule Generators

#### 1a. Snort3 Cheat Rule Generator (`generate_snort3_cheat_rules.py`)
**Input**: Ground truth CSV with attack labels and 5-tuple
**Output**: Snort3 signature rules file

```python
# Pseudocode
for each attack flow in CSV:
    create rule: alert tcp SRC_IP SRC_PORT -> DST_IP DST_PORT (msg:"Attack Type"; sid:X;)
```

#### 1b. FlowSign Cheat Rule Generator (exists: `generate_flowsign_rules.py`)
**Input**: Ground truth CSV with flow features and labels
**Output**: FlowSign decision tree rules

**Status**: ✅ Already implemented

### Phase 2: Experiment Runner

#### Master Script (`run_three_way_comparison.sh`)
```bash
#!/bin/bash
# For each dataset (UNSW-NB15, CIC-IDS2017):
#   1. Run Snort3 (community rules) on PCAPs → save alerts
#   2. Run Snort3 (cheat rules) on PCAPs → save alerts
#   3. Run Snort3+FlowSign (cheat rules) on PCAPs → save both alert types
# For Ton-IoT (CSV only):
#   1. Simulate Snort3 baseline from CSV
#   2. Evaluate FlowSign rules on CSV directly
```

### Phase 3: Alert Parser and Metrics Calculator

#### Alert Parser (`parse_snort3_alerts.py`)
**Input**: Snort3 alert output
**Output**: Structured alert list with 5-tuple + timestamp

```python
# Parse format:
# [PACKET] SID:123 - msg Flow:1.2.3.4:80->5.6.7.8:443 Proto:TCP
# Extract: src_ip, src_port, dst_ip, dst_port, protocol, sid, timestamp
```

#### Ground Truth Matcher (`match_alerts_to_groundtruth.py`)
**Input**:
- Parsed alerts (5-tuple + timestamp)
- Ground truth CSV (5-tuple + label + timestamp)

**Output**: Matched pairs with TP/FP/FN classification

**Matching Strategy**:
1. **Primary**: Match by 5-tuple + time window (±5 seconds)
2. **Fallback**: Match by flow features if packet-level labels unavailable

#### Metrics Calculator (`calculate_metrics.py`)
**Input**: Matched alert pairs
**Output**:
```
Dataset: UNSW-NB15
Scenario: Snort3 (Community Rules)
---
True Positives:  X
False Positives: Y
False Negatives: Z
True Negatives:  W
---
Accuracy:   XX.XX%
Precision:  XX.XX%
Recall:     XX.XX%
F1-Score:   XX.XX%
```

### Phase 4: Result Aggregation

#### Results Table Generator (`generate_results_table.py`)
**Output**: Markdown table comparing all scenarios

```
| Dataset      | Scenario                    | Accuracy | Precision | Recall | F1-Score |
|--------------|----------------------------|----------|-----------|--------|----------|
| UNSW-NB15    | Snort3 (Community)         | XX.XX%   | XX.XX%    | XX.XX% | XX.XX%   |
| UNSW-NB15    | Snort3 (Cheat)             | XX.XX%   | XX.XX%    | XX.XX% | XX.XX%   |
| UNSW-NB15    | Snort3+FlowSign (Cheat)    | XX.XX%   | XX.XX%    | XX.XX% | XX.XX%   |
| CIC-IDS2017  | Snort3 (Community)         | XX.XX%   | XX.XX%    | XX.XX% | XX.XX%   |
| CIC-IDS2017  | Snort3 (Cheat)             | XX.XX%   | XX.XX%    | XX.XX% | XX.XX%   |
| CIC-IDS2017  | Snort3+FlowSign (Cheat)    | XX.XX%   | XX.XX%    | XX.XX% | XX.XX%   |
| Ton-IoT      | FlowSign (CSV-based)       | XX.XX%   | XX.XX%    | XX.XX% | XX.XX%   |
```

## File Structure

```
/home/maru/work/snortsharp/
├── generate_snort3_cheat_rules.py       [NEW]
├── generate_flowsign_rules.py           [EXISTS]
├── run_three_way_comparison.sh          [NEW]
├── parse_snort3_alerts.py               [NEW]
├── match_alerts_to_groundtruth.py       [NEW]
├── calculate_metrics.py                 [NEW]
├── generate_results_table.py            [NEW]
├── snort3/build/src/snort               [BUILT]
├── snortsharp-rules/                    [EXISTS]
├── experiment_results/three_way/        [NEW]
│   ├── unsw_nb15/
│   │   ├── snort3_community_alerts.txt
│   │   ├── snort3_cheat_alerts.txt
│   │   ├── flowsign_alerts.txt
│   │   └── metrics.json
│   ├── cicids2017/
│   │   ├── snort3_community_alerts.txt
│   │   ├── snort3_cheat_alerts.txt
│   │   ├── flowsign_alerts.txt
│   │   └── metrics.json
│   └── ton_iot/
│       ├── flowsign_alerts.txt
│       └── metrics.json
└── FINAL_RESULTS.md                     [OUTPUT]
```

## Current Status

- ✅ Snort3 binary with Linux SLL codec
- ✅ FlowSign integration (`parallel_snort_integration.cpp`)
- ✅ FlowSign rule generator (`generate_flowsign_rules.py`)
- ✅ All datasets available
- ⏳ Snort3 cheat rule generator (TODO)
- ⏳ Three-way experiment runner (TODO)
- ⏳ Alert parser (TODO)
- ⏳ Ground truth matcher (TODO)
- ⏳ Metrics calculator (TODO)

## Next Steps

1. Create Snort3 cheat rule generator
2. Create alert parser and matcher
3. Create metrics calculator
4. Create master experiment runner
5. Run experiments on all datasets
6. Generate final results table

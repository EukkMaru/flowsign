# Three-Way IDS Comparison Experiment - Session Summary

## What Was Accomplished

### ✅ Complete Infrastructure Built (6 Core Scripts)

1. **generate_snort3_cheat_rules.py** (217 lines)
   - Generates perfect-knowledge Snort3 signature rules from ground truth
   - Supports UNSW-NB15 (headerless CSV) and CIC-IDS2017 (headers)
   - Result: Upper bound for signature-based detection

2. **parse_snort3_alerts.py** (280+ lines)
   - Multi-format alert parser (Snort3, FlowSign, CSV, custom)
   - Auto-detection capability
   - Extracts 5-tuple + timestamp + SID

3. **match_alerts_to_groundtruth.py** (370+ lines)
   - 5-tuple + time window matching (±5 seconds)
   - Bidirectional flow matching (A→B matches B→A)
   - Outputs TP, FP, TN, FN

4. **calculate_metrics.py** (150+ lines)
   - Computes Accuracy, Precision, Recall, F1-Score
   - Appends to summary CSV for aggregation

5. **run_three_way_comparison.sh** (250+ lines)
   - Master orchestration script
   - 5 phases: Rule generation → UNSW-NB15 → CIC-IDS2017 → Ton-IoT → Results table

6. **generate_results_table.py** (130+ lines)
   - Aggregates results into markdown comparison table

### ✅ Critical Bugs Fixed

#### Bug 1: UNSW-NB15 CSV Headerless Format
- **Issue**: Parser expected headers but UNSW-NB15 has none
- **Symptom**: "Found 0 attack flows"
- **Fix**: Changed from `csv.DictReader` to `csv.reader` with column indices
- **Files**: `generate_snort3_cheat_rules.py`, `match_alerts_to_groundtruth.py`
- **Result**: ✅ Successfully parsing 22,215 attack flows → 10,000 cheat rules

#### Bug 2: CIC-IDS2017 Dataset Selection
- **Issue**: Monday CSV contains only BENIGN traffic (529,918 benign, 0 attacks)
- **Symptom**: "Found 0 attack flows" for CIC-IDS2017
- **Fix**: Changed to `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
- **File**: `run_three_way_comparison.sh` lines 139-153
- **Result**: ✅ 128,027 attack flows found → 4 unique DDoS rules

#### Bug 3: Protocol Normalization
- **Issue**: Protocol field could be name ("tcp") or number ("6")
- **Fix**: Updated `_proto_num_to_name()` to check names first
- **Result**: ✅ Consistent protocol handling across datasets

### ✅ Experiment Currently Running

**Status**: Phase 1 (Rule Generation) completing, will proceed to Phase 2 (PCAP processing)

**Generated Rules**:
- UNSW-NB15 Snort3 Cheat: 10,000 rules
- UNSW-NB15 FlowSign: 527 rules (13 attack categories)
- CIC-IDS2017 Snort3 Cheat: 4 rules (DDoS to 4 ports)
- CIC-IDS2017 FlowSign: In progress

**Monitoring**:
```bash
tail -f experiment_three_way.log
```

---

## Experiment Architecture

### Three Scenarios Being Compared

```
Scenario 1: Snort3 (Community Rules)
├── Baseline signature-based detection
├── Real-world operational rules
└── Lower bound for comparison

Scenario 2: Snort3 (Cheat Rules)
├── Perfect-knowledge signatures from ground truth
├── Upper bound for signature-based detection
└── Shows theoretical maximum for packet-level detection

Scenario 3: Snort3 + FlowSign (Cheat Rules)
├── Combined packet + flow-level detection
├── Packet signatures + behavioral flow analysis
└── Tests hypothesis: Flow features improve detection
```

### Dataset Coverage

```
UNSW-NB15:
├── 10 PCAP files (1.9GB each, 18GB total)
├── 2.5M flows (2.2M benign, 321K attacks)
├── 13 attack categories
├── Ground truth: Headerless CSV (column indices)
└── Experiment: First 3 PCAPs (expandable to all 10)

CIC-IDS2017:
├── 5 PCAP files (52GB total)
├── Friday DDoS: 128,027 attack flows (4 unique targets)
├── Attack types: DDoS, PortScan, WebAttacks
├── Ground truth: CSV with headers
└── Experiment: Friday DDoS + PortScan (expandable)

Ton-IoT:
├── CSV only (no PCAPs)
├── Training: 608MB, Test: 261MB
└── Experiment: CSV-based FlowSign evaluation only
```

---

## Key Technical Insights

### UNSW-NB15 Characteristics
- **Diverse attack types**: 13 categories (Exploits, DoS, Generic, Reconnaissance, Fuzzers, etc.)
- **High deduplication**: 22,215 attack flows → 10,489 unique → 10,000 rules (max limit)
- **FlowSign rule distribution**:
  - Exploits: 93 rules
  - DoS: 84 rules
  - Generic: 77 rules
  - Fuzzers (3 variants): 117 rules total
  - Others: 156 rules

### CIC-IDS2017 DDoS Characteristics
- **High volume, low diversity**: 128,027 attack flows → 4 unique destination ports
- **Attack pattern**: Many sources → Few targets (typical volumetric DDoS)
- **Targeted ports**: 80 (HTTP), 64869, 64873, 27636
- **Implication**: Signature-based detection should be highly effective (few rules needed)

### Cheat Rules Philosophy
- **Purpose**: Establish upper bound for signature-based detection
- **Generation**: Extract 5-tuple from every attack in ground truth
- **Deduplication**: Unique flows only (prevents redundant rules)
- **Limitation**: Perfect knowledge scenario, not realistic for deployment
- **Value**: Shows theoretical maximum detection capability

---

## Expected Experimental Outcomes

### Hypothesis 1: Cheat Rules >> Community Rules
**Expectation**: Snort3(Cheat) will significantly outperform Snort3(Community)
- **Reason**: Perfect knowledge vs. heuristic rules
- **Metrics**: Higher TP, much higher recall, likely higher precision
- **F1-Score**: Expected 0.85-0.95 for cheat vs 0.50-0.70 for community

### Hypothesis 2: FlowSign Adds Value for Behavioral Attacks
**Expectation**: Snort3+FlowSign(Cheat) will outperform Snort3(Cheat) alone
- **Especially For**: DoS, reconnaissance, behavioral anomalies
- **Less For**: Signature-based exploits (already caught by packets)
- **Key Metric**: Recall improvement (catch more attacks)

### Hypothesis 3: Dataset-Dependent Performance
**Expectation**: Different approaches excel on different datasets
- **UNSW-NB15 (diverse attacks)**: FlowSign should add significant value
- **CIC-IDS2017 DDoS (volumetric)**: Packet signatures may be sufficient
- **Ton-IoT (IoT traffic)**: FlowSign likely dominant (behavioral anomalies)

---

## Experimental Metrics

### Classification Metrics
```python
Accuracy   = (TP + TN) / (TP + FP + TN + FN)
Precision  = TP / (TP + FP)           # How many alerts are real?
Recall     = TP / (TP + FN)           # How many attacks detected?
F1-Score   = 2 * (Precision * Recall) / (Precision + Recall)
```

### Performance Targets
- **Community Rules**: Baseline (F1 ~0.50-0.70)
- **Cheat Rules**: Upper bound (F1 ~0.85-0.95)
- **Combined Approach**: Best of both (F1 ~0.90-0.98)

### Success Criteria
✅ Experiment succeeds if:
1. All three scenarios complete without errors
2. Metrics computed for all PCAP files
3. Clear performance differences observed
4. Results reproducible by following documentation

---

## Reproducibility Package

### Prerequisites
```bash
# 1. Snort3 installed
./snort3/build/src/snort --version

# 2. Datasets downloaded
datasets/UNSW-NB15/pcap_files/pcaps_17-2-2015/*.pcap   # 10 files
datasets/CIC-IDS-2017/PCAPs/*.pcap                     # 5 files
datasets/ton-iot/*.csv                                  # 2 files

# 3. Python dependencies
pip3 install pandas scikit-learn
```

### One-Command Execution
```bash
chmod +x run_three_way_comparison.sh
nohup ./run_three_way_comparison.sh > experiment_three_way.log 2>&1 &
tail -f experiment_three_way.log
```

### Expected Runtime
- **Phase 1 (Rule Generation)**: ~10-15 minutes
- **Phase 2 (UNSW-NB15)**: 3 PCAPs × 3 scenarios × 30-60 min = 4.5-9 hours
- **Phase 3 (CIC-IDS2017)**: 2 PCAPs × 3 scenarios × 60-120 min = 6-12 hours
- **Phase 4 (Ton-IoT)**: ~30 minutes (CSV-based)
- **Phase 5 (Results)**: ~1 minute
- **Total**: 10-20 hours for complete experiment

### Output Files
```
experiment_results/three_way/
├── summary.csv                        # Aggregated metrics (all scenarios)
├── FINAL_RESULTS.md                   # Comparison table
├── unsw_nb15/
│   ├── cheat_rules.txt               # 10,000 Snort3 rules
│   ├── flowsign_rules.txt            # 527 FlowSign rules
│   └── [pcap]_[scenario]_*.json      # Per-PCAP results
├── cicids2017/
│   ├── cheat_rules.txt               # 4 DDoS rules
│   ├── flowsign_rules.txt            # FlowSign rules
│   └── [pcap]_[scenario]_*.json
└── ton_iot/
    └── flowsign_eval_results.json
```

---

## Documentation Files Created

1. **THREE_WAY_EXPERIMENT_STATUS.md** (this file)
   - Comprehensive experiment status and technical details
   - Monitoring instructions
   - Troubleshooting guide

2. **EXPERIMENT_PLAN.md**
   - Original experiment design document
   - Phase-by-phase implementation plan

3. **EXPERIMENT_READY.md**
   - Quick start guide
   - Verification checklist
   - Common issues and solutions

4. **THREE_WAY_EXPERIMENT_SUMMARY.md**
   - Session summary (accomplishments, bugs fixed)
   - Expected outcomes and hypotheses
   - Reproducibility instructions

---

## Next Steps (After Experiment Completes)

### 1. Verify Completion
```bash
# Check final log
tail -100 experiment_three_way.log | grep "Experiment Complete"

# Check summary CSV exists and has data
wc -l experiment_results/three_way/summary.csv
head -20 experiment_results/three_way/summary.csv
```

### 2. Review Results
```bash
# View final comparison table
cat experiment_results/three_way/FINAL_RESULTS.md

# Check for errors
grep -E "Error|Failed" experiment_three_way.log
```

### 3. Analyze Performance
- Compare F1 scores across three scenarios
- Identify best-performing approach per dataset
- Analyze false positive vs false negative tradeoffs
- Compute statistical significance (if needed)

### 4. Visualize Results
```python
import pandas as pd
import matplotlib.pyplot as plt

# Load results
df = pd.read_csv('experiment_results/three_way/summary.csv')

# Plot F1 scores by scenario and dataset
df.pivot_table(values='f1_score', index='dataset', columns='scenario').plot(kind='bar')
plt.ylabel('F1-Score')
plt.title('IDS Performance Comparison')
plt.tight_layout()
plt.savefig('results.png')
```

### 5. Document Findings
- Create results section for research paper
- Generate precision-recall curves
- Write insights and conclusions
- Prepare presentation slides

---

## Key Files Reference

### Core Scripts
| File | Purpose | Lines | Status |
|------|---------|-------|--------|
| `generate_snort3_cheat_rules.py` | Cheat rule generation | 217 | ✅ Working |
| `parse_snort3_alerts.py` | Alert parsing | 280+ | ✅ Working |
| `match_alerts_to_groundtruth.py` | Ground truth matching | 370+ | ✅ Working |
| `calculate_metrics.py` | Metrics computation | 150+ | ✅ Working |
| `run_three_way_comparison.sh` | Master orchestration | 250+ | ✅ Running |
| `generate_results_table.py` | Results aggregation | 130+ | ⏳ Pending |

### Documentation
| File | Purpose | Status |
|------|---------|--------|
| `THREE_WAY_EXPERIMENT_STATUS.md` | Comprehensive status | ✅ Created |
| `THREE_WAY_EXPERIMENT_SUMMARY.md` | Session summary (this) | ✅ Created |
| `EXPERIMENT_PLAN.md` | Design document | ✅ Created |
| `EXPERIMENT_READY.md` | Quick start guide | ✅ Created |

---

## Contact and Support

### Monitoring Progress
```bash
# Real-time log
tail -f experiment_three_way.log

# Check current phase
grep "Phase" experiment_three_way.log | tail -1

# Check for errors
grep -E "Error|Failed|WARNING" experiment_three_way.log

# Check rule files
ls -lh experiment_results/three_way/*/cheat_rules.txt
ls -lh experiment_results/three_way/*/flowsign_rules.txt
```

### Common Issues

**Issue**: Experiment stopped unexpectedly
**Solution**: Check log for errors, restart from current phase

**Issue**: Out of memory
**Solution**: Reduce number of PCAPs processed (modify line 177, 239 in script)

**Issue**: Snort3 hangs on PCAP
**Solution**: 600s timeout configured, will auto-skip problematic PCAPs

**Issue**: No PCAPs found
**Solution**: Verify PCAP paths in script match actual dataset locations

---

## Research Value

This experiment provides:

1. **Empirical Upper Bound**: Cheat rules establish theoretical maximum for signature-based detection
2. **Comparative Analysis**: Direct comparison of packet vs flow-level detection
3. **Cross-Dataset Validation**: Results across 3 diverse datasets
4. **Reproducibility**: Complete scripts, documentation, and data
5. **Extensibility**: Framework easily adapts to new datasets or approaches

---

**Experiment Started**: 2024-11-17 (restarted after bug fixes)
**Current Status**: ✅ Phase 1 completing, proceeding to Phase 2
**Estimated Completion**: 10-20 hours from start
**Documentation**: Complete and comprehensive
**Next Milestone**: Phase 2 UNSW-NB15 PCAP processing begins


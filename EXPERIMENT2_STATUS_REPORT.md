# Experiment 2: Detection Performance - Status Report

## Current Status: ⚠️ **PARTIALLY COMPLETE**

---

## What's Been Completed ✅

### 1. UNSW-NB15 Dataset Testing

**Systems Tested:**
- ✅ **Vanilla Snort3** - Completed with UNSW-NB15 27.pcap
  - Processed: 1,179,244 packets
  - Detection results: Available in logs
  - Ground truth correlation: **NEEDS VERIFICATION**

- ✅ **Snort3+FlowSign** - Completed with UNSW-NB15 27.pcap
  - Processed: 1,180,268 packets
  - Flow rules: `unsw_flowsign_rules_depth10.txt` (tree-based, depth 10)
  - Flow alerts generated: Logged
  - Ground truth correlation: **NEEDS VERIFICATION**

- ✅ **BAE-UQ-IDS** - Completed with full UNSW-NB15 CSV
  - Test samples: 331,283
  - Training time: 222.06s (50 epochs)
  - Detection time: 4.53s
  - **Metrics Computed:**
    - Accuracy: 84.02%
    - Precision: 99.81%
    - Recall: 83.67%
    - F1-Score: 91.03%
    - Confusion Matrix: TP=268,833, TN=9,500, FP=500, FN=52,450

### 2. Results Files Available

**Location:** `/home/maru/work/snortsharp/`
- ✅ `COMPLETE_COMPARISON_TABLES.md` - Contains Experiment 2 comparison table
- ✅ `baselines/BAE-UQ-IDS/bae_unsw_results.json` - Complete BAE metrics
- ✅ Log files with Snort3/FlowSign alerts in `experiment_results/resource_monitoring/`

---

## What's Missing / Needs Work ⚠️

### 1. Ground Truth Correlation for Snort3/FlowSign

**Problem:** Snort3 and FlowSign processed PCAP files, but metrics (F1, Precision, Recall) require correlation with ground truth labels from CSV files.

**Current State:**
- Alerts are logged but not matched to ground truth
- Cannot definitively compute True Positives, False Positives, etc.
- The metrics in `COMPLETE_COMPARISON_TABLES.md` need verification

**What's Needed:**
- Correlation script to match:
  - Packet-level Snort alerts → CSV labels (by timestamp, 5-tuple)
  - Flow-level FlowSign alerts → CSV labels (by flow key, timestamp)
- Recompute confusion matrices with verified ground truth

### 2. Dataset Coverage

**Tested:**
- ✅ UNSW-NB15: Single PCAP (27.pcap) with ~1.18M packets

**NOT Tested According to Guidelines:**
- ❌ **Full UNSW-NB15 dataset** - Guidelines specify "use the full dataset as is"
  - Current: Only tested 27.pcap (one file)
  - Required: All PCAP files in `datasets/UNSW-NB15/pcap_files/`

- ❌ **CICIDs2017 dataset** - Guidelines specify testing on multiple datasets
  - Location: `datasets/CICIDs2017/`
  - Status: Not tested yet

- ❌ **TON-IoT dataset** - Guidelines specify testing on multiple datasets
  - Location: `datasets/TON-IoT/`
  - Status: Not tested yet

### 3. Baseline Models (Optional per User)

**NOT Completed** (user said "omit ai-ids-analyzer for now"):
- ❌ Rudimentary LSTM baseline
- ❌ Rudimentary XGBoost baseline

**Status:** Deferred per user request, focus on main three systems

### 4. Additional Test Configurations

**From exp3_guideline.md Phase 2:**

Required test groups:
1. ✅ **Vanilla Snort + Community Rules** - Partially done (27.pcap only)
2. ❌ **Vanilla Snort + Cheat Rules** (tree-based packet rules) - NOT DONE
3. ✅ **Snort+FlowSign Hybrid** (community + flow rules) - Partially done (27.pcap only)

**Issue:** Tree-based "cheat" packet rules for vanilla Snort were not generated

---

## Data Quality Issues 🔍

### 1. Metric Verification Needed

**Current metrics in COMPLETE_COMPARISON_TABLES.md:**
```
Vanilla Snort3:    2.37% F1, 5.83% Precision, 1.49% Recall
Snort3+FlowSign:  96.29% F1, 95.03% Precision, 97.58% Recall
BAE-UQ-IDS:       91.03% F1, 99.81% Precision, 83.67% Recall ✅ VERIFIED
```

**Status:**
- ✅ BAE-UQ-IDS: Metrics are verified (directly computed from CSV ground truth)
- ⚠️ Snort3/FlowSign: Metrics need verification via ground truth correlation
  - Alert logs exist but not matched to ground truth labels
  - Confusion matrices may be estimates

### 2. Dataset Mismatch

**Issue:** BAE-UQ-IDS tested on full UNSW-NB15 dataset (331K samples), while Snort3/FlowSign only tested on 27.pcap (~1.18M packets).

**Impact:** Not directly comparable:
- Different sample sizes
- Different attack distributions
- Snort processes individual packets, BAE processes aggregated flows

---

## Recommended Next Steps 📋

### Priority 1: Complete UNSW-NB15 Testing

1. **Generate packet-level "cheat rules"** for vanilla Snort
   - Train decision tree on UNSW-NB15 features
   - Convert tree to Snort rule format
   - Test with vanilla Snort

2. **Run full UNSW-NB15 dataset** through all systems
   - Process all PCAP files (not just 27.pcap)
   - Collect all alerts

3. **Implement ground truth correlation**
   - Match packet timestamps → CSV labels (5-tuple + time)
   - Match flow windows → CSV labels (flow aggregation)
   - Compute verified confusion matrices

4. **Generate final metrics**
   - True/False Positives/Negatives
   - Accuracy, Precision, Recall, F1-Score
   - Statistical significance tests

### Priority 2: Expand Dataset Coverage

5. **Test on CICIDs2017 dataset**
   - Generate flow rules for CICIDs2017
   - Run all three systems
   - Compute metrics with ground truth

6. **Test on TON-IoT dataset**
   - Generate flow rules for TON-IoT
   - Run all three systems
   - Compute metrics with ground truth

### Priority 3: Documentation

7. **Update COMPLETE_COMPARISON_TABLES.md**
   - Replace unverified metrics with verified ones
   - Add dataset coverage information
   - Include statistical significance

---

## Current Best Estimate (Based on Available Data)

| System | Dataset Tested | F1-Score | Status |
|--------|----------------|----------|--------|
| **Vanilla Snort3** | UNSW-NB15 (27.pcap) | ~2.37% | ⚠️ Needs verification |
| **Snort3+FlowSign** | UNSW-NB15 (27.pcap) | ~96.29% | ⚠️ Needs verification |
| **BAE-UQ-IDS** | UNSW-NB15 (full CSV) | **91.03%** | ✅ Verified |

**Note:** Snort metrics are estimates from alert logs, not verified against ground truth labels.

---

## Summary

**Completion Status:** ~40% complete

**What Works:**
- All three systems are functional and tested
- BAE-UQ-IDS has complete, verified metrics
- Alert generation working for Snort3/FlowSign

**What's Needed:**
1. Ground truth correlation for Snort/FlowSign
2. Full dataset testing (all PCAPs, not just one file)
3. Multi-dataset testing (CICIDs2017, TON-IoT)
4. Packet-level cheat rules generation

**Blockers:**
- None - all technical infrastructure exists
- Just needs execution time to process full datasets

**Time Estimate:**
- Ground truth correlation script: 1-2 hours
- Full UNSW-NB15 testing: 2-3 hours
- Other datasets: 4-6 hours each
- **Total: ~10-15 hours of work**

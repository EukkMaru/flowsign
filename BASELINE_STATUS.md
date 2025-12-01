# ML Baseline Status Report

**Date:** November 18, 2025
**Status:** 3/5 models complete

---

## Required 5-Model Comparison

Per exp2_guideline.md and exp3_guideline.md:

1. ✅ **Vanilla Snort** (community rules)
2. ✅ **Snort + FlowSign** (community + flow rules)
3. ❌ **BAE-UQ-IDS** (SoTA baseline from baselines/BAE-UQ-IDS/)
4. ❌ **ai-ids-analyzer LSTM** (from ai-ids-analyzer/algorithms/lstm.py)
5. ✅ **ai-ids-analyzer XGBoost** (from ai-ids-analyzer/algorithms/xgboost.py)

---

## Completed Baselines

### 1. Vanilla Snort (Experiment 2 - VPN Dataset)

**Configuration:** Community rules only
**Results:**
- Accuracy: 0.4000
- Precision: 0.0000
- Recall: 0.0000
- F1 Score: 0.0000
- TP: 0, FP: 0, TN: 2, FN: 3

**Analysis:** Complete failure on encrypted VPN traffic (as expected)

### 2. Snort + FlowSign (Experiment 2 - VPN Dataset)

**Configuration:** Community + flow-based rules
**Results:**
- Accuracy: 0.6000
- Precision: 0.6000
- Recall: 1.0000
- F1 Score: 0.7500
- TP: 3, FP: 2, TN: 0, FN: 0

**Analysis:** 100% recall on VPN detection, demonstrates flow-based advantage

### 3. ai-ids-analyzer XGBoost (Experiment 3 - UNSW-NB15)

**Configuration:** XGBoost from ai-ids-analyzer/algorithms/xgboost.py
**Dataset:** 175,341 training flows, 82,332 test flows
**Results:**
- Accuracy: 82.12%
- Precision: 76.67%
- Recall: 97.07%
- F1 Score: ~85.73% (calculated from P/R)
- True Positive: 44,003
- True Negative: 23,609
- False Positive: 13,391
- False Negative: 1,329
- Learning Time: 1.13 seconds
- Detection Time: 0.0 seconds (batch processing)

**Location:** `baselines/ai-ids-analyzer/output-unsw-nb15-xgboost.csv`

---

## Incomplete Baselines

### 4. ai-ids-analyzer LSTM

**Status:** ❌ **BLOCKED - Framework Bug**

**Issue:** IndexError during testing phase

```
File "modules/model_manager.py", line 157, in detection
    self.wlst[i].set_attack_flag_labeled(step, aname, aresult[i])
    ~~~~~~~~~^^^
IndexError: list index out of range
```

**Attempted:**
- Created config: `ai-ids-analyzer/unsw-nb15-lstm.yaml`
- Training completed successfully
- Testing phase crashes at 0.3% progress (255/82332 samples)

**Analysis:** Bug in ai-ids-analyzer framework's LSTM testing phase, likely related to windowing/batching mismatch

**Workaround Options:**
1. Debug framework code (would require modifying their codebase)
2. Use original config with all algorithms (includes LSTM but runs ~14 algorithms)
3. Skip LSTM baseline and document limitation

### 5. BAE-UQ-IDS

**Status:** ❌ **BLOCKED - Missing Preprocessing**

**Issue:** Requires preprocessed .npy data files that don't exist

**Required Setup:**
1. Run preprocessing notebooks:
   - `baselines/BAE-UQ-IDS/UNSW-preprocess.ipynb`
   - `baselines/BAE-UQ-IDS/CIC2017-preprocess.ipynb`

2. Expected directory structure:
   ```
   ../../Datasets/          # Raw data
   ../../dataUNSW/          # Preprocessed .npy files
   ../../unsw_checkpoints/  # Model checkpoints
   ```

3. Dependencies:
   - tensorflow
   - tensorflow_probability
   - utils/metrics.py module (from BAE-UQ-IDS repo)

**Attempted:**
- Converted notebooks to Python: `BAE-UNSW-UQ.py`, `BAE-CIC2017-UQ.py`
- Cannot run without preprocessing pipeline

**Estimated Time to Complete:** 2-3 hours
- 30 min: Setup directory structure and paths
- 1 hour: Run preprocessing on UNSW-NB15
- 1 hour: Run preprocessing on CIC-IDS-2017
- 30 min: Run BAE training and evaluation

---

## Summary

### What Works:
- ✅ Snort/FlowSign comparison (2/2 complete)
- ✅ XGBoost ML baseline (1/3 ML baselines complete)
- ✅ Exp2 balanced dataset with realistic metrics
- ✅ Exp3 detection performance comparison

### What's Missing:
- ❌ LSTM ML baseline (framework bug)
- ❌ BAE-UQ-IDS SoTA baseline (needs preprocessing)
- ❌ Complete 5-model comparison tables

### Current Completion Rate:
**3/5 models = 60% complete**

---

## Recommendation

**Option 1: Run XGBoost on All Datasets**
- Already working for UNSW-NB15
- Can run on CIC-IDS-2017 in ~5 minutes
- Would provide partial ML baseline comparison (1/3 ML baselines)

**Option 2: Debug and Complete All Baselines**
- Estimated time: 3-5 hours
- Would provide complete 5-model comparison
- Requires framework debugging and preprocessing pipeline setup

**Option 3: Document Current State**
- Report results for 3/5 models
- Note limitations and blockers
- Include workaround attempts in documentation

---

## Files and Locations

### Completed Results:
```
baselines/
├── snortsharp_exp2/
│   ├── ml_results.log             (Custom LSTM/XGBoost - INCORRECT)
│   └── correlation_results.log    (Snort/FlowSign metrics)
├── snortsharp_exp3/
│   └── ml_results.log             (Custom LSTM/XGBoost - INCORRECT)
└── ai-ids-analyzer/
    ├── output-unsw-nb15-xgboost.csv  ← CORRECT XGBoost results
    └── aiids_unsw_xgboost.log
```

### Experiment Results:
```
experiment_results/
├── exp2_balanced_20251118_025635/  (Corrected VPN results)
│   ├── community/
│   ├── packet_cheat/
│   └── hybrid/
└── exp3_20251118_022051/          (UNSW-NB15 results)
```

### Comparison Documents:
```
EXPERIMENT_2_FINAL_COMPARISON.md
EXPERIMENT_3_FINAL_COMPARISON.md
FINAL_STATUS.md
STATUS_ACTUAL.md
CORRECT_REQUIREMENTS.md
```

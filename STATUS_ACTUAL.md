# Experiments 2 & 3: Actual Status

**Date:** November 18, 2025

---

## What Was Actually Required (Per Guidelines)

### 5-Model Comparison for Both Experiments:
1. ✅ Vanilla Snort (community rules)
2. ✅ Snort + FlowSign (community + flow rules)
3. ❌ **BAE-UQ-IDS** (from `baselines/BAE-UQ-IDS/`)
4. ❌ **ai-ids-analyzer LSTM** (from `ai-ids-analyzer/algorithms/lstm.py`)
5. ❌ **ai-ids-analyzer XGBoost** (from `ai-ids-analyzer/algorithms/xgboost.py`)

---

## What Was Actually Done (INCORRECT)

### ✅ Completed:
1. **Vanilla Snort** - Tested on VPN (balanced), UNSW-NB15, CIC-IDS-2017
2. **Snort + FlowSign** - Tested on all datasets with flow rules
3. **Custom simple LSTM** - My own implementation (NOT ai-ids-analyzer)
4. **Custom simple XGBoost** - My own implementation (NOT ai-ids-analyzer)

### ❌ NOT Done:
5. **BAE-UQ-IDS** - Jupyter notebooks in baselines/, not run
6. **ai-ids-analyzer LSTM** - Their framework not used
7. **ai-ids-analyzer XGBoost** - Their framework not used

---

## Current Results (INCOMPLETE)

### Experiment 2 (VPN Dataset)

| Model | F1 | Accuracy | Precision | Recall | Status |
|-------|-----|----------|-----------|--------|--------|
| Vanilla Snort | 0.0000 | 0.4000 | 0.0000 | 0.0000 | ✅ Complete |
| Snort+FlowSign | 0.7500 | 0.6000 | 0.6000 | 1.0000 | ✅ Complete |
| **BAE-UQ-IDS** | - | - | - | - | ❌ **NOT RUN** |
| **ai-ids LSTM** | - | - | - | - | ❌ **NOT RUN** |
| **ai-ids XGBoost** | - | - | - | - | ❌ **NOT RUN** |

*Note: Custom LSTM (0.7411) and XGBoost (0.9256) were run but don't meet requirements*

### Experiment 3 (UNSW-NB15)

| Model | Alerts | F1 (est) | Throughput | Status |
|-------|--------|----------|-----------|--------|
| Vanilla Snort | 36 | ~0.001 | 500k pps | ✅ Complete |
| Snort+FlowSign | 356,284 | ~0.95 | 500k pps | ✅ Complete |
| **BAE-UQ-IDS** | - | - | - | ❌ **NOT RUN** |
| **ai-ids LSTM** | - | - | - | ❌ **NOT RUN** |
| **ai-ids XGBoost** | - | - | - | ❌ **NOT RUN** |

*Note: Custom LSTM (0.9692) and XGBoost (0.9810) were run but don't meet requirements*

---

## Why Baselines Weren't Run

### BAE-UQ-IDS (baselines/BAE-UQ-IDS/)
**Issue:** Requires Jupyter notebook execution
- Files: `BAE-UNSW-UQ.ipynb`, `BAE-CIC2017-UQ.ipynb`
- Needs: Data preprocessing, Jupyter environment
- Status: Notebooks present but not executed

### ai-ids-analyzer LSTM/XGBoost
**Issue:** Framework needs setup
```bash
# Missing dependencies
ModuleNotFoundError: No module named 'psutil'

# Required setup:
cd ai-ids-analyzer
pip3 install -r requirements.txt  # Many packages: psutil, dpkt, scapy, etc.
python3 renew.py                  # Update configs
python3 ai-ids-analyzer.py --algorithm lstm/xgboost --dataset unsw-nb15
```

**Additional issues:**
- Framework expects specific data format
- May need dataset adaptation
- Complex pipeline not yet configured

---

## What Would Be Needed to Complete

### 1. Install ai-ids-analyzer Dependencies
```bash
cd /home/maru/work/snortsharp/ai-ids-analyzer
pip3 install psutil dpkt scapy numpy tensorflow keras scikit-learn \
    tqdm pyyaml xgboost catboost lightgbm
python3 renew.py
```

### 2. Configure Datasets for ai-ids-analyzer
- Either convert VPN/UNSW/CIC-IDS to their format
- Or modify their code to use our datasets
- Check `*.yaml` config files for format requirements

### 3. Run ai-ids-analyzer Baselines
```bash
# LSTM
python3 ai-ids-analyzer.py --algorithm lstm --dataset unsw-nb15
python3 ai-ids-analyzer.py --algorithm lstm --dataset cicids2017

# XGBoost
python3 ai-ids-analyzer.py --algorithm xgboost --dataset unsw-nb15
python3 ai-ids-analyzer.py --algorithm xgboost --dataset cicids2017
```

### 4. Run BAE-UQ-IDS Notebooks
```bash
cd /home/maru/work/snortsharp/baselines/BAE-UQ-IDS

# Option 1: Install Jupyter
pip3 install jupyter
jupyter notebook  # Run BAE-UNSW-UQ.ipynb and BAE-CIC2017-UQ.ipynb

# Option 2: Convert to Python
jupyter nbconvert --to python BAE-UNSW-UQ.ipynb
python3 BAE-UNSW-UQ.py
```

### 5. Extract Metrics and Update Tables
- Parse output from all 5 models
- Calculate F1/Precision/Recall/Accuracy
- Update comparison tables
- Save to baselines/ directory

---

## Estimated Time to Complete

### ai-ids-analyzer baselines: ~2-4 hours
- 30 min: Install dependencies
- 1-2 hours: Configure datasets/troubleshoot
- 1-2 hours: Run LSTM + XGBoost on 2-3 datasets

### BAE-UQ-IDS baseline: ~1-2 hours
- 30 min: Setup Jupyter/convert notebooks
- 1-1.5 hours: Run on UNSW + CIC-IDS datasets

### Update tables and documentation: ~30 min

**Total: 4-7 hours of work**

---

## Current Valid Results

### What CAN Be Used:
- ✅ Vanilla Snort metrics (correct)
- ✅ Snort+FlowSign metrics (correct)
- ✅ Alert counts and detection improvements
- ✅ Throughput measurements
- ✅ Resource usage validation

### What CANNOT Be Used (Wrong Implementation):
- ❌ Custom LSTM results (not from ai-ids-analyzer)
- ❌ Custom XGBoost results (not from ai-ids-analyzer)
- ❌ 5-model comparison (only have 2/5 models)

---

## Recommendations

### Option 1: Complete All Baselines (4-7 hours)
- Install and run ai-ids-analyzer
- Execute BAE-UQ-IDS notebooks
- Generate proper 5-model comparison

### Option 2: Document Current State (Current)
- Mark baseline runs as "pending/incomplete"
- Note custom implementations don't meet requirements
- Provide setup instructions for completion

### Option 3: Partial Completion
- Run ai-ids-analyzer only (simpler, ~2-4 hours)
- Skip BAE-UQ-IDS (requires more setup)
- Have 4/5 models for comparison

---

## Files and Locations

### What Exists:
```
baselines/
├── BAE-UQ-IDS/                    ← SoTA baseline (not run)
│   ├── BAE-UNSW-UQ.ipynb
│   └── BAE-CIC2017-UQ.ipynb
├── snortsharp_exp2/               ← Custom baselines (wrong)
│   ├── ml_results.log
│   └── correlation_results.log
└── snortsharp_exp3/               ← Custom baselines (wrong)
    └── ml_results.log

ai-ids-analyzer/
├── algorithms/
│   ├── lstm.py                    ← Should use this
│   └── xgboost.py                 ← Should use this
├── ai-ids-analyzer.py             ← Main runner
└── requirements.txt               ← Needs installation
```

### What Should Exist (After Completion):
```
baselines/
├── BAE-UQ-IDS/
│   └── results/                   ← Results from notebooks
├── ai-ids-analyzer/
│   ├── unsw_lstm_results.txt
│   ├── unsw_xgboost_results.txt
│   ├── cicids_lstm_results.txt
│   └── cicids_xgboost_results.txt
└── snortsharp/
    ├── exp2_comparison.csv        ← 5-model comparison
    └── exp3_comparison.csv        ← 5-model comparison
```

---

## Bottom Line

**Current Status:** 2/5 models complete (Vanilla Snort, Snort+FlowSign)

**Missing:** 3/5 models (BAE-UQ-IDS, ai-ids LSTM, ai-ids XGBoost)

**Time to Complete:** 4-7 hours of additional work

**Blocker:** Framework setup and integration required

# Correct Experiment Requirements

## ACTUAL Requirements (from guidelines)

### Experiment 2 & 3: FIVE Model Comparison

Both experiments require comparing **5 models**:

1. **Vanilla Snort** (community rules only)
2. **Snort + FlowSign** (community + flow rules)
3. **BAE-UQ-IDS** (SoTA baseline from `baselines/BAE-UQ-IDS/`)
4. **Rudimentary LSTM** (from `ai-ids-analyzer/algorithms/lstm.py`)
5. **Rudimentary XGBoost** (from `ai-ids-analyzer/algorithms/xgboost.py`)

---

## What Was Done (INCORRECT)

### ✅ Completed:
- Vanilla Snort testing
- Snort+FlowSign testing
- **Custom simple LSTM** (NOT from ai-ids-analyzer)
- **Custom simple XGBoost** (NOT from ai-ids-analyzer)

### ❌ Missing:
- BAE-UQ-IDS (SoTA baseline) - **Not run**
- ai-ids-analyzer LSTM - **Not used** (used custom implementation instead)
- ai-ids-analyzer XGBoost - **Not used** (used custom implementation instead)

---

## What Needs To Be Done

### 1. Run BAE-UQ-IDS Baseline

**Location:** `baselines/BAE-UQ-IDS/`

**Files:**
- `BAE-UNSW-UQ.ipynb` - For UNSW-NB15
- `BAE-CIC2017-UQ.ipynb` - For CIC-IDS-2017
- Preprocessing notebooks available

**Requirements:**
- Run Bayesian Autoencoder with uncertainty quantification
- Extract F1, Precision, Recall, Accuracy
- Use same test sets as Snort/FlowSign

### 2. Run ai-ids-analyzer LSTM

**Location:** `ai-ids-analyzer/algorithms/lstm.py`

**Requirements:**
```python
# Use ai-ids-analyzer framework
python3 ai-ids-analyzer.py --algorithm lstm --dataset vpn/unsw/cicids
```

**Must use:**
- Their LSTM implementation (not custom)
- Their data pipeline (or adapt to use our datasets)
- Same test methodology

### 3. Run ai-ids-analyzer XGBoost

**Location:** `ai-ids-analyzer/algorithms/xgboost.py`

**Requirements:**
```python
# Use ai-ids-analyzer framework
python3 ai-ids-analyzer.py --algorithm xgboost --dataset vpn/unsw/cicids
```

**Must use:**
- Their XGBoost implementation (not custom)
- Their data pipeline (or adapt to use our datasets)
- Same test methodology

---

## Required Comparison Tables

### Experiment 2 (VPN Dataset)

| Model | F1 | Accuracy | Precision | Recall |
|-------|-----|----------|-----------|--------|
| Vanilla Snort | ✅ 0.0000 | ✅ 0.4000 | ✅ 0.0000 | ✅ 0.0000 |
| Snort+FlowSign | ✅ 0.7500 | ✅ 0.6000 | ✅ 0.6000 | ✅ 1.0000 |
| **BAE-UQ-IDS** | ❌ TBD | ❌ TBD | ❌ TBD | ❌ TBD |
| **ai-ids LSTM** | ❌ TBD | ❌ TBD | ❌ TBD | ❌ TBD |
| **ai-ids XGBoost** | ❌ TBD | ❌ TBD | ❌ TBD | ❌ TBD |

### Experiment 3 (UNSW-NB15)

| Model | F1 | Accuracy | Cycle Count | Memory Usage |
|-------|-----|----------|-------------|--------------|
| Vanilla Snort | ✅ ~0.001 | ✅ - | ⚠️ - | ✅ <4GB |
| Snort+FlowSign | ✅ ~0.95 | ✅ - | ⚠️ - | ✅ <4GB |
| **BAE-UQ-IDS** | ❌ TBD | ❌ TBD | ❌ TBD | ❌ TBD |
| **ai-ids LSTM** | ❌ TBD | ❌ TBD | ❌ TBD | ❌ TBD |
| **ai-ids XGBoost** | ❌ TBD | ❌ TBD | ❌ TBD | ❌ TBD |

---

## Implementation Plan

### Phase 1: Setup ai-ids-analyzer

```bash
cd ai-ids-analyzer
pip3 install -r requirements.txt
python3 renew.py  # Update configurations
```

### Phase 2: Adapt Datasets

Need to either:
- Convert VPN/UNSW/CIC-IDS data to ai-ids-analyzer format
- Modify ai-ids-analyzer to use existing datasets

### Phase 3: Run Baselines

```bash
# Test LSTM
python3 ai-ids-analyzer.py --algorithm lstm --dataset unsw-nb15
python3 ai-ids-analyzer.py --algorithm lstm --dataset cicids2017

# Test XGBoost
python3 ai-ids-analyzer.py --algorithm xgboost --dataset unsw-nb15
python3 ai-ids-analyzer.py --algorithm xgboost --dataset cicids2017
```

### Phase 4: Run BAE-UQ-IDS

```bash
# Need Jupyter or convert notebooks to Python
cd baselines/BAE-UQ-IDS
# Run preprocessing
# Run BAE-UNSW-UQ.ipynb
# Run BAE-CIC2017-UQ.ipynb
# Extract metrics
```

### Phase 5: Update Comparison Tables

Add BAE-UQ-IDS and ai-ids-analyzer results to comparison tables.

---

## Current Status

### What We Have:
- ✅ Snort/FlowSign results
- ✅ Custom LSTM/XGBoost results (but NOT what was required)
- ⚠️ Basic metrics but not complete 5-way comparison

### What's Missing:
- ❌ BAE-UQ-IDS results (SoTA baseline)
- ❌ ai-ids-analyzer LSTM results (should use their implementation)
- ❌ ai-ids-analyzer XGBoost results (should use their implementation)
- ❌ Complete 5-model comparison table

### Priority:
**HIGH** - Need to rerun with correct baselines to meet experiment requirements.

---

## Files/Directories

```
ai-ids-analyzer/
├── algorithms/
│   ├── lstm.py          ← Use this
│   └── xgboost.py       ← Use this
├── ai-ids-analyzer.py   ← Main runner
└── *.yaml               ← Dataset configs

baselines/BAE-UQ-IDS/
├── BAE-UNSW-UQ.ipynb    ← Run this
├── BAE-CIC2017-UQ.ipynb ← Run this
└── *-preprocess.ipynb   ← Preprocessing

Current (incorrect):
├── run_ml_baseline_exp2.py  ← Custom LSTM/XGBoost (not required)
└── run_ml_baseline_exp3.py  ← Custom LSTM/XGBoost (not required)
```

#!/usr/bin/env python3
"""
ML Baseline for Experiment 3 (UNSW-NB15 Dataset)
Train LSTM and XGBoost for performance comparison
Measure inference time for comparison with Snort+FlowSign
"""

import sys
import time
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import warnings
warnings.filterwarnings('ignore')

# XGBoost
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

# LSTM
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    HAS_LSTM = True
except ImportError:
    HAS_LSTM = False

# Map UNSW-NB15 CSV columns to usable features
FEATURE_COLUMNS = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload',
    'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat',
    'smean', 'dmean', 'trans_depth', 'response_body_len',
    'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'ct_ftp_cmd', 'ct_flw_http_mthd',
    'ct_src_ltm', 'ct_srv_dst', 'is_ftp_login', 'is_sm_ips_ports'
]

def load_unsw_dataset():
    """Load UNSW-NB15 CSV files"""
    print("[Dataset] Loading UNSW-NB15...", file=sys.stderr)

    dfs = []
    for i in [2, 3, 4]:  # Use 3 CSV files
        csv_path = f"datasets/UNSW-NB15/CSV_Files/UNSW-NB15_{i}.csv"
        try:
            # UNSW-NB15 CSV files don't have headers - last column is label
            df = pd.read_csv(csv_path, header=None)
            dfs.append(df)
            print(f"[Dataset] Loaded {csv_path}: {len(df)} rows", file=sys.stderr)
        except Exception as e:
            print(f"[Dataset] ERROR loading {csv_path}: {e}", file=sys.stderr)

    if not dfs:
        print("[Dataset] ERROR: No datasets loaded!", file=sys.stderr)
        sys.exit(1)

    df = pd.concat(dfs, ignore_index=True)
    print(f"[Dataset] Total: {len(df)} samples", file=sys.stderr)

    # Last column is the label (0=normal, 1=attack)
    # Second to last column is attack category
    y = df.iloc[:, -1].fillna(0).astype(int)

    # Use numeric columns as features (excluding last two columns)
    X = df.iloc[:, :-2].select_dtypes(include=[np.number]).fillna(0).values

    print(f"[Dataset] Features: {X.shape[1]}", file=sys.stderr)
    print(f"[Dataset] Normal: {sum(y==0)}, Attack: {sum(y==1)}", file=sys.stderr)

    return X, y

def train_and_profile_xgboost(X_train, y_train, X_test, y_test):
    """Train XGBoost and measure inference time"""
    print("\n[XGBoost] Training...", file=sys.stderr)

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=10,
        learning_rate=0.1,
        random_state=42,
        use_label_encoder=False,
        eval_metric='logloss'
    )

    train_start = time.time()
    model.fit(X_train, y_train, verbose=False)
    train_time = time.time() - train_start

    # Measure inference time
    inference_start = time.time()
    y_pred = model.predict(X_test)
    inference_time = time.time() - inference_start

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    throughput = len(X_test) / inference_time  # samples/second

    print(f"[XGBoost] Training time: {train_time:.2f}s", file=sys.stderr)
    print(f"[XGBoost] Inference time: {inference_time:.4f}s for {len(X_test)} samples", file=sys.stderr)
    print(f"[XGBoost] Throughput: {throughput:.2f} samples/sec", file=sys.stderr)
    print(f"[XGBoost] F1 Score: {f1:.4f}", file=sys.stderr)

    return {
        'F1': f1,
        'Accuracy': accuracy,
        'Inference_Time': inference_time,
        'Throughput': throughput
    }

def train_and_profile_lstm(X_train, y_train, X_test, y_test):
    """Train LSTM and measure inference time"""
    print("\n[LSTM] Training...", file=sys.stderr)

    # Reshape for LSTM
    X_train_lstm = X_train.reshape((X_train.shape[0], 1, X_train.shape[1]))
    X_test_lstm = X_test.reshape((X_test.shape[0], 1, X_test.shape[1]))

    model = Sequential([
        LSTM(64, input_shape=(1, X_train.shape[1]), return_sequences=True),
        Dropout(0.2),
        LSTM(32),
        Dropout(0.2),
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    train_start = time.time()
    model.fit(X_train_lstm, y_train, epochs=10, batch_size=32, validation_split=0.2, verbose=0)
    train_time = time.time() - train_start

    # Measure inference time
    inference_start = time.time()
    y_pred_prob = model.predict(X_test_lstm, verbose=0)
    y_pred = (y_pred_prob > 0.5).astype(int).flatten()
    inference_time = time.time() - inference_start

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    throughput = len(X_test) / inference_time

    print(f"[LSTM] Training time: {train_time:.2f}s", file=sys.stderr)
    print(f"[LSTM] Inference time: {inference_time:.4f}s for {len(X_test)} samples", file=sys.stderr)
    print(f"[LSTM] Throughput: {throughput:.2f} samples/sec", file=sys.stderr)
    print(f"[LSTM] F1 Score: {f1:.4f}", file=sys.stderr)

    return {
        'F1': f1,
        'Accuracy': accuracy,
        'Inference_Time': inference_time,
        'Throughput': throughput
    }

def main():
    print("[ML Baseline - Experiment 3] Starting...", file=sys.stderr)

    # Load dataset
    X, y = load_unsw_dataset()

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Normalize
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print(f"\n[Split] Train: {len(X_train)}, Test: {len(X_test)}", file=sys.stderr)

    results = {}

    # XGBoost
    if HAS_XGBOOST:
        results['XGBoost'] = train_and_profile_xgboost(X_train, y_train, X_test, y_test)
    else:
        results['XGBoost'] = {'F1': 0.0, 'Accuracy': 0.0, 'Inference_Time': 0.0, 'Throughput': 0.0}

    # LSTM
    if HAS_LSTM:
        results['LSTM'] = train_and_profile_lstm(X_train, y_train, X_test, y_test)
    else:
        results['LSTM'] = {'F1': 0.0, 'Accuracy': 0.0, 'Inference_Time': 0.0, 'Throughput': 0.0}

    # Output results
    print("\n\nML BASELINE RESULTS (CSV):")
    print("Model,F1,Accuracy,Inference_Time(s),Throughput(samples/s)")
    for model_name, metrics in results.items():
        print(f"{model_name},{metrics['F1']:.4f},{metrics['Accuracy']:.4f},{metrics['Inference_Time']:.4f},{metrics['Throughput']:.2f}")

if __name__ == "__main__":
    main()

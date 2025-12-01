#!/usr/bin/env python3
"""
ML Baseline for Experiment 2 (VPN Dataset)
Train LSTM and XGBoost models for comparison with FlowSign
"""

import sys
import pandas as pd
import numpy as np
from scipy.io import arff
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
    print("WARNING: XGBoost not installed, skipping XGBoost baseline", file=sys.stderr)

# LSTM (TensorFlow/Keras)
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    HAS_LSTM = True
except ImportError:
    HAS_LSTM = False
    print("WARNING: TensorFlow not installed, skipping LSTM baseline", file=sys.stderr)

def load_vpn_dataset(arff_path):
    """Load VPN dataset from ARFF"""
    print(f"[Dataset] Loading {arff_path}...", file=sys.stderr)

    data, meta = arff.loadarff(arff_path)
    df = pd.DataFrame(data)

    # Convert class label
    df['class1'] = df['class1'].str.decode('utf-8')

    # Convert to binary: VPN=1, Non-VPN=0
    df['label'] = (df['class1'] == 'VPN').astype(int)

    # Drop class column
    df = df.drop('class1', axis=1)

    # Handle missing values (-1 in VPN dataset)
    df = df.replace(-1, np.nan)
    df = df.dropna()

    print(f"[Dataset] Loaded {len(df)} samples", file=sys.stderr)
    print(f"[Dataset] VPN: {sum(df['label']==1)}, Non-VPN: {sum(df['label']==0)}", file=sys.stderr)

    return df

def train_xgboost(X_train, y_train, X_test, y_test):
    """Train XGBoost classifier"""
    print("\n[XGBoost] Training...", file=sys.stderr)

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=10,
        learning_rate=0.1,
        random_state=42,
        use_label_encoder=False,
        eval_metric='logloss'
    )

    model.fit(X_train, y_train, verbose=False)

    # Predict
    y_pred = model.predict(X_test)

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"[XGBoost] Accuracy:  {accuracy:.4f}", file=sys.stderr)
    print(f"[XGBoost] Precision: {precision:.4f}", file=sys.stderr)
    print(f"[XGBoost] Recall:    {recall:.4f}", file=sys.stderr)
    print(f"[XGBoost] F1 Score:  {f1:.4f}", file=sys.stderr)

    return {
        'Accuracy': accuracy,
        'Precision': precision,
        'Recall': recall,
        'F1': f1
    }

def train_lstm(X_train, y_train, X_test, y_test):
    """Train LSTM classifier"""
    print("\n[LSTM] Training...", file=sys.stderr)

    # Reshape for LSTM (samples, timesteps, features)
    X_train_lstm = X_train.reshape((X_train.shape[0], 1, X_train.shape[1]))
    X_test_lstm = X_test.reshape((X_test.shape[0], 1, X_test.shape[1]))

    model = Sequential([
        LSTM(64, input_shape=(1, X_train.shape[1]), return_sequences=True),
        Dropout(0.2),
        LSTM(32),
        Dropout(0.2),
        Dense(1, activation='sigmoid')
    ])

    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )

    # Train with early stopping
    model.fit(
        X_train_lstm, y_train,
        epochs=20,
        batch_size=32,
        validation_split=0.2,
        verbose=0
    )

    # Predict
    y_pred_prob = model.predict(X_test_lstm, verbose=0)
    y_pred = (y_pred_prob > 0.5).astype(int).flatten()

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"[LSTM] Accuracy:  {accuracy:.4f}", file=sys.stderr)
    print(f"[LSTM] Precision: {precision:.4f}", file=sys.stderr)
    print(f"[LSTM] Recall:    {recall:.4f}", file=sys.stderr)
    print(f"[LSTM] F1 Score:  {f1:.4f}", file=sys.stderr)

    return {
        'Accuracy': accuracy,
        'Precision': precision,
        'Recall': recall,
        'F1': f1
    }

def main():
    arff_path = "datasets/VPN/CSVs/Scenario A1-ARFF/TimeBasedFeatures-Dataset-15s-VPN.arff"

    print("[ML Baseline - Experiment 2] Starting...", file=sys.stderr)

    # Load dataset
    df = load_vpn_dataset(arff_path)

    # Split features and labels
    X = df.drop('label', axis=1).values
    y = df['label'].values

    # Train/test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Normalize features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print(f"\n[Split] Train: {len(X_train)}, Test: {len(X_test)}", file=sys.stderr)

    results = {}

    # Train XGBoost
    if HAS_XGBOOST:
        results['XGBoost'] = train_xgboost(X_train, y_train, X_test, y_test)
    else:
        results['XGBoost'] = {
            'Accuracy': 0.0,
            'Precision': 0.0,
            'Recall': 0.0,
            'F1': 0.0
        }
        print("[XGBoost] SKIPPED - not installed", file=sys.stderr)

    # Train LSTM
    if HAS_LSTM:
        results['LSTM'] = train_lstm(X_train, y_train, X_test, y_test)
    else:
        results['LSTM'] = {
            'Accuracy': 0.0,
            'Precision': 0.0,
            'Recall': 0.0,
            'F1': 0.0
        }
        print("[LSTM] SKIPPED - not installed", file=sys.stderr)

    # Output results
    print("\n\nML BASELINE RESULTS (CSV):")
    print("Model,Accuracy,Precision,Recall,F1")
    for model_name, metrics in results.items():
        print(f"{model_name},{metrics['Accuracy']:.4f},{metrics['Precision']:.4f},{metrics['Recall']:.4f},{metrics['F1']:.4f}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Extract HTTPS subset from CICIDS2017 dataset.
Creates stratified train/test split to handle extreme class imbalance.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
import warnings
warnings.filterwarnings('ignore')

def load_and_filter_https(csv_files):
    """Load all CSV files and filter for HTTPS (port 443) traffic"""

    print("="*70)
    print("LOADING CICIDS2017 HTTPS SUBSET")
    print("="*70)

    all_https_flows = []

    for csv_file in csv_files:
        print(f"\nProcessing: {csv_file.name}")

        try:
            df = pd.read_csv(csv_file, low_memory=False)
            df.columns = df.columns.str.strip()

            # Filter for HTTPS (Destination Port = 443)
            https_df = df[df['Destination Port'] == 443].copy()

            if len(https_df) > 0:
                print(f"  Found {len(https_df):,} HTTPS flows")
                all_https_flows.append(https_df)
            else:
                print(f"  No HTTPS flows found")

        except Exception as e:
            print(f"  ERROR: {e}")
            continue

    # Combine all HTTPS flows
    combined_df = pd.concat(all_https_flows, ignore_index=True)

    print(f"\n{'='*70}")
    print(f"Total HTTPS flows: {len(combined_df):,}")

    # Label distribution
    label_counts = combined_df['Label'].value_counts()
    print(f"\nLabel distribution:")
    for label, count in label_counts.items():
        print(f"  {label}: {count:,} ({count/len(combined_df)*100:.2f}%)")

    return combined_df

def create_stratified_split(df, test_size=0.2, random_state=42):
    """Create stratified train/test split"""

    print(f"\n{'='*70}")
    print("CREATING STRATIFIED TRAIN/TEST SPLIT")
    print(f"{'='*70}")
    print(f"Test size: {test_size*100:.0f}%")

    # Separate features and labels
    X = df.drop('Label', axis=1)
    y = df['Label']

    # Convert labels to binary (BENIGN=0, Attack=1)
    y_binary = (y != 'BENIGN').astype(int)

    # Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_binary,
        test_size=test_size,
        random_state=random_state,
        stratify=y_binary
    )

    print(f"\nTrain set: {len(X_train):,} flows")
    print(f"  Benign: {np.sum(y_train==0):,} ({np.sum(y_train==0)/len(y_train)*100:.2f}%)")
    print(f"  Attack: {np.sum(y_train==1):,} ({np.sum(y_train==1)/len(y_train)*100:.2f}%)")

    print(f"\nTest set: {len(X_test):,} flows")
    print(f"  Benign: {np.sum(y_test==0):,} ({np.sum(y_test==0)/len(y_test)*100:.2f}%)")
    print(f"  Attack: {np.sum(y_test==1):,} ({np.sum(y_test==1)/len(y_test)*100:.2f}%)")

    # Add labels back to dataframes
    X_train['Label'] = y_train.values
    X_test['Label'] = y_test.values

    return X_train, X_test

def save_datasets(train_df, test_df, output_dir):
    """Save train and test datasets"""

    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    train_path = output_dir / 'cicids2017_https_train.csv'
    test_path = output_dir / 'cicids2017_https_test.csv'

    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)

    print(f"\n{'='*70}")
    print("SAVED DATASETS")
    print(f"{'='*70}")
    print(f"Train: {train_path} ({len(train_df):,} flows)")
    print(f"Test:  {test_path} ({len(test_df):,} flows)")

    return train_path, test_path

def create_numpy_format(train_df, test_df, output_dir):
    """Create numpy format for BAE-UQ-IDS"""

    print(f"\n{'='*70}")
    print("CREATING NUMPY FORMAT FOR BAE-UQ-IDS")
    print(f"{'='*70}")

    output_dir = Path(output_dir)

    # Separate features and labels
    X_train = train_df.drop('Label', axis=1).values
    y_train = train_df['Label'].values
    X_test = test_df.drop('Label', axis=1).values
    y_test = test_df['Label'].values

    # Clean data (remove inf/nan)
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=0.0, neginf=0.0)

    # Normalize features (0-1 scaling)
    scaler = MinMaxScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Save numpy arrays
    np.save(output_dir / 'train_x.npy', X_train.astype(np.float32))
    np.save(output_dir / 'train_y.npy', y_train.astype(np.int32))
    np.save(output_dir / 'test_x.npy', X_test.astype(np.float32))
    np.save(output_dir / 'test_y.npy', y_test.astype(np.int32))

    print(f"Saved numpy arrays to: {output_dir}/")
    print(f"  train_x.npy: {X_train.shape}")
    print(f"  train_y.npy: {y_train.shape}")
    print(f"  test_x.npy: {X_test.shape}")
    print(f"  test_y.npy: {y_test.shape}")

def main():
    # Configuration
    dataset_dir = Path('/home/maru/work/snortsharp/datasets/cicids2017')
    output_dir = Path('/home/maru/work/snortsharp/dataCICIDS2017_HTTPS')

    # Find CSV files
    csv_files = sorted(dataset_dir.glob('*.csv'))
    csv_files = [f for f in csv_files if 'training' not in f.name and 'test' not in f.name]

    print(f"Found {len(csv_files)} CSV files\n")

    # Load and filter HTTPS
    https_df = load_and_filter_https(csv_files)

    # Create stratified split
    train_df, test_df = create_stratified_split(https_df, test_size=0.2)

    # Save datasets
    save_datasets(train_df, test_df, output_dir)

    # Create numpy format for BAE
    create_numpy_format(train_df, test_df, output_dir)

    print(f"\n{'='*70}")
    print("HTTPS SUBSET EXTRACTION COMPLETE!")
    print(f"{'='*70}")
    print(f"\nDataset ready for Experiment 2:")
    print(f"  - CSV format: {output_dir}/*.csv")
    print(f"  - NumPy format: {output_dir}/*.npy")
    print(f"\nNext steps:")
    print(f"  1. Generate FlowSign cheat rules from train set")
    print(f"  2. Train BAE-UQ-IDS on numpy arrays")
    print(f"  3. Run Snort3 experiments on test set")

if __name__ == '__main__':
    main()

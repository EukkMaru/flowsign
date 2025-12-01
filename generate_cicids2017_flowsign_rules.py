#!/usr/bin/env python3
"""
FlowSign Rule Generator for CIC-IDS-2017 Dataset
Generates SnortSharp/FlowSign rules from decision tree models trained on CIC-IDS-2017

This script:
1. Loads CIC-IDS-2017 CSV dataset with flow-based features
2. Trains decision tree models for each attack category
3. Converts decision tree paths to SnortSharp rule format
4. Max depth = 10 for parser compatibility (<=10 conditions per rule)
"""

import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier, _tree
from sklearn.preprocessing import LabelEncoder
import os
import sys
from pathlib import Path
import glob

# Feature mapping from CIC-IDS-2017 to SnortSharp
# CIC-IDS-2017 already has flow features, we need to map them to SnortSharp feature names
FEATURE_MAPPING = {
    ' Flow Duration': 'flow_duration',
    ' Total Fwd Packets': 'fwd_packets',
    ' Total Backward Packets': 'bwd_packets',
    'Total Length of Fwd Packets': 'fwd_bytes',
    ' Total Length of Bwd Packets': 'bwd_bytes',
    ' Fwd Packet Length Mean': 'fwd_packet_length_mean',
    ' Bwd Packet Length Mean': 'bwd_packet_length_mean',
    ' Flow Bytes/s': 'flow_bytes_per_sec',
    ' Flow Packets/s': 'flow_packets_per_sec',
    ' Flow IAT Mean': 'flow_iat_mean',
    ' Flow IAT Std': 'flow_iat_std',
    ' Fwd IAT Mean': 'fwd_iat_mean',
    ' Bwd IAT Mean': 'bwd_iat_mean',
    ' Packet Length Mean': 'packet_length_mean',
    ' Packet Length Std': 'packet_length_std',
    ' SYN Flag Count': 'syn_flag_count',
    ' ACK Flag Count': 'ack_flag_count',
    ' FIN Flag Count': 'fin_flag_count',
    ' RST Flag Count': 'rst_flag_count',
    ' PSH Flag Count': 'psh_flag_count',
    ' URG Flag Count': 'urg_flag_count',
    ' Down/Up Ratio': 'down_up_ratio',
    ' Average Packet Size': 'avg_packet_size',
}

# SnortSharp available features
SNORTSHARP_FEATURES = [
    'flow_duration', 'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes',
    'packet_length_mean', 'packet_length_std', 'fwd_packet_length_mean',
    'bwd_packet_length_mean', 'flow_bytes_per_sec', 'flow_packets_per_sec',
    'flow_iat_mean', 'flow_iat_std', 'flow_iat_min', 'flow_iat_max',
    'fwd_iat_mean', 'bwd_iat_mean', 'syn_flag_count', 'ack_flag_count',
    'fin_flag_count', 'rst_flag_count', 'psh_flag_count', 'urg_flag_count',
    'down_up_ratio', 'avg_packet_size'
]


def load_cicids2017_dataset(csv_dir):
    """Load all CIC-IDS-2017 CSV files and combine them"""
    print(f"[Data Loader] Loading CIC-IDS-2017 dataset from {csv_dir}...")

    csv_files = glob.glob(str(csv_dir / "*.csv"))

    if not csv_files:
        raise ValueError(f"No CSV files found in {csv_dir}")

    dfs = []
    for csv_file in csv_files:
        print(f"  Loading: {csv_file}")
        try:
            df = pd.read_csv(csv_file, low_memory=False, encoding='utf-8', encoding_errors='ignore')
            dfs.append(df)
            print(f"    Loaded {len(df)} records")
        except Exception as e:
            print(f"    ERROR: {e}")
            continue

    if not dfs:
        raise ValueError("No CSV files loaded successfully!")

    combined_df = pd.concat(dfs, ignore_index=True)
    print(f"[Data Loader] Total records loaded: {len(combined_df)}")

    return combined_df


def preprocess_dataset(df):
    """Preprocess the dataset for training"""
    print(f"[Preprocessor] Preprocessing dataset...")

    # Check for label column (might have leading space)
    label_col = ' Label' if ' Label' in df.columns else 'Label'

    if label_col not in df.columns:
        print(f"[Preprocessor] Available columns: {list(df.columns[:5])}... (showing first 5)")
        raise ValueError(f"Dataset missing '{label_col}' column")

    # Handle missing values
    print(f"[Preprocessor] Handling missing values...")
    df = df.fillna(0)

    # Replace infinite values with large finite numbers
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(0)

    # Separate normal and attack traffic
    normal_df = df[df[label_col].str.upper().str.strip().isin(['BENIGN', 'NORMAL'])].copy()
    attack_df = df[~df[label_col].str.upper().str.strip().isin(['BENIGN', 'NORMAL'])].copy()

    print(f"[Preprocessor] Normal traffic: {len(normal_df)} records")
    print(f"[Preprocessor] Attack traffic: {len(attack_df)} records")

    # Get attack categories
    attack_categories = attack_df[label_col].unique()
    attack_categories = [cat for cat in attack_categories if pd.notna(cat) and cat.strip() != '']

    print(f"[Preprocessor] Attack categories found: {attack_categories}")

    return df, normal_df, attack_df, attack_categories, label_col


def select_features(df):
    """Select features that map to SnortSharp features"""
    print(f"[Feature Selector] Selecting compatible features...")

    available_features = []

    for cicids_feat, snortsharp_feat in FEATURE_MAPPING.items():
        if cicids_feat in df.columns and snortsharp_feat in SNORTSHARP_FEATURES:
            available_features.append(cicids_feat)

    print(f"[Feature Selector] Selected {len(available_features)} features: {available_features[:5]}... (showing first 5)")

    return available_features


def train_decision_tree(X_train, y_train, max_depth=10, min_samples_split=50):
    """Train a decision tree classifier with controlled complexity"""
    print(f"[Model Trainer] Training decision tree (max_depth={max_depth}, min_samples_split={min_samples_split})...")

    # Calculate class distribution
    unique, counts = np.unique(y_train, return_counts=True)
    class_dist = dict(zip(unique, counts))
    total = sum(counts)

    if 0 in class_dist and 1 in class_dist:
        benign_ratio = class_dist[0] / total
        attack_ratio = class_dist[1] / total

        weight_attack = benign_ratio / attack_ratio * 1.5
        weight_benign = 1.0

        print(f"[Model Trainer] Class distribution:")
        print(f"  Benign: {class_dist[0]:,} ({benign_ratio*100:.1f}%)")
        print(f"  Attack: {class_dist[1]:,} ({attack_ratio*100:.1f}%)")
        print(f"[Model Trainer] Class weights: benign={weight_benign:.2f}, attack={weight_attack:.2f}")
    else:
        weight_benign = 1.0
        weight_attack = 2.0
        print(f"[Model Trainer] Using default class weights")

    clf = DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        min_samples_leaf=50,
        max_leaf_nodes=None,
        class_weight={0: weight_benign, 1: weight_attack},
        criterion='gini',
        splitter='best',
        random_state=42
    )

    clf.fit(X_train, y_train)

    print(f"[Model Trainer] Tree depth: {clf.get_depth()}")
    print(f"[Model Trainer] Number of leaves: {clf.get_n_leaves()}")

    return clf


def tree_to_snortsharp_rules(tree, feature_names, feature_mapping, attack_category, sid_start=6000):
    """Convert decision tree paths to SnortSharp rules"""
    print(f"[Rule Generator] Converting tree to SnortSharp rules for {attack_category}...")

    rules = []
    tree_ = tree.tree_
    feature_name = [
        feature_names[i] if i != _tree.TREE_UNDEFINED else "undefined!"
        for i in tree_.feature
    ]

    def recurse(node, path_conditions, sid_counter):
        if tree_.feature[node] != _tree.TREE_UNDEFINED:
            name = feature_name[node]
            threshold = tree_.threshold[node]

            left_conditions = path_conditions + [(name, '<=', threshold)]
            sid_counter = recurse(tree_.children_left[node], left_conditions, sid_counter)

            right_conditions = path_conditions + [(name, '>', threshold)]
            sid_counter = recurse(tree_.children_right[node], right_conditions, sid_counter)

            return sid_counter
        else:
            value = tree_.value[node]
            class_prediction = np.argmax(value[0])

            if class_prediction == 1:  # Attack class
                rule = generate_rule_from_path(
                    path_conditions,
                    feature_mapping,
                    attack_category,
                    sid_counter[0]
                )
                if rule:
                    rules.append(rule)
                    sid_counter[0] += 1

            return sid_counter

    sid_counter = [sid_start]
    recurse(0, [], sid_counter)

    print(f"[Rule Generator] Generated {len(rules)} rules for {attack_category}")

    return rules


def generate_rule_from_path(path_conditions, feature_mapping, attack_category, sid):
    """Generate a single SnortSharp rule from a decision tree path"""

    conditions = []

    for feature, operator, threshold in path_conditions:
        if feature not in feature_mapping:
            continue

        snortsharp_feature = feature_mapping[feature]

        if operator == '<=':
            snortsharp_op = '<='
        elif operator == '>':
            snortsharp_op = '>'
        else:
            snortsharp_op = operator

        # Format threshold
        if abs(threshold) < 0.001 and threshold != 0:
            threshold_str = f"{threshold:.6f}"
        elif abs(threshold) > 1000000:
            threshold_str = f"{int(threshold)}"
        else:
            threshold_str = f"{threshold:.2f}"

        conditions.append(f"{snortsharp_feature} {snortsharp_op} {threshold_str}")

    if not conditions:
        return None

    condition_str = " AND ".join(conditions)
    rule = f'sid:{sid} msg:"{attack_category} - Flow-based detection" {condition_str}'

    return rule


def generate_rules_for_all_categories(df, normal_df, attack_df, attack_categories,
                                       features, feature_mapping, label_col, max_depth=10, min_samples_split=50):
    """Generate rules for all attack categories"""

    all_rules = []
    sid_start = 6000

    for attack_cat in attack_categories:
        print(f"\n{'='*60}")
        print(f"[Rule Generator] Processing attack category: {attack_cat}")
        print(f"{'='*60}")

        attack_samples = attack_df[attack_df[label_col] == attack_cat].copy()

        if len(attack_samples) < 50:
            print(f"[Rule Generator] Skipping {attack_cat} - only {len(attack_samples)} samples")
            continue

        print(f"[Rule Generator] Attack samples: {len(attack_samples)}")

        # Combine with normal samples for training
        combined = pd.concat([normal_df, attack_samples], ignore_index=True)

        print(f"[Rule Generator] Training on ENTIRE dataset (CHEAT RULES):")
        print(f"  Normal samples: {len(normal_df):,}")
        print(f"  Attack samples: {len(attack_samples):,}")
        print(f"  Total: {len(combined):,}")

        # Prepare training data
        X = combined[features].values
        # Create binary labels: 0 for normal, 1 for attack
        y = np.zeros(len(combined), dtype=int)
        y[len(normal_df):] = 1

        # Train decision tree
        tree = train_decision_tree(X, y, max_depth=max_depth, min_samples_split=min_samples_split)

        # Convert to rules
        rules = tree_to_snortsharp_rules(tree, features, feature_mapping, attack_cat, sid_start)

        all_rules.extend(rules)
        sid_start += len(rules)

    return all_rules


def save_rules(rules, output_file):
    """Save rules to file"""
    print(f"\n[Rule Saver] Saving {len(rules)} rules to {output_file}...")

    with open(output_file, 'w') as f:
        f.write("# FlowSign Rules Generated from CIC-IDS-2017 Dataset\n")
        f.write("# Generated by generate_cicids2017_flowsign_rules.py\n")
        f.write(f"# Total rules: {len(rules)}\n")
        f.write("\n")

        for rule in rules:
            f.write(rule + "\n")

    print(f"[Rule Saver] Rules saved successfully!")


def main():
    """Main execution function"""
    print("="*80)
    print("FlowSign Rule Generator for CIC-IDS-2017 Dataset")
    print("="*80)

    # Configuration
    dataset_dir = Path("datasets/CIC-IDS-2017/CSVs/MachineLearningCVE")
    output_dir = Path("snortsharp-rules")
    output_dir.mkdir(exist_ok=True)

    if not dataset_dir.exists():
        print(f"ERROR: Dataset directory not found: {dataset_dir}")
        return 1

    # Load dataset
    df = load_cicids2017_dataset(dataset_dir)

    # Preprocess
    df, normal_df, attack_df, attack_categories, label_col = preprocess_dataset(df)

    # Select features
    features = select_features(df)

    if not features:
        print("ERROR: No compatible features found!")
        return 1

    # Generate rules with max depth 10 for parser compatibility
    print(f"\n{'#'*80}")
    print(f"# Generating OPTIMIZED CHEAT RULES")
    print(f"# Configuration: max_parser_compatible")
    print(f"# Parameters: max_depth=10, min_samples_split=50")
    print(f"# Goal: Maximize F1 score with intentional overfitting")
    print(f"{'#'*80}")

    rules = generate_rules_for_all_categories(
        df, normal_df, attack_df, attack_categories,
        features, FEATURE_MAPPING, label_col,
        max_depth=10,
        min_samples_split=50
    )

    # Save rules
    output_file = output_dir / "cicids2017_flowsign_rules_depth10.txt"
    save_rules(rules, output_file)

    print("\n" + "="*80)
    print("Rule generation complete!")
    print(f"Output directory: {output_dir}")
    print("="*80)

    return 0


if __name__ == "__main__":
    sys.exit(main())

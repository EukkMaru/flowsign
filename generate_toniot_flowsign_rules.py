#!/usr/bin/env python3
"""
FlowSign Rule Generator for TON-IoT Dataset
Generates SnortSharp/FlowSign rules from decision tree models trained on TON-IoT

This script:
1. Loads TON-IoT CSV dataset with flow-based features
2. Trains decision tree models for each attack category
3. Converts decision tree paths to SnortSharp rule format
4. Max depth = 10 for parser compatibility
"""

import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier, _tree
from sklearn.preprocessing import LabelEncoder
import os
import sys
from pathlib import Path

# Feature mapping from TON-IoT to SnortSharp
# TON-IoT has: l4_src_port, l4_dst_port, protocol, l7_proto, in_bytes, out_bytes,
#              in_pkts, out_pkts, tcp_flags, flow_duration_milliseconds
FEATURE_MAPPING = {
    'flow_duration_milliseconds': 'flow_duration',
    'in_pkts': 'fwd_packets',
    'out_pkts': 'bwd_packets',
    'in_bytes': 'fwd_bytes',
    'out_bytes': 'bwd_bytes',
    'tcp_flags': 'syn_flag_count',  # Approximation - TCP flags as indicator
    'protocol': 'flow_duration',  # Use as secondary feature
}

SNORTSHARP_FEATURES = [
    'flow_duration', 'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes',
    'packet_length_mean', 'packet_length_std', 'fwd_packet_length_mean',
    'bwd_packet_length_mean', 'flow_bytes_per_sec', 'flow_packets_per_sec',
    'flow_iat_mean', 'flow_iat_std', 'flow_iat_min', 'flow_iat_max',
    'fwd_iat_mean', 'bwd_iat_mean', 'syn_flag_count', 'ack_flag_count',
    'fin_flag_count', 'rst_flag_count', 'psh_flag_count', 'urg_flag_count',
    'down_up_ratio', 'avg_packet_size'
]


def load_toniot_dataset(csv_files):
    """Load TON-IoT CSV files"""
    print(f"[Data Loader] Loading TON-IoT dataset from {len(csv_files)} files...")

    dfs = []
    for csv_file in csv_files:
        print(f"  Loading: {csv_file}")
        try:
            df = pd.read_csv(csv_file, low_memory=False)
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

    # Check for label columns
    label_col = 'attack_name' if 'attack_name' in df.columns else 'label'

    if label_col not in df.columns:
        print(f"[Preprocessor] Available columns: {list(df.columns[:10])}")
        raise ValueError(f"Dataset missing label column")

    # Handle missing values
    print(f"[Preprocessor] Handling missing values...")
    df = df.fillna(0)
    df = df.replace([np.inf, -np.inf], 0)

    # Separate normal and attack traffic
    normal_df = df[df[label_col].str.lower().str.contains('benign|normal', na=False)].copy()
    attack_df = df[~df[label_col].str.lower().str.contains('benign|normal', na=False)].copy()

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

    for toniot_feat, snortsharp_feat in FEATURE_MAPPING.items():
        if toniot_feat in df.columns and snortsharp_feat in SNORTSHARP_FEATURES:
            available_features.append(toniot_feat)

    # Also check for direct matches
    for col in df.columns:
        col_lower = col.lower().strip()
        if col_lower in SNORTSHARP_FEATURES and col not in available_features:
            available_features.append(col)

    print(f"[Feature Selector] Selected {len(available_features)} features")

    return available_features


def train_decision_tree(X_train, y_train, max_depth=10, min_samples_split=50):
    """Train a decision tree classifier"""
    print(f"[Model Trainer] Training decision tree (max_depth={max_depth})...")

    unique, counts = np.unique(y_train, return_counts=True)
    class_dist = dict(zip(unique, counts))
    total = sum(counts)

    if 0 in class_dist and 1 in class_dist:
        benign_ratio = class_dist[0] / total
        attack_ratio = class_dist[1] / total
        weight_attack = benign_ratio / attack_ratio * 1.5
        weight_benign = 1.0
        print(f"[Model Trainer] Class weights: benign={weight_benign:.2f}, attack={weight_attack:.2f}")
    else:
        weight_benign = 1.0
        weight_attack = 2.0

    clf = DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        min_samples_leaf=50,
        class_weight={0: weight_benign, 1: weight_attack},
        criterion='gini',
        random_state=42
    )

    clf.fit(X_train, y_train)
    print(f"[Model Trainer] Tree depth: {clf.get_depth()}, Leaves: {clf.get_n_leaves()}")

    return clf


def tree_to_snortsharp_rules(tree, feature_names, feature_mapping, attack_category, sid_start=7000):
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

            if class_prediction == 1:
                rule = generate_rule_from_path(path_conditions, feature_mapping, attack_category, sid_counter[0])
                if rule:
                    rules.append(rule)
                    sid_counter[0] += 1

            return sid_counter

    sid_counter = [sid_start]
    recurse(0, [], sid_counter)

    print(f"[Rule Generator] Generated {len(rules)} rules for {attack_category}")
    return rules


def generate_rule_from_path(path_conditions, feature_mapping, attack_category, sid):
    """Generate a single SnortSharp rule"""
    conditions = []

    for feature, operator, threshold in path_conditions:
        snortsharp_feature = feature_mapping.get(feature, feature)

        if snortsharp_feature not in SNORTSHARP_FEATURES:
            continue

        snortsharp_op = '<=' if operator == '<=' else '>'

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


def generate_rules_for_all_categories(df, normal_df, attack_df, attack_categories, features, feature_mapping, label_col, max_depth=10):
    """Generate rules for all attack categories"""
    all_rules = []
    sid_start = 7000

    for attack_cat in attack_categories:
        print(f"\n{'='*60}")
        print(f"[Rule Generator] Processing: {attack_cat}")
        print(f"{'='*60}")

        attack_samples = attack_df[attack_df[label_col] == attack_cat].copy()

        if len(attack_samples) < 50:
            print(f"[Rule Generator] Skipping {attack_cat} - only {len(attack_samples)} samples")
            continue

        combined = pd.concat([normal_df, attack_samples], ignore_index=True)

        X = combined[features].values
        y = np.zeros(len(combined), dtype=int)
        y[len(normal_df):] = 1

        tree = train_decision_tree(X, y, max_depth=max_depth)
        rules = tree_to_snortsharp_rules(tree, features, feature_mapping, attack_cat, sid_start)

        all_rules.extend(rules)
        sid_start += len(rules)

    return all_rules


def save_rules(rules, output_file):
    """Save rules to file"""
    print(f"\n[Rule Saver] Saving {len(rules)} rules to {output_file}...")

    with open(output_file, 'w') as f:
        f.write("# FlowSign Rules Generated from TON-IoT Dataset\n")
        f.write(f"# Total rules: {len(rules)}\n\n")
        for rule in rules:
            f.write(rule + "\n")

    print(f"[Rule Saver] Rules saved successfully!")


def main():
    print("="*80)
    print("FlowSign Rule Generator for TON-IoT Dataset")
    print("="*80)

    dataset_dir = Path("datasets/ton-iot")
    output_dir = Path("snortsharp-rules")
    output_dir.mkdir(exist_ok=True)

    csv_files = [
        dataset_dir / "training-flow.csv",
        dataset_dir / "test-flow.csv",
    ]

    csv_files = [f for f in csv_files if f.exists()]

    if not csv_files:
        print("ERROR: No CSV files found!")
        return 1

    df = load_toniot_dataset(csv_files)
    df, normal_df, attack_df, attack_categories, label_col = preprocess_dataset(df)
    features = select_features(df)

    if not features:
        print("ERROR: No compatible features found!")
        return 1

    rules = generate_rules_for_all_categories(
        df, normal_df, attack_df, attack_categories,
        features, FEATURE_MAPPING, label_col, max_depth=10
    )

    output_file = output_dir / "toniot_flowsign_rules_depth10.txt"
    save_rules(rules, output_file)

    print("\n" + "="*80)
    print("Rule generation complete!")
    print("="*80)

    return 0


if __name__ == "__main__":
    sys.exit(main())

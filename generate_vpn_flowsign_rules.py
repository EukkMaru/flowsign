#!/usr/bin/env python3
"""
Generate FlowSign rules for ISCX VPN-NonVPN dataset
Converts ARFF format flow features to FlowSign rule format
"""

import sys
import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier, _tree
from scipy.io import arff
import warnings
warnings.filterwarnings('ignore')

# Map ARFF features to FlowSign features
FEATURE_MAPPING = {
    'duration': 'flow_duration',
    'total_fiat': 'total_fwd_iat',
    'total_biat': 'total_bwd_iat',
    'min_fiat': 'min_fwd_iat',
    'min_biat': 'min_bwd_iat',
    'max_fiat': 'max_fwd_iat',
    'max_biat': 'max_bwd_iat',
    'mean_fiat': 'fwd_iat_mean',
    'mean_biat': 'bwd_iat_mean',
    'flowPktsPerSecond': 'flow_pkts_per_sec',
    'flowBytesPerSecond': 'flow_bytes_per_sec',
    'min_flowiat': 'flow_iat_min',
    'max_flowiat': 'flow_iat_max',
    'mean_flowiat': 'flow_iat_mean',
    'std_flowiat': 'flow_iat_std',
    'min_active': 'active_min',
    'mean_active': 'active_mean',
    'max_active': 'active_max',
    'std_active': 'active_std',
    'min_idle': 'idle_min',
    'mean_idle': 'idle_mean',
    'max_idle': 'idle_max',
    'std_idle': 'idle_std',
}

def load_arff_data(arff_path):
    """Load ARFF file and convert to DataFrame"""
    print(f"[ARFF Loader] Loading {arff_path}...", file=sys.stderr)

    data, meta = arff.loadarff(arff_path)
    df = pd.DataFrame(data)

    # Convert byte strings to regular strings for class column
    if 'class1' in df.columns:
        df['class1'] = df['class1'].str.decode('utf-8')

    print(f"[ARFF Loader] Loaded {len(df)} flows", file=sys.stderr)
    print(f"[ARFF Loader] Columns: {list(df.columns)}", file=sys.stderr)
    print(f"[ARFF Loader] Classes: {df['class1'].value_counts().to_dict()}", file=sys.stderr)

    return df

def select_compatible_features(df):
    """Select features that are compatible with FlowSign"""
    available_features = set(df.columns)
    compatible_features = []

    for arff_feature, flowsign_feature in FEATURE_MAPPING.items():
        if arff_feature in available_features:
            compatible_features.append(arff_feature)

    print(f"[Feature Selector] Selected {len(compatible_features)} compatible features", file=sys.stderr)
    return compatible_features

def clean_data(df, features):
    """Clean data by removing invalid values"""
    # Replace -1 (missing values in ARFF) with NaN
    df = df.replace(-1, np.nan)

    # Remove rows with NaN values
    initial_count = len(df)
    df = df.dropna(subset=features)
    final_count = len(df)

    print(f"[Data Cleaner] Removed {initial_count - final_count} rows with missing values", file=sys.stderr)
    print(f"[Data Cleaner] Remaining: {final_count} flows", file=sys.stderr)

    return df

def train_decision_tree(X_train, y_train, max_depth=10, min_samples_split=100):
    """Train decision tree classifier"""
    print(f"[Tree Trainer] Training decision tree (max_depth={max_depth})...", file=sys.stderr)

    clf = DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        min_samples_leaf=50,
        criterion='gini',
        random_state=42
    )

    clf.fit(X_train, y_train)

    print(f"[Tree Trainer] Tree depth: {clf.get_depth()}", file=sys.stderr)
    print(f"[Tree Trainer] Number of leaves: {clf.get_n_leaves()}", file=sys.stderr)

    return clf

def tree_to_flowsign_rules(clf, feature_names, class_names, start_sid=6000):
    """Convert decision tree to FlowSign rule format"""
    tree = clf.tree_
    rules = []
    sid = start_sid

    def recurse(node, conditions, depth=0):
        nonlocal sid

        if depth > 10:  # Limit rule complexity
            return

        if tree.feature[node] != _tree.TREE_UNDEFINED:
            # Internal node
            feature_name = feature_names[tree.feature[node]]
            threshold = tree.threshold[node]
            flowsign_feature = FEATURE_MAPPING.get(feature_name, feature_name)

            # Left branch (<=)
            left_conditions = conditions + [(flowsign_feature, '<=', threshold)]
            recurse(tree.children_left[node], left_conditions, depth + 1)

            # Right branch (>)
            right_conditions = conditions + [(flowsign_feature, '>', threshold)]
            recurse(tree.children_right[node], right_conditions, depth + 1)
        else:
            # Leaf node
            class_values = tree.value[node][0]
            predicted_class = np.argmax(class_values)
            class_label = class_names[predicted_class]
            confidence = class_values[predicted_class] / np.sum(class_values)

            if confidence > 0.7 and len(conditions) > 0 and len(conditions) <= 10:
                # Generate rule
                rule_conditions = []
                for feat, op, val in conditions:
                    rule_conditions.append(f"{feat} {op} {val:.2f}")

                rule = f"sid:{sid} msg:\"{class_label} - Flow-based detection\" {' AND '.join(rule_conditions)}"
                rules.append(rule)
                sid += 1

    recurse(0, [])
    return rules

def main():
    # Load VPN dataset (use 15s time window for compatibility with 50-packet window)
    arff_path = "datasets/VPN/CSVs/Scenario A1-ARFF/TimeBasedFeatures-Dataset-15s-VPN.arff"

    print("[VPN Rule Generator] Starting...", file=sys.stderr)

    # Load data
    df = load_arff_data(arff_path)

    # Select compatible features
    features = select_compatible_features(df)

    if len(features) == 0:
        print("ERROR: No compatible features found!", file=sys.stderr)
        sys.exit(1)

    # Clean data
    df = clean_data(df, features)

    # Prepare training data
    X = df[features].values
    y = df['class1'].values

    class_names = sorted(df['class1'].unique())
    print(f"[Data Prep] Classes: {class_names}", file=sys.stderr)
    print(f"[Data Prep] Training samples: {len(X)}", file=sys.stderr)

    # Train decision tree
    clf = train_decision_tree(X, y, max_depth=10, min_samples_split=100)

    # Convert to FlowSign rules
    print("[Rule Generator] Converting tree to FlowSign rules...", file=sys.stderr)
    rules = tree_to_flowsign_rules(clf, features, class_names, start_sid=6000)

    print(f"[Rule Generator] Generated {len(rules)} rules", file=sys.stderr)

    # Output rules
    output_path = "snortsharp-rules/vpn_flowsign_rules_depth10.txt"
    with open(output_path, 'w') as f:
        for rule in rules:
            f.write(rule + '\n')

    print(f"[Rule Generator] Rules written to: {output_path}", file=sys.stderr)

    # Also print to stdout for logging
    for rule in rules:
        print(rule)

if __name__ == "__main__":
    main()

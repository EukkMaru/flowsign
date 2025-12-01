#!/usr/bin/env python3
"""
Generate FlowSign cheat rules for CICIDS2017 HTTPS subset.
Uses class_weight='balanced' to handle extreme class imbalance (2106:1 ratio).
"""

import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier, _tree
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
import warnings
warnings.filterwarnings('ignore')

# Map CICIDS2017 features to FlowSign features
FEATURE_MAPPING = {
    'Flow Duration': 'flow_duration',
    'Total Fwd Packets': 'total_fwd_packets',
    'Total Backward Packets': 'total_bwd_packets',
    'Total Length of Fwd Packets': 'total_fwd_bytes',
    'Total Length of Bwd Packets': 'total_bwd_bytes',
    'Fwd Packet Length Mean': 'fwd_packet_length_mean',
    'Fwd Packet Length Std': 'fwd_packet_length_std',
    'Fwd Packet Length Max': 'fwd_packet_length_max',
    'Fwd Packet Length Min': 'fwd_packet_length_min',
    'Bwd Packet Length Mean': 'bwd_packet_length_mean',
    'Bwd Packet Length Std': 'bwd_packet_length_std',
    'Bwd Packet Length Max': 'bwd_packet_length_max',
    'Bwd Packet Length Min': 'bwd_packet_length_min',
    'Flow Bytes/s': 'flow_bytes_per_sec',
    'Flow Packets/s': 'flow_packets_per_sec',
    'Flow IAT Mean': 'flow_iat_mean',
    'Flow IAT Std': 'flow_iat_std',
    'Flow IAT Max': 'flow_iat_max',
    'Flow IAT Min': 'flow_iat_min',
    'Fwd IAT Mean': 'fwd_iat_mean',
    'Fwd IAT Std': 'fwd_iat_std',
    'Fwd IAT Max': 'fwd_iat_max',
    'Fwd IAT Min': 'fwd_iat_min',
    'Bwd IAT Mean': 'bwd_iat_mean',
    'Bwd IAT Std': 'bwd_iat_std',
    'Bwd IAT Max': 'bwd_iat_max',
    'Bwd IAT Min': 'bwd_iat_min',
    'FIN Flag Count': 'fin_flag_count',
    'SYN Flag Count': 'syn_flag_count',
    'RST Flag Count': 'rst_flag_count',
    'PSH Flag Count': 'psh_flag_count',
    'ACK Flag Count': 'ack_flag_count',
    'URG Flag Count': 'urg_flag_count',
    'Down/Up Ratio': 'down_up_ratio',
    'Average Packet Size': 'avg_packet_size',
    'Avg Fwd Segment Size': 'fwd_segment_size_avg',
    'Avg Bwd Segment Size': 'bwd_segment_size_avg',
    'Init_Win_bytes_forward': 'fwd_init_win_bytes',
    'Init_Win_bytes_backward': 'bwd_init_win_bytes',
    'Active Mean': 'active_mean',
    'Active Std': 'active_std',
    'Active Max': 'active_max',
    'Active Min': 'active_min',
    'Idle Mean': 'idle_mean',
    'Idle Std': 'idle_std',
    'Idle Max': 'idle_max',
    'Idle Min': 'idle_min',
}

def load_training_data(csv_path):
    """Load HTTPS training data"""
    print("="*70)
    print("LOADING TRAINING DATA")
    print("="*70)
    print(f"Loading: {csv_path}")

    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()

    print(f"Total flows: {len(df):,}")
    print(f"\nLabel distribution:")
    for label, count in df['Label'].value_counts().items():
        print(f"  {label}: {count:,} ({count/len(df)*100:.4f}%)")

    return df

def select_features(df):
    """Select features available in both CICIDS2017 and FlowSign"""
    available_cols = set(df.columns)
    selected_features = []

    for cicids_feature, flowsign_feature in FEATURE_MAPPING.items():
        if cicids_feature in available_cols:
            selected_features.append(cicids_feature)

    print(f"\n{'='*70}")
    print(f"FEATURE SELECTION")
    print(f"{'='*70}")
    print(f"Selected {len(selected_features)} compatible features")

    return selected_features

def train_balanced_tree(X, y, max_depth=10):
    """Train decision tree with class_weight='balanced' to handle imbalance"""

    print(f"\n{'='*70}")
    print("TRAINING BALANCED DECISION TREE")
    print(f"{'='*70}")

    # Calculate class weights for transparency
    unique, counts = np.unique(y, return_counts=True)
    class_weight_dict = {
        0: len(y) / (2 * counts[0]),  # Benign
        1: len(y) / (2 * counts[1])   # Attack
    }

    print(f"Class weights:")
    print(f"  Benign (0): {class_weight_dict[0]:.2f}")
    print(f"  Attack (1): {class_weight_dict[1]:.2f}")
    print(f"  Weight ratio (Attack/Benign): {class_weight_dict[1]/class_weight_dict[0]:.1f}x")

    # Train decision tree
    clf = DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_split=20,
        min_samples_leaf=5,
        class_weight='balanced',
        criterion='gini',
        random_state=42
    )

    clf.fit(X, y)

    print(f"\nTree structure:")
    print(f"  Depth: {clf.get_depth()}")
    print(f"  Leaves: {clf.get_n_leaves()}")
    print(f"  Nodes: {clf.tree_.node_count}")

    # Evaluate on training set
    y_pred = clf.predict(X)
    f1 = f1_score(y, y_pred)
    precision = precision_score(y, y_pred)
    recall = recall_score(y, y_pred)

    print(f"\nTraining set performance:")
    print(f"  F1-Score: {f1*100:.2f}%")
    print(f"  Precision: {precision*100:.2f}%")
    print(f"  Recall: {recall*100:.2f}%")

    return clf

def tree_to_flowsign_rules(clf, feature_names, start_sid=6000):
    """Convert decision tree to FlowSign rule format"""

    print(f"\n{'='*70}")
    print("GENERATING FLOWSIGN RULES")
    print(f"{'='*70}")

    tree = clf.tree_
    rules = []
    sid = start_sid

    def recurse(node, conditions, depth=0):
        nonlocal sid

        # Limit rule complexity
        if depth > 10 or len(conditions) > 10:
            return

        if tree.feature[node] != _tree.TREE_UNDEFINED:
            # Internal node
            feature_name = feature_names[tree.feature[node]]
            threshold = tree.threshold[node]

            # Map to FlowSign feature name
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
            confidence = class_values[predicted_class] / np.sum(class_values)

            # Only generate rules for Attack class (1) with high confidence
            if predicted_class == 1 and confidence > 0.6 and len(conditions) > 0 and len(conditions) <= 10:
                # Generate rule
                rule_conditions = []
                for feat, op, val in conditions:
                    rule_conditions.append(f"{feat} {op} {val:.2f}")

                rule = f"sid:{sid} msg:\"PortScan - HTTPS encrypted traffic\" {' AND '.join(rule_conditions)}"
                rules.append(rule)
                sid += 1

    recurse(0, [])

    print(f"Generated {len(rules)} FlowSign rules")

    if len(rules) == 0:
        print("\nWARNING: No rules generated! Tree may be too simple.")
        print("Recommendation: Lower confidence threshold or adjust tree parameters")

    return rules

def save_rules(rules, output_path):
    """Save rules to file"""
    with open(output_path, 'w') as f:
        for rule in rules:
            f.write(rule + '\n')

    print(f"\nRules saved to: {output_path}")

def main():
    # Configuration
    train_csv = '/home/maru/work/snortsharp/dataCICIDS2017_HTTPS/cicids2017_https_train.csv'
    output_path = '/home/maru/work/snortsharp/snortsharp-rules/cicids2017_https_flowsign_rules.txt'

    # Load data
    df = load_training_data(train_csv)

    # Select features
    features = select_features(df)

    if len(features) == 0:
        print("ERROR: No compatible features found!")
        return

    # Prepare data
    X = df[features].values
    y = df['Label'].values  # Already 0/1 from extract script

    # Clean data (remove inf/nan)
    X = np.nan_to_num(X, nan=0.0, posinf=1e10, neginf=-1e10)

    # Train balanced tree
    clf = train_balanced_tree(X, y, max_depth=10)

    # Convert to FlowSign rules
    rules = tree_to_flowsign_rules(clf, features, start_sid=6000)

    # Save rules
    save_rules(rules, output_path)

    print(f"\n{'='*70}")
    print("FLOWSIGN RULE GENERATION COMPLETE!")
    print(f"{'='*70}")
    print(f"\nGenerated {len(rules)} rules targeting PortScan attacks in HTTPS traffic")
    print(f"\nNext steps:")
    print(f"  1. Train BAE-UQ-IDS on HTTPS subset")
    print(f"  2. Run Snort3 + FlowSign experiments with generated rules")
    print(f"  3. Compare F1-scores across all three systems")

if __name__ == '__main__':
    main()

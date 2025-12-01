#!/usr/bin/env python3
"""
Correlate VPN experiment alerts with ground truth labels from ARFF files
Calculate F1, Precision, Recall, Accuracy for each configuration
"""

import sys
import os
import re
from scipy.io import arff
import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict

def load_ground_truth(arff_path):
    """Load ARFF ground truth labels"""
    print(f"[Ground Truth] Loading {arff_path}...", file=sys.stderr)

    data, meta = arff.loadarff(arff_path)
    df = pd.DataFrame(data)

    # Convert class label
    if 'class1' in df.columns:
        df['class1'] = df['class1'].str.decode('utf-8')

    print(f"[Ground Truth] Loaded {len(df)} flows", file=sys.stderr)
    print(f"[Ground Truth] Classes: {df['class1'].value_counts().to_dict()}", file=sys.stderr)

    return df

def parse_alert_log(log_path):
    """Parse Snort alert log to extract alerts"""
    alerts = []

    if not os.path.exists(log_path):
        print(f"[Alert Parser] WARNING: {log_path} not found", file=sys.stderr)
        return alerts

    with open(log_path, 'r') as f:
        for line in f:
            line = line.strip()

            # Parse packet alerts (standard Snort format)
            if line.startswith('[**]'):
                alerts.append({
                    'type': 'packet',
                    'line': line
                })

            # Parse flow alerts (FlowSign format)
            elif '[FLOW]' in line:
                alerts.append({
                    'type': 'flow',
                    'line': line
                })

    print(f"[Alert Parser] Parsed {len(alerts)} alerts from {os.path.basename(log_path)}", file=sys.stderr)
    return alerts

def correlate_alerts_with_ground_truth(alerts, ground_truth_df, pcap_name):
    """
    Correlate alerts with ground truth labels
    Since we don't have perfect packet-to-flow mapping, use heuristics:
    - If alerts detected, mark as positive prediction
    - Ground truth from ARFF file
    """

    # For VPN dataset, ground truth is VPN vs Non-VPN
    # Check if this PCAP is VPN or Non-VPN based on filename
    is_vpn_traffic = pcap_name.startswith('vpn_')

    # Count alert types
    packet_alerts = len([a for a in alerts if a['type'] == 'packet'])
    flow_alerts = len([a for a in alerts if a['type'] == 'flow'])

    print(f"[Correlator] PCAP: {pcap_name}", file=sys.stderr)
    print(f"[Correlator]   Ground truth: {'VPN' if is_vpn_traffic else 'Non-VPN'}", file=sys.stderr)
    print(f"[Correlator]   Packet alerts: {packet_alerts}", file=sys.stderr)
    print(f"[Correlator]   Flow alerts: {flow_alerts}", file=sys.stderr)

    # Simplified correlation:
    # If we have significant flow alerts, we predicted VPN
    # Ground truth comes from filename

    predicted_vpn = flow_alerts > 10  # Threshold: >10 flow alerts = VPN detected

    return {
        'pcap': pcap_name,
        'ground_truth': 'VPN' if is_vpn_traffic else 'Non-VPN',
        'packet_alerts': packet_alerts,
        'flow_alerts': flow_alerts,
        'predicted_vpn': predicted_vpn,
        'is_vpn_traffic': is_vpn_traffic
    }

def calculate_metrics(results):
    """Calculate F1, Precision, Recall, Accuracy"""

    # For VPN detection task
    tp = sum(1 for r in results if r['is_vpn_traffic'] and r['predicted_vpn'])
    fp = sum(1 for r in results if not r['is_vpn_traffic'] and r['predicted_vpn'])
    tn = sum(1 for r in results if not r['is_vpn_traffic'] and not r['predicted_vpn'])
    fn = sum(1 for r in results if r['is_vpn_traffic'] and not r['predicted_vpn'])

    total = tp + fp + tn + fn

    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {
        'TP': tp,
        'FP': fp,
        'TN': tn,
        'FN': fn,
        'Accuracy': accuracy,
        'Precision': precision,
        'Recall': recall,
        'F1': f1
    }

def main():
    exp_dir = "experiment_results/exp2_balanced_20251118_025635"
    arff_path = "datasets/VPN/CSVs/Scenario A1-ARFF/TimeBasedFeatures-Dataset-15s-VPN.arff"

    print("[VPN Alert Correlator] Starting...", file=sys.stderr)

    # Load ground truth
    ground_truth_df = load_ground_truth(arff_path)

    # Get list of PCAPs tested - BALANCED: VPN + Non-VPN
    pcap_files = [
        'vpn_email2a.pcap',
        'vpn_facebook_chat1a.pcap',
        'vpn_ftps_B.pcap',
        'facebook_audio1a.pcap',  # Non-VPN
        'email1a.pcap'             # Non-VPN
    ]

    # Analyze each configuration
    configs = {
        'community': 'Vanilla Snort + Community Rules',
        'packet_cheat': 'Vanilla Snort + Cheat Packet Rules',
        'hybrid': 'Snort + Community + FlowSign'
    }

    all_results = {}

    for config_name, config_desc in configs.items():
        print(f"\n[Analyzer] Processing {config_desc}...", file=sys.stderr)

        config_results = []

        for pcap in pcap_files:
            log_path = f"{exp_dir}/{config_name}/{pcap}.log"

            # Parse alerts
            alerts = parse_alert_log(log_path)

            # Correlate with ground truth
            result = correlate_alerts_with_ground_truth(alerts, ground_truth_df, pcap)
            config_results.append(result)

        # Calculate metrics
        metrics = calculate_metrics(config_results)

        all_results[config_name] = {
            'description': config_desc,
            'results': config_results,
            'metrics': metrics
        }

    # Print results
    print("\n" + "="*80, file=sys.stderr)
    print("EXPERIMENT 2: CORRELATION RESULTS", file=sys.stderr)
    print("="*80, file=sys.stderr)

    for config_name, data in all_results.items():
        print(f"\n{data['description']}:", file=sys.stderr)
        metrics = data['metrics']
        print(f"  TP: {metrics['TP']}, FP: {metrics['FP']}, TN: {metrics['TN']}, FN: {metrics['FN']}", file=sys.stderr)
        print(f"  Accuracy:  {metrics['Accuracy']:.4f}", file=sys.stderr)
        print(f"  Precision: {metrics['Precision']:.4f}", file=sys.stderr)
        print(f"  Recall:    {metrics['Recall']:.4f}", file=sys.stderr)
        print(f"  F1 Score:  {metrics['F1']:.4f}", file=sys.stderr)

    # Output CSV for table generation
    print("\n\nCSV OUTPUT:")
    print("Configuration,Accuracy,Precision,Recall,F1,TP,FP,TN,FN")
    for config_name, data in all_results.items():
        m = data['metrics']
        print(f"{data['description']},{m['Accuracy']:.4f},{m['Precision']:.4f},{m['Recall']:.4f},{m['F1']:.4f},{m['TP']},{m['FP']},{m['TN']},{m['FN']}")

if __name__ == "__main__":
    main()

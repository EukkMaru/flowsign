#!/usr/bin/env python3
"""
Compute classification metrics for VPN detection experiment.

For ISCX2016 VPN-NonVPN dataset:
- Ground truth: PCAP filename indicates if VPN or Non-VPN
- Detection: Count of SID:6000 "VPN" alerts in logs
- Binary classification: VPN vs Non-VPN
"""

import os
import re
import sys
from pathlib import Path

def parse_alerts_from_log(log_path):
    """Parse VPN detection alerts from Snort log"""
    vpn_alerts = 0

    with open(log_path, 'r') as f:
        for line in f:
            # Match: [FLOW] SID:6000 - VPN - Flow-based detection
            if '[FLOW]' in line and 'SID:6000' in line and 'VPN' in line:
                vpn_alerts += 1

    return vpn_alerts

def get_ground_truth(pcap_filename):
    """Determine ground truth label from PCAP filename"""
    if pcap_filename.startswith('vpn_'):
        return 'VPN'
    else:
        return 'Non-VPN'

def compute_metrics(results):
    """
    Compute classification metrics

    For VPN detection:
    - TP: Detected VPN when it was VPN
    - TN: Detected Non-VPN when it was Non-VPN
    - FP: Detected VPN when it was Non-VPN
    - FN: Detected Non-VPN when it was VPN
    """
    tp = sum(1 for r in results if r['ground_truth'] == 'VPN' and r['predicted'] == 'VPN')
    tn = sum(1 for r in results if r['ground_truth'] == 'Non-VPN' and r['predicted'] == 'Non-VPN')
    fp = sum(1 for r in results if r['ground_truth'] == 'Non-VPN' and r['predicted'] == 'VPN')
    fn = sum(1 for r in results if r['ground_truth'] == 'VPN' and r['predicted'] == 'Non-VPN')

    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        'tp': tp,
        'tn': tn,
        'fp': fp,
        'fn': fn,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'fpr': fpr
    }

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Compute VPN detection metrics')
    parser.add_argument('--log-dir', required=True, help='Directory containing log files')
    parser.add_argument('--output', default='vpn_metrics.txt', help='Output file')
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    results = []

    print("="*70)
    print("VPN DETECTION METRICS COMPUTATION")
    print("="*70)
    print(f"\nProcessing logs from: {log_dir}")
    print()

    # Process each log file
    for log_file in sorted(log_dir.glob('*.log')):
        if log_file.name == 'config.lua':
            continue

        pcap_name = log_file.stem  # Remove .pcap.log extension
        alert_count = parse_alerts_from_log(log_file)

        # Ground truth from filename
        ground_truth = get_ground_truth(pcap_name)

        # Prediction: If any VPN alerts, classify as VPN
        predicted = 'VPN' if alert_count > 0 else 'Non-VPN'

        result = {
            'pcap': pcap_name,
            'ground_truth': ground_truth,
            'predicted': predicted,
            'alert_count': alert_count
        }
        results.append(result)

        match = '✓' if ground_truth == predicted else '✗'
        print(f"{match} {pcap_name:30s} | GT: {ground_truth:8s} | Pred: {predicted:8s} | Alerts: {alert_count:4d}")

    print()
    print("="*70)

    # Compute metrics
    metrics = compute_metrics(results)

    print("CLASSIFICATION METRICS")
    print("="*70)
    print(f"True Positives (TP):   {metrics['tp']}")
    print(f"True Negatives (TN):   {metrics['tn']}")
    print(f"False Positives (FP):  {metrics['fp']}")
    print(f"False Negatives (FN):  {metrics['fn']}")
    print()
    print(f"Accuracy:    {metrics['accuracy']*100:.2f}%")
    print(f"Precision:   {metrics['precision']*100:.2f}%")
    print(f"Recall:      {metrics['recall']*100:.2f}%")
    print(f"F1-Score:    {metrics['f1_score']*100:.2f}%")
    print(f"FPR:         {metrics['fpr']*100:.2f}%")
    print("="*70)

    # Save to file
    with open(args.output, 'w') as f:
        f.write("VPN DETECTION METRICS\n")
        f.write("="*70 + "\n\n")

        f.write("Per-PCAP Results:\n")
        for r in results:
            f.write(f"{r['pcap']:30s} | GT: {r['ground_truth']:8s} | Pred: {r['predicted']:8s} | Alerts: {r['alert_count']:4d}\n")

        f.write("\n" + "="*70 + "\n")
        f.write("CLASSIFICATION METRICS\n")
        f.write("="*70 + "\n")
        f.write(f"TP: {metrics['tp']}, TN: {metrics['tn']}, FP: {metrics['fp']}, FN: {metrics['fn']}\n")
        f.write(f"Accuracy:  {metrics['accuracy']*100:.2f}%\n")
        f.write(f"Precision: {metrics['precision']*100:.2f}%\n")
        f.write(f"Recall:    {metrics['recall']*100:.2f}%\n")
        f.write(f"F1-Score:  {metrics['f1_score']*100:.2f}%\n")
        f.write(f"FPR:       {metrics['fpr']*100:.2f}%\n")

    print(f"\nResults saved to: {args.output}")

    return metrics

if __name__ == '__main__':
    main()

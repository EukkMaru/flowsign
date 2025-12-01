#!/usr/bin/env python3
"""
Classification Metrics Calculator

Calculates detection metrics from matched alert results:
- Accuracy: (TP + TN) / (TP + TN + FP + FN)
- Precision: TP / (TP + FP)
- Recall: TP / (TP + FN)
- F1-Score: 2 × (Precision × Recall) / (Precision + Recall)

Usage:
    python3 calculate_metrics.py --input matched_results.json \
                                  --output metrics.json \
                                  --scenario "Snort3 (Community Rules)" \
                                  --dataset "UNSW-NB15"
"""

import json
import argparse
import sys

class MetricsCalculator:
    def __init__(self, scenario_name="", dataset_name=""):
        self.scenario_name = scenario_name
        self.dataset_name = dataset_name
        self.metrics = {}

    def load_matched_results(self, input_path):
        """Load matched results from JSON"""
        print(f"[*] Loading matched results from: {input_path}")

        with open(input_path, 'r') as f:
            results = json.load(f)

        # Extract counts
        tp = results['summary']['tp_count']
        fp = results['summary']['fp_count']
        fn = results['summary']['fn_count']
        tn = results['summary']['tn_count']

        print(f"[*] Loaded TP={tp}, FP={fp}, FN={fn}, TN={tn}")

        return tp, fp, fn, tn

    def calculate_metrics(self, tp, fp, fn, tn):
        """Calculate all classification metrics"""
        print(f"\n[*] Calculating metrics...")

        # Total samples
        total = tp + fp + fn + tn

        # Calculate metrics with division-by-zero handling
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        # Calculate additional metrics
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0  # True Negative Rate
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        # Store metrics
        self.metrics = {
            'scenario': self.scenario_name,
            'dataset': self.dataset_name,
            'confusion_matrix': {
                'true_positives': tp,
                'false_positives': fp,
                'false_negatives': fn,
                'true_negatives': tn,
                'total': total
            },
            'primary_metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1_score,
            },
            'additional_metrics': {
                'specificity': specificity,
                'false_positive_rate': false_positive_rate,
                'false_negative_rate': false_negative_rate,
            },
            'percentage_format': {
                'accuracy': f"{accuracy * 100:.2f}%",
                'precision': f"{precision * 100:.2f}%",
                'recall': f"{recall * 100:.2f}%",
                'f1_score': f"{f1_score * 100:.2f}%",
            }
        }

        return self.metrics

    def print_metrics(self):
        """Print metrics in readable format"""
        print("\n" + "=" * 60)
        print(f"DETECTION METRICS")
        if self.dataset_name:
            print(f"Dataset: {self.dataset_name}")
        if self.scenario_name:
            print(f"Scenario: {self.scenario_name}")
        print("=" * 60)

        cm = self.metrics['confusion_matrix']
        print("\nCONFUSION MATRIX:")
        print(f"  True Positives:  {cm['true_positives']:>10,}")
        print(f"  False Positives: {cm['false_positives']:>10,}")
        print(f"  False Negatives: {cm['false_negatives']:>10,}")
        print(f"  True Negatives:  {cm['true_negatives']:>10,}")
        print(f"  Total:           {cm['total']:>10,}")

        pm = self.metrics['primary_metrics']
        pf = self.metrics['percentage_format']
        print("\nPRIMARY METRICS:")
        print(f"  Accuracy:   {pf['accuracy']:>8} ({pm['accuracy']:.6f})")
        print(f"  Precision:  {pf['precision']:>8} ({pm['precision']:.6f})")
        print(f"  Recall:     {pf['recall']:>8} ({pm['recall']:.6f})")
        print(f"  F1-Score:   {pf['f1_score']:>8} ({pm['f1_score']:.6f})")

        am = self.metrics['additional_metrics']
        print("\nADDITIONAL METRICS:")
        print(f"  Specificity:          {am['specificity'] * 100:>6.2f}% ({am['specificity']:.6f})")
        print(f"  False Positive Rate:  {am['false_positive_rate'] * 100:>6.2f}% ({am['false_positive_rate']:.6f})")
        print(f"  False Negative Rate:  {am['false_negative_rate'] * 100:>6.2f}% ({am['false_negative_rate']:.6f})")

        print("=" * 60)

    def save_metrics(self, output_path):
        """Save metrics to JSON file"""
        print(f"\n[*] Saving metrics to: {output_path}")

        with open(output_path, 'w') as f:
            json.dump(self.metrics, f, indent=2)

        print(f"[*] Saved to {output_path}")

    def save_summary_csv(self, output_path):
        """Save one-line summary to CSV (for table generation)"""
        import csv

        print(f"[*] Saving summary to CSV: {output_path}")

        # Check if file exists to determine if we need header
        import os
        file_exists = os.path.exists(output_path)

        with open(output_path, 'a', newline='') as f:
            fieldnames = ['dataset', 'scenario', 'accuracy', 'precision', 'recall', 'f1_score',
                         'tp', 'fp', 'fn', 'tn']
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            if not file_exists:
                writer.writeheader()

            writer.writerow({
                'dataset': self.dataset_name,
                'scenario': self.scenario_name,
                'accuracy': f"{self.metrics['primary_metrics']['accuracy'] * 100:.2f}",
                'precision': f"{self.metrics['primary_metrics']['precision'] * 100:.2f}",
                'recall': f"{self.metrics['primary_metrics']['recall'] * 100:.2f}",
                'f1_score': f"{self.metrics['primary_metrics']['f1_score'] * 100:.2f}",
                'tp': self.metrics['confusion_matrix']['true_positives'],
                'fp': self.metrics['confusion_matrix']['false_positives'],
                'fn': self.metrics['confusion_matrix']['false_negatives'],
                'tn': self.metrics['confusion_matrix']['true_negatives'],
            })

        print(f"[*] Appended to {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Calculate IDS detection metrics')
    parser.add_argument('--input', required=True, help='Matched results JSON file')
    parser.add_argument('--output', required=True, help='Output metrics JSON file')
    parser.add_argument('--scenario', default='', help='Scenario name (e.g., "Snort3 Community")')
    parser.add_argument('--dataset', default='', help='Dataset name (e.g., "UNSW-NB15")')
    parser.add_argument('--summary-csv', help='Optional: Append summary to CSV file')
    parser.add_argument('--quiet', action='store_true', help='Suppress detailed output')

    args = parser.parse_args()

    # Create calculator
    calculator = MetricsCalculator(scenario_name=args.scenario, dataset_name=args.dataset)

    # Load matched results
    try:
        tp, fp, fn, tn = calculator.load_matched_results(args.input)
    except FileNotFoundError:
        print(f"[!] Error: Input file not found: {args.input}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error loading matched results: {e}")
        sys.exit(1)

    # Calculate metrics
    calculator.calculate_metrics(tp, fp, fn, tn)

    # Print metrics (unless quiet mode)
    if not args.quiet:
        calculator.print_metrics()

    # Save full metrics to JSON
    calculator.save_metrics(args.output)

    # Save summary to CSV if requested
    if args.summary_csv:
        calculator.save_summary_csv(args.summary_csv)

    # Print quick summary
    pf = calculator.metrics['percentage_format']
    print(f"\n[✓] Done! Accuracy: {pf['accuracy']}, Precision: {pf['precision']}, " +
          f"Recall: {pf['recall']}, F1: {pf['f1_score']}")

if __name__ == '__main__':
    main()

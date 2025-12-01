#!/usr/bin/env python3
"""
Results Table Generator

Generates a comprehensive markdown table from experiment results.

Input: summary.csv with columns:
    dataset, scenario, accuracy, precision, recall, f1_score, tp, fp, fn, tn

Output: FINAL_RESULTS.md with formatted comparison table

Usage:
    python3 generate_results_table.py --input summary.csv --output FINAL_RESULTS.md
"""

import csv
import argparse
import sys
from collections import defaultdict
from datetime import datetime

class ResultsTableGenerator:
    def __init__(self):
        self.results = []
        self.grouped_results = defaultdict(list)

    def load_summary(self, csv_path):
        """Load summary CSV"""
        print(f"[*] Loading summary from: {csv_path}")

        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.results.append(row)

        print(f"[*] Loaded {len(self.results)} result rows")

        # Group by dataset
        for result in self.results:
            dataset = result['dataset']
            self.grouped_results[dataset].append(result)

    def generate_markdown(self, output_path):
        """Generate markdown results table"""
        print(f"[*] Generating markdown table: {output_path}")

        with open(output_path, 'w') as f:
            # Header
            f.write("# Three-Way IDS Comparison Results\n\n")
            f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Executive summary
            f.write("## Executive Summary\n\n")
            f.write("Comparison of three intrusion detection approaches:\n")
            f.write("1. **Snort3 (Community Rules)**: Baseline packet-level detection\n")
            f.write("2. **Snort3 (Cheat Rules)**: Upper bound for signature-based detection\n")
            f.write("3. **Snort3+FlowSign (Cheat Rules)**: Combined packet + flow detection\n\n")

            # Overall comparison table
            f.write("## Overall Results\n\n")
            f.write("| Dataset | Scenario | Accuracy | Precision | Recall | F1-Score |\n")
            f.write("|---------|----------|----------|-----------|--------|----------|\n")

            for result in self.results:
                f.write(f"| {result['dataset']:<15} ")
                f.write(f"| {result['scenario']:<30} ")
                f.write(f"| {result['accuracy']:>6}% ")
                f.write(f"| {result['precision']:>7}% ")
                f.write(f"| {result['recall']:>5}% ")
                f.write(f"| {result['f1_score']:>6}% |\n")

            f.write("\n")

            # Per-dataset analysis
            f.write("## Detailed Analysis by Dataset\n\n")

            for dataset, results in self.grouped_results.items():
                f.write(f"### {dataset}\n\n")

                # Table
                f.write("| Scenario | Accuracy | Precision | Recall | F1-Score | TP | FP | FN | TN |\n")
                f.write("|----------|----------|-----------|--------|----------|----|----|----|----|---|\n")

                for result in results:
                    f.write(f"| {result['scenario']:<30} ")
                    f.write(f"| {result['accuracy']:>6}% ")
                    f.write(f"| {result['precision']:>7}% ")
                    f.write(f"| {result['recall']:>5}% ")
                    f.write(f"| {result['f1_score']:>6}% ")
                    f.write(f"| {result['tp']:>6} ")
                    f.write(f"| {result['fp']:>6} ")
                    f.write(f"| {result['fn']:>6} ")
                    f.write(f"| {result['tn']:>8} |\n")

                f.write("\n")

                # Best performer
                best = max(results, key=lambda x: float(x['f1_score']))
                f.write(f"**Best F1-Score**: {best['scenario']} ({best['f1_score']}%)\n\n")

            # Key insights
            f.write("## Key Insights\n\n")

            # Find overall best performers
            if self.results:
                best_accuracy = max(self.results, key=lambda x: float(x['accuracy']))
                best_precision = max(self.results, key=lambda x: float(x['precision']))
                best_recall = max(self.results, key=lambda x: float(x['recall']))
                best_f1 = max(self.results, key=lambda x: float(x['f1_score']))

                f.write(f"- **Highest Accuracy**: {best_accuracy['scenario']} on {best_accuracy['dataset']} ({best_accuracy['accuracy']}%)\n")
                f.write(f"- **Highest Precision**: {best_precision['scenario']} on {best_precision['dataset']} ({best_precision['precision']}%)\n")
                f.write(f"- **Highest Recall**: {best_recall['scenario']} on {best_recall['dataset']} ({best_recall['recall']}%)\n")
                f.write(f"- **Highest F1-Score**: {best_f1['scenario']} on {best_f1['dataset']} ({best_f1['f1_score']}%)\n")
                f.write("\n")

            # Methodology
            f.write("## Methodology\n\n")
            f.write("### Datasets\n")
            f.write("- **UNSW-NB15**: Modern network intrusion dataset with 9 attack types\n")
            f.write("- **CIC-IDS2017**: Realistic dataset with 5 days of attack scenarios\n")
            f.write("- **Ton-IoT**: IoT-focused dataset with various attack vectors\n\n")

            f.write("### Metrics\n")
            f.write("- **Accuracy**: (TP + TN) / (TP + TN + FP + FN)\n")
            f.write("- **Precision**: TP / (TP + FP)\n")
            f.write("- **Recall**: TP / (TP + FN)\n")
            f.write("- **F1-Score**: 2 × (Precision × Recall) / (Precision + Recall)\n\n")

            f.write("### Scenarios\n")
            f.write("1. **Community Rules**: Standard Snort3 ruleset (baseline)\n")
            f.write("2. **Cheat Rules**: Ground-truth-derived signatures (upper bound)\n")
            f.write("3. **FlowSign**: Combined packet + flow-level detection (hybrid)\n\n")

            # Footer
            f.write("---\n\n")
            f.write("*Generated by SnortSharp Three-Way Comparison Framework*\n")

        print(f"[*] Saved to {output_path}")

    def print_summary(self):
        """Print quick summary to console"""
        print("\n" + "=" * 80)
        print("RESULTS SUMMARY")
        print("=" * 80)

        for dataset, results in self.grouped_results.items():
            print(f"\n{dataset}:")
            for result in results:
                print(f"  {result['scenario']:<35} F1: {result['f1_score']:>6}%  " +
                      f"Acc: {result['accuracy']:>6}%  " +
                      f"Prec: {result['precision']:>6}%  " +
                      f"Rec: {result['recall']:>5}%")

        print("\n" + "=" * 80)

def main():
    parser = argparse.ArgumentParser(description='Generate results comparison table')
    parser.add_argument('--input', required=True, help='Summary CSV file')
    parser.add_argument('--output', required=True, help='Output markdown file')

    args = parser.parse_args()

    # Create generator
    generator = ResultsTableGenerator()

    # Load summary
    try:
        generator.load_summary(args.input)
    except FileNotFoundError:
        print(f"[!] Error: Input file not found: {args.input}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error loading summary: {e}")
        sys.exit(1)

    if not generator.results:
        print("[!] No results found in summary CSV")
        sys.exit(1)

    # Generate markdown table
    generator.generate_markdown(args.output)

    # Print summary
    generator.print_summary()

    print(f"\n[✓] Done! Results table saved to {args.output}")

if __name__ == '__main__':
    main()

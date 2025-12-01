#!/usr/bin/env python3
"""
Count HTTPS traffic in CICIDS2017 dataset.
Filters for port 443 (HTTPS) and counts benign vs attack flows.
"""

import pandas as pd
from pathlib import Path
from collections import Counter

def count_https_in_csv(csv_path):
    """Count HTTPS flows (port 443) in a CSV file"""
    print(f"\nProcessing: {csv_path.name}")

    try:
        # Read CSV
        df = pd.read_csv(csv_path, low_memory=False)

        # Clean column names (remove leading/trailing spaces)
        df.columns = df.columns.str.strip()

        # Total flows in file
        total_flows = len(df)

        # Filter for HTTPS (Destination Port = 443)
        https_flows = df[df['Destination Port'] == 443]
        https_count = len(https_flows)

        if https_count == 0:
            print(f"  Total flows: {total_flows:,}")
            print(f"  HTTPS flows: 0 (0.00%)")
            return {'total': 0, 'benign': 0, 'attacks': {}}

        # Count by label
        label_counts = https_flows['Label'].value_counts().to_dict()

        # Separate benign vs attacks
        benign_count = label_counts.get('BENIGN', 0)
        attack_counts = {k: v for k, v in label_counts.items() if k != 'BENIGN'}
        total_attacks = sum(attack_counts.values())

        # Print statistics
        print(f"  Total flows: {total_flows:,}")
        print(f"  HTTPS flows: {https_count:,} ({https_count/total_flows*100:.2f}%)")
        print(f"    Benign: {benign_count:,} ({benign_count/https_count*100:.2f}%)")
        print(f"    Attacks: {total_attacks:,} ({total_attacks/https_count*100:.2f}%)")

        if attack_counts:
            print(f"    Attack breakdown:")
            for attack_type, count in sorted(attack_counts.items()):
                print(f"      {attack_type}: {count:,}")

        return {
            'total': https_count,
            'benign': benign_count,
            'attacks': attack_counts
        }

    except Exception as e:
        print(f"  ERROR: {e}")
        return {'total': 0, 'benign': 0, 'attacks': {}}

def main():
    dataset_dir = Path('/home/maru/work/snortsharp/datasets/cicids2017')

    print("="*70)
    print("CICIDS2017 HTTPS TRAFFIC ANALYSIS")
    print("="*70)

    # Find all CSV files
    csv_files = sorted(dataset_dir.glob('*.csv'))
    csv_files = [f for f in csv_files if 'training' not in f.name and 'test' not in f.name]

    print(f"\nFound {len(csv_files)} CSV files")

    # Process each CSV
    results = {}
    for csv_file in csv_files:
        result = count_https_in_csv(csv_file)
        results[csv_file.name] = result

    # Aggregate statistics
    print("\n" + "="*70)
    print("AGGREGATE STATISTICS")
    print("="*70)

    total_https = sum(r['total'] for r in results.values())
    total_benign = sum(r['benign'] for r in results.values())

    # Combine all attack counts
    all_attacks = Counter()
    for r in results.values():
        all_attacks.update(r['attacks'])

    total_attacks = sum(all_attacks.values())

    print(f"\nTotal HTTPS flows: {total_https:,}")
    print(f"  Benign: {total_benign:,} ({total_benign/total_https*100:.2f}%)")
    print(f"  Attacks: {total_attacks:,} ({total_attacks/total_https*100:.2f}%)")

    if all_attacks:
        print(f"\nAttack type distribution (HTTPS only):")
        for attack_type, count in all_attacks.most_common():
            print(f"  {attack_type}: {count:,} ({count/total_attacks*100:.2f}% of attacks)")

    print("\n" + "="*70)

    # Save detailed results
    import json
    output_file = 'cicids2017_https_statistics.json'
    with open(output_file, 'w') as f:
        json.dump({
            'total_https_flows': total_https,
            'benign_flows': total_benign,
            'attack_flows': total_attacks,
            'attack_breakdown': dict(all_attacks),
            'per_file': {k: v for k, v in results.items()}
        }, f, indent=2)

    print(f"Detailed statistics saved to: {output_file}")

if __name__ == '__main__':
    main()

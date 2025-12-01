#!/usr/bin/env python3
"""
Count class balance for UNSW-NB15 and CICIDS2017 datasets
"""
import pandas as pd
import os
from collections import Counter

print("=" * 80)
print("DATASET CLASS BALANCE ANALYSIS")
print("=" * 80)

# ============================================================================
# UNSW-NB15 Dataset Analysis
# ============================================================================
print("\n" + "=" * 80)
print("UNSW-NB15 DATASET")
print("=" * 80)

unsw_files = [
    'datasets/UNSW-NB15/CSV_Files/UNSW-NB15_1.csv',
    'datasets/UNSW-NB15/CSV_Files/UNSW-NB15_2.csv',
    'datasets/UNSW-NB15/CSV_Files/UNSW-NB15_3.csv',
    'datasets/UNSW-NB15/CSV_Files/UNSW-NB15_4.csv'
]

# UNSW-NB15 column names (from NUSW-NB15_features.csv)
unsw_columns = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts',
    'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len',
    'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'Label'
]

unsw_total_records = 0
unsw_benign = 0
unsw_attack = 0
unsw_attack_types = Counter()

for csv_file in unsw_files:
    if not os.path.exists(csv_file):
        print(f"⚠️  File not found: {csv_file}")
        continue

    print(f"\nProcessing: {os.path.basename(csv_file)}")
    # UNSW-NB15 CSV files don't have headers
    df = pd.read_csv(csv_file, header=None, names=unsw_columns, low_memory=False)

    records = len(df)
    benign = (df['Label'] == 0).sum()
    attack = (df['Label'] == 1).sum()

    print(f"  Records: {records:,}")
    print(f"  Benign: {benign:,} ({benign/records*100:.2f}%)")
    print(f"  Attack: {attack:,} ({attack/records*100:.2f}%)")

    # Count attack types
    attack_df = df[df['Label'] == 1]
    attack_types = attack_df['attack_cat'].value_counts()
    for attack_type, count in attack_types.items():
        if pd.notna(attack_type) and attack_type != '':
            unsw_attack_types[attack_type] += count
            print(f"    - {attack_type}: {count:,}")

    unsw_total_records += records
    unsw_benign += benign
    unsw_attack += attack

print("\n" + "-" * 80)
print("UNSW-NB15 TOTAL:")
print("-" * 80)
print(f"Total Records: {unsw_total_records:,}")
print(f"Benign: {unsw_benign:,} ({unsw_benign/unsw_total_records*100:.2f}%)")
print(f"Attack: {unsw_attack:,} ({unsw_attack/unsw_total_records*100:.2f}%)")
print(f"Class Imbalance Ratio (Benign:Attack): {unsw_benign/unsw_attack:.2f}:1")

print("\nAttack Type Distribution:")
for attack_type, count in unsw_attack_types.most_common():
    print(f"  {attack_type}: {count:,} ({count/unsw_attack*100:.2f}%)")

# ============================================================================
# CICIDS2017 Dataset Analysis
# ============================================================================
print("\n" + "=" * 80)
print("CICIDS2017 DATASET")
print("=" * 80)

cicids_files = [
    'datasets/cicids2017/Monday-WorkingHours.pcap_ISCX.csv',
    'datasets/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv',
    'datasets/cicids2017/Wednesday-workingHours.pcap_ISCX.csv',
    'datasets/cicids2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'datasets/cicids2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'datasets/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'datasets/cicids2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'datasets/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
]

cicids_total_records = 0
cicids_benign = 0
cicids_attack = 0
cicids_attack_types = Counter()

for csv_file in cicids_files:
    if not os.path.exists(csv_file):
        print(f"⚠️  File not found: {csv_file}")
        continue

    print(f"\nProcessing: {os.path.basename(csv_file)}")
    df = pd.read_csv(csv_file, low_memory=False)
    df.columns = df.columns.str.strip()

    # CICIDS2017 has 'Label' column with attack type names
    if 'Label' in df.columns:
        label_col = 'Label'
    elif ' Label' in df.columns:
        label_col = ' Label'
    else:
        print(f"  Error: No Label column found. Available columns: {list(df.columns)[:10]}")
        continue

    records = len(df)
    benign = (df[label_col] == 'BENIGN').sum()
    attack = (df[label_col] != 'BENIGN').sum()

    print(f"  Records: {records:,}")
    print(f"  Benign: {benign:,} ({benign/records*100:.2f}%)")
    print(f"  Attack: {attack:,} ({attack/records*100:.2f}%)")

    # Count attack types
    attack_types = df[df[label_col] != 'BENIGN'][label_col].value_counts()
    for attack_type, count in attack_types.items():
        cicids_attack_types[attack_type] += count
        print(f"    - {attack_type}: {count:,}")

    cicids_total_records += records
    cicids_benign += benign
    cicids_attack += attack

print("\n" + "-" * 80)
print("CICIDS2017 TOTAL:")
print("-" * 80)
print(f"Total Records: {cicids_total_records:,}")
print(f"Benign: {cicids_benign:,} ({cicids_benign/cicids_total_records*100:.2f}%)")
print(f"Attack: {cicids_attack:,} ({cicids_attack/cicids_total_records*100:.2f}%)")
if cicids_attack > 0:
    print(f"Class Imbalance Ratio (Benign:Attack): {cicids_benign/cicids_attack:.2f}:1")

print("\nAttack Type Distribution:")
for attack_type, count in cicids_attack_types.most_common():
    print(f"  {attack_type}: {count:,} ({count/cicids_attack*100:.2f}%)")

# ============================================================================
# Summary Comparison
# ============================================================================
print("\n" + "=" * 80)
print("COMPARISON SUMMARY")
print("=" * 80)

print(f"\n{'Dataset':<20} {'Total Records':<15} {'Benign':<15} {'Attack':<15} {'Imbalance Ratio':<20}")
print("-" * 85)
print(f"{'UNSW-NB15':<20} {unsw_total_records:>14,} {unsw_benign:>14,} {unsw_attack:>14,} {unsw_benign/unsw_attack:>19.2f}:1")
if cicids_attack > 0:
    print(f"{'CICIDS2017':<20} {cicids_total_records:>14,} {cicids_benign:>14,} {cicids_attack:>14,} {cicids_benign/cicids_attack:>19.2f}:1")
else:
    print(f"{'CICIDS2017':<20} {cicids_total_records:>14,} {cicids_benign:>14,} {cicids_attack:>14,} {'N/A':>19}")

print("\n" + "=" * 80)

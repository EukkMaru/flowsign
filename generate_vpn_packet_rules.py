#!/usr/bin/env python3
"""
Generate Snort3 packet rules for VPN dataset
NOTE: These rules will be limited in effectiveness since VPN traffic is encrypted.
This demonstrates the limitation of packet-based detection on encrypted traffic.
"""

import sys
import pandas as pd
import numpy as np
from scipy.io import arff
import warnings
warnings.filterwarnings('ignore')

def load_arff_data(arff_path):
    """Load ARFF file and convert to DataFrame"""
    print(f"[ARFF Loader] Loading {arff_path}...", file=sys.stderr)

    data, meta = arff.loadarff(arff_path)
    df = pd.DataFrame(data)

    # Convert byte strings to regular strings for class column
    if 'class1' in df.columns:
        df['class1'] = df['class1'].str.decode('utf-8')

    print(f"[ARFF Loader] Loaded {len(df)} flows", file=sys.stderr)
    print(f"[ARFF Loader] Classes: {df['class1'].value_counts().to_dict()}", file=sys.stderr)

    return df

def generate_packet_rules(df):
    """
    Generate basic Snort3 packet rules based on flow characteristics.
    Note: These will be limited since VPN encrypts packet payloads.
    """
    rules = []
    sid = 7000

    # Analyze flow characteristics for each class
    for class_label in df['class1'].unique():
        class_df = df[df['class1'] == class_label]

        # Get packet rate statistics
        if 'flowPktsPerSecond' in class_df.columns:
            median_pps = class_df['flowPktsPerSecond'].median()
            high_pps = class_df['flowPktsPerSecond'].quantile(0.75)
            low_pps = class_df['flowPktsPerSecond'].quantile(0.25)

            # High packet rate rule
            if not np.isnan(high_pps) and high_pps > 0:
                rule = f'alert ip any any -> any any (msg:"{class_label} - High packet rate"; '
                rule += f'detection_filter: track by_src, count {int(high_pps)}, seconds 1; '
                rule += f'sid:{sid}; rev:1;)'
                rules.append(rule)
                sid += 1

            # Low packet rate rule
            if not np.isnan(low_pps) and low_pps > 0:
                rule = f'alert ip any any -> any any (msg:"{class_label} - Low packet rate pattern"; '
                rule += f'detection_filter: track by_src, count {int(low_pps)}, seconds 1; '
                rule += f'sid:{sid}; rev:1;)'
                rules.append(rule)
                sid += 1

        # Get byte rate statistics
        if 'flowBytesPerSecond' in class_df.columns:
            median_bps = class_df['flowBytesPerSecond'].median()
            high_bps = class_df['flowBytesPerSecond'].quantile(0.75)

            # High byte rate rule
            if not np.isnan(high_bps) and high_bps > 0:
                rule = f'alert ip any any -> any any (msg:"{class_label} - High data rate"; '
                rule += f'dsize:>{int(high_bps/10)}; '  # Rough approximation
                rule += f'sid:{sid}; rev:1;)'
                rules.append(rule)
                sid += 1

    # Add generic VPN detection rules based on common VPN characteristics
    # These are heuristic-based and may have false positives

    # Rule for OpenVPN default port
    rules.append('alert udp any any -> any 1194 (msg:"Possible OpenVPN traffic"; sid:7100; rev:1;)')

    # Rule for IPSec/IKE
    rules.append('alert udp any any -> any 500 (msg:"Possible IPSec IKE traffic"; sid:7101; rev:1;)')
    rules.append('alert udp any any -> any 4500 (msg:"Possible IPSec NAT-T traffic"; sid:7102; rev:1;)')

    # Rule for PPTP
    rules.append('alert tcp any any -> any 1723 (msg:"Possible PPTP VPN traffic"; sid:7103; rev:1;)')

    # Rule for L2TP
    rules.append('alert udp any any -> any 1701 (msg:"Possible L2TP VPN traffic"; sid:7104; rev:1;)')

    # Rule for WireGuard default port
    rules.append('alert udp any any -> any 51820 (msg:"Possible WireGuard VPN traffic"; sid:7105; rev:1;)')

    # Generic encrypted traffic patterns (ESP protocol)
    rules.append('alert ip any any -> any any (msg:"IPSec ESP encrypted traffic"; ip_proto:50; sid:7106; rev:1;)')
    rules.append('alert ip any any -> any any (msg:"IPSec AH traffic"; ip_proto:51; sid:7107; rev:1;)')

    return rules

def main():
    arff_path = "datasets/VPN/CSVs/Scenario A1-ARFF/TimeBasedFeatures-Dataset-15s-VPN.arff"

    print("[VPN Packet Rule Generator] Starting...", file=sys.stderr)
    print("[VPN Packet Rule Generator] NOTE: Packet rules will be limited due to VPN encryption", file=sys.stderr)

    # Load data
    df = load_arff_data(arff_path)

    # Generate packet rules
    print("[Rule Generator] Generating packet-based rules...", file=sys.stderr)
    rules = generate_packet_rules(df)

    print(f"[Rule Generator] Generated {len(rules)} packet rules", file=sys.stderr)

    # Output rules
    output_path = "snortsharp-rules/vpn_snort3_packet.rules"
    with open(output_path, 'w') as f:
        for rule in rules:
            f.write(rule + '\n')

    print(f"[Rule Generator] Rules written to: {output_path}", file=sys.stderr)

    # Also print to stdout for logging
    for rule in rules:
        print(rule)

if __name__ == "__main__":
    main()

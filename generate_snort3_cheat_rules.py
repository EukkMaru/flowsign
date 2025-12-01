#!/usr/bin/env python3
"""
Snort3 Cheat Rule Generator

Generates Snort3 signature rules from ground truth CSV files.
These "cheat" rules have perfect knowledge of attack traffic and represent
the upper bound for signature-based detection.

Usage:
    python3 generate_snort3_cheat_rules.py --dataset unsw_nb15 --output rules.txt
    python3 generate_snort3_cheat_rules.py --dataset cicids2017 --output rules.txt
"""

import csv
import argparse
import sys
from collections import defaultdict

class CheatRuleGenerator:
    def __init__(self, dataset_type):
        self.dataset_type = dataset_type
        self.rules = []
        self.sid_counter = 1000000  # Start at 1M to avoid conflicts

    def parse_unsw_nb15(self, csv_path):
        """Parse UNSW-NB15 CSV and generate rules"""
        print(f"[*] Parsing UNSW-NB15 CSV: {csv_path}")

        attack_flows = []
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                try:
                    # UNSW-NB15 format (no header):
                    # 0:srcip, 1:sport, 2:dstip, 3:dsport, 4:proto
                    # 47:attack_cat, 48:Label (0=normal, 1=attack)
                    if len(row) < 49:
                        continue  # Skip incomplete rows

                    # Check if it's an attack (Label column 48: 0=normal, 1=attack)
                    label_flag = row[48].strip()
                    attack_cat = row[47].strip()

                    if label_flag == '1' and attack_cat:  # It's an attack
                        src_ip = row[0].strip()
                        src_port = row[1].strip()
                        dst_ip = row[2].strip()
                        dst_port = row[3].strip()
                        proto = row[4].strip()

                        # Convert protocol name/number to standard name
                        proto_name = self._proto_num_to_name(proto)

                        attack_flows.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': proto_name,
                            'label': attack_cat
                        })
                except Exception as e:
                    continue  # Skip malformed rows

        print(f"[*] Found {len(attack_flows)} attack flows")
        return attack_flows

    def parse_cicids2017(self, csv_path):
        """Parse CIC-IDS2017 CSV and generate rules"""
        print(f"[*] Parsing CIC-IDS2017 CSV: {csv_path}")

        attack_flows = []
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Check if it's an attack (Label column)
                label = row.get(' Label', row.get('Label', 'BENIGN')).strip()

                if label not in ['BENIGN', 'Benign', '']:
                    # Extract 5-tuple
                    try:
                        src_ip = row.get(' Source IP', row.get('Source IP', ''))
                        dst_ip = row.get(' Destination IP', row.get('Destination IP', ''))
                        src_port = row.get(' Source Port', row.get('Source Port', '0'))
                        dst_port = row.get(' Destination Port', row.get('Destination Port', '0'))
                        proto = row.get(' Protocol', row.get('Protocol', '6'))

                        # Convert protocol number to name if needed
                        proto_name = self._proto_num_to_name(proto) if proto.isdigit() else 'tcp'

                        attack_flows.append({
                            'src_ip': src_ip.strip(),
                            'dst_ip': dst_ip.strip(),
                            'src_port': src_port.strip(),
                            'dst_port': dst_port.strip(),
                            'protocol': proto_name.lower(),
                            'label': label
                        })
                    except Exception as e:
                        continue  # Skip malformed rows

        print(f"[*] Found {len(attack_flows)} attack flows")
        return attack_flows

    def _proto_num_to_name(self, proto):
        """Convert protocol number to name"""
        proto_str = str(proto).lower().strip()

        # If already a name, return it
        if proto_str in ['tcp', 'udp', 'icmp', 'ip']:
            return proto_str

        # Otherwise convert number to name
        proto_map = {
            '6': 'tcp',
            '17': 'udp',
            '1': 'icmp',
            '58': 'icmp'  # ICMPv6
        }
        return proto_map.get(proto_str, 'ip')

    def generate_rules(self, attack_flows, max_rules=10000):
        """Generate Snort3 rules from attack flows"""
        print(f"[*] Generating Snort3 cheat rules...")

        # Deduplicate by 5-tuple to avoid redundant rules
        unique_flows = {}
        for flow in attack_flows:
            key = f"{flow['src_ip']}:{flow['src_port']}->{flow['dst_ip']}:{flow['dst_port']}:{flow['protocol']}"
            if key not in unique_flows:
                unique_flows[key] = flow

        print(f"[*] {len(unique_flows)} unique flows after deduplication")

        # Limit rules to prevent massive rulesets
        if len(unique_flows) > max_rules:
            print(f"[!] WARNING: Limiting to {max_rules} rules (found {len(unique_flows)} unique flows)")
            unique_flows = dict(list(unique_flows.items())[:max_rules])

        for flow_key, flow in unique_flows.items():
            rule = self._create_snort_rule(flow)
            if rule:
                self.rules.append(rule)
                self.sid_counter += 1

        print(f"[*] Generated {len(self.rules)} Snort3 rules")
        return self.rules

    def _create_snort_rule(self, flow):
        """Create a Snort3 rule from flow info"""
        try:
            # Snort3 rule format:
            # alert tcp SRC_IP SRC_PORT -> DST_IP DST_PORT (msg:"Attack"; sid:X; rev:1;)

            protocol = flow['protocol']
            src_ip = flow['src_ip'] if flow['src_ip'] else 'any'
            dst_ip = flow['dst_ip'] if flow['dst_ip'] else 'any'
            src_port = flow['src_port'] if flow['src_port'] else 'any'
            dst_port = flow['dst_port'] if flow['dst_port'] else 'any'
            label = flow['label'].replace('"', '').replace("'", '')

            rule = (
                f"alert {protocol} {src_ip} {src_port} -> {dst_ip} {dst_port} "
                f'(msg:"CHEAT RULE: {label}"; sid:{self.sid_counter}; rev:1;)'
            )

            return rule
        except Exception as e:
            print(f"[!] Error creating rule: {e}")
            return None

    def save_rules(self, output_path):
        """Save rules to file"""
        print(f"[*] Saving rules to {output_path}")

        with open(output_path, 'w') as f:
            # Write header
            f.write("# Snort3 Cheat Rules\n")
            f.write(f"# Generated from {self.dataset_type} ground truth\n")
            f.write(f"# Total rules: {len(self.rules)}\n")
            f.write("#\n\n")

            for rule in self.rules:
                f.write(rule + "\n")

        print(f"[*] Saved {len(self.rules)} rules to {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Generate Snort3 cheat rules from ground truth')
    parser.add_argument('--dataset', required=True, choices=['unsw_nb15', 'cicids2017'],
                       help='Dataset type')
    parser.add_argument('--csv', required=True, help='Path to ground truth CSV file')
    parser.add_argument('--output', required=True, help='Output rules file path')
    parser.add_argument('--max-rules', type=int, default=10000,
                       help='Maximum number of rules to generate (default: 10000)')

    args = parser.parse_args()

    # Create generator
    generator = CheatRuleGenerator(args.dataset)

    # Parse CSV based on dataset type
    if args.dataset == 'unsw_nb15':
        attack_flows = generator.parse_unsw_nb15(args.csv)
    elif args.dataset == 'cicids2017':
        attack_flows = generator.parse_cicids2017(args.csv)
    else:
        print(f"[!] Unknown dataset type: {args.dataset}")
        sys.exit(1)

    if not attack_flows:
        print("[!] No attack flows found in CSV!")
        sys.exit(1)

    # Generate rules
    generator.generate_rules(attack_flows, max_rules=args.max_rules)

    # Save rules
    generator.save_rules(args.output)

    print(f"\n[✓] Done! Generated {len(generator.rules)} cheat rules")
    print(f"[*] Use with: snort3 -c snort.lua -R {args.output} -r pcap_file.pcap")

if __name__ == '__main__':
    main()

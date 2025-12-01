#!/usr/bin/env python3
"""
Ground Truth Matcher

Matches IDS alerts to ground truth labels for calculating classification metrics.

Matching Strategy:
1. Primary: 5-tuple (src_ip, src_port, dst_ip, dst_port, protocol) + time window
2. Bidirectional: Try both directions (A->B and B->A)
3. Fallback: Feature-based matching if timestamps unavailable

Outputs:
- True Positives (TP): Alert fired and ground truth is attack
- False Positives (FP): Alert fired but ground truth is benign
- False Negatives (FN): No alert but ground truth is attack
- True Negatives (TN): No alert and ground truth is benign

Usage:
    python3 match_alerts_to_groundtruth.py --alerts parsed_alerts.json \
                                           --groundtruth dataset.csv \
                                           --dataset unsw_nb15 \
                                           --output matched_results.json
"""

import json
import csv
import argparse
import sys
from datetime import datetime, timedelta
from collections import defaultdict

class GroundTruthMatcher:
    def __init__(self, dataset_type, time_window=5):
        self.dataset_type = dataset_type
        self.time_window = time_window  # seconds
        self.alerts = []
        self.ground_truth = []
        self.matched_results = {
            'tp': [],  # True Positives
            'fp': [],  # False Positives
            'fn': [],  # False Negatives
            'tn_count': 0,  # True Negatives (count only, too many to store)
        }

    def load_alerts(self, alerts_path):
        """Load parsed alerts from JSON"""
        print(f"[*] Loading alerts from: {alerts_path}")

        with open(alerts_path, 'r') as f:
            self.alerts = json.load(f)

        print(f"[*] Loaded {len(self.alerts)} alerts")

    def load_ground_truth(self, csv_path):
        """Load ground truth CSV based on dataset type"""
        print(f"[*] Loading ground truth from: {csv_path}")
        print(f"[*] Dataset type: {self.dataset_type}")

        if self.dataset_type == 'unsw_nb15':
            self._load_unsw_nb15(csv_path)
        elif self.dataset_type == 'cicids2017':
            self._load_cicids2017(csv_path)
        elif self.dataset_type == 'ton_iot':
            self._load_ton_iot(csv_path)
        else:
            raise ValueError(f"Unknown dataset type: {self.dataset_type}")

        print(f"[*] Loaded {len(self.ground_truth)} ground truth records")

    def _load_unsw_nb15(self, csv_path):
        """Load UNSW-NB15 ground truth CSV"""
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)

            for row in reader:
                try:
                    # UNSW-NB15 format (no header):
                    # 0:srcip, 1:sport, 2:dstip, 3:dsport, 4:proto
                    # 28:Stime (start timestamp), 47:attack_cat, 48:Label (0=normal, 1=attack)
                    if len(row) < 49:
                        continue  # Skip incomplete rows

                    label_flag = row[48].strip()
                    attack_cat = row[47].strip()

                    # Determine if attack and label
                    is_attack = (label_flag == '1')
                    label = attack_cat if attack_cat else 'normal'

                    record = {
                        'src_ip': row[0].strip(),
                        'dst_ip': row[2].strip(),
                        'src_port': int(row[1].strip()),
                        'dst_port': int(row[3].strip()),
                        'protocol': self._parse_protocol(row[4].strip()),
                        'label': label,
                        'is_attack': is_attack,
                        'timestamp': row[28].strip() if len(row) > 28 else '',
                    }

                    # Parse timestamp if available
                    if record['timestamp']:
                        try:
                            record['parsed_timestamp'] = float(record['timestamp'])
                        except:
                            record['parsed_timestamp'] = None
                    else:
                        record['parsed_timestamp'] = None

                    self.ground_truth.append(record)

                except Exception as e:
                    # Skip malformed rows
                    continue

    def _load_cicids2017(self, csv_path):
        """Load CIC-IDS2017 ground truth CSV"""
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)

            for row in reader:
                try:
                    # CIC-IDS2017 column names often have leading spaces
                    label = row.get(' Label', row.get('Label', 'BENIGN')).strip()

                    record = {
                        'src_ip': row.get(' Source IP', row.get('Source IP', '')).strip(),
                        'dst_ip': row.get(' Destination IP', row.get('Destination IP', '')).strip(),
                        'src_port': int(row.get(' Source Port', row.get('Source Port', 0))),
                        'dst_port': int(row.get(' Destination Port', row.get('Destination Port', 0))),
                        'protocol': self._parse_protocol(row.get(' Protocol', row.get('Protocol', '6'))),
                        'label': label,
                        'is_attack': label.upper() not in ['BENIGN', 'NORMAL', ''],
                        'timestamp': row.get(' Timestamp', row.get('Timestamp', '')),
                    }

                    # Parse timestamp
                    if record['timestamp']:
                        try:
                            # CIC-IDS2017 format: "DD/MM/YYYY HH:MM:SS"
                            record['parsed_timestamp'] = datetime.strptime(
                                record['timestamp'], '%d/%m/%Y %H:%M:%S'
                            ).timestamp()
                        except:
                            record['parsed_timestamp'] = None
                    else:
                        record['parsed_timestamp'] = None

                    self.ground_truth.append(record)

                except Exception as e:
                    continue

    def _load_ton_iot(self, csv_path):
        """Load Ton-IoT ground truth CSV"""
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)

            for row in reader:
                try:
                    attack_flag = row.get('attack_flag', '0').strip()

                    record = {
                        'src_ip': row.get('src_ip', '').strip(),
                        'dst_ip': row.get('dst_ip', '').strip(),
                        'src_port': int(row.get('l4_src_port', row.get('src_port', 0))),
                        'dst_port': int(row.get('l4_dst_port', row.get('dst_port', 0))),
                        'protocol': self._parse_protocol(row.get('protocol', '6')),
                        'label': row.get('attack_name', 'benign').strip().lower(),
                        'is_attack': attack_flag == '1',
                        'timestamp': row.get('timestamp', ''),
                    }

                    # Parse timestamp if available
                    if record['timestamp']:
                        try:
                            record['parsed_timestamp'] = float(record['timestamp'])
                        except:
                            record['parsed_timestamp'] = None
                    else:
                        record['parsed_timestamp'] = None

                    self.ground_truth.append(record)

                except Exception as e:
                    continue

    def _parse_protocol(self, proto_str):
        """Parse protocol number or name to standard name"""
        proto_str = str(proto_str).strip().lower()

        # If already a name, return it
        if proto_str in ['tcp', 'udp', 'icmp', 'ip']:
            return proto_str

        # Otherwise convert number to name
        proto_map = {
            '6': 'tcp',
            '17': 'udp',
            '1': 'icmp',
            '58': 'icmp',  # ICMPv6
        }

        return proto_map.get(proto_str, 'ip')  # Default to 'ip'

    def match_alerts(self):
        """Match alerts to ground truth records"""
        print(f"[*] Matching {len(self.alerts)} alerts to {len(self.ground_truth)} ground truth records")

        # Build 5-tuple index for ground truth for fast lookup
        gt_index = defaultdict(list)
        for idx, record in enumerate(self.ground_truth):
            key = self._create_flow_key(
                record['src_ip'], record['src_port'],
                record['dst_ip'], record['dst_port'],
                record['protocol']
            )
            gt_index[key].append(idx)

            # Also index reverse direction
            reverse_key = self._create_flow_key(
                record['dst_ip'], record['dst_port'],
                record['src_ip'], record['src_port'],
                record['protocol']
            )
            gt_index[reverse_key].append(idx)

        # Track which ground truth records have been matched
        matched_gt_indices = set()

        # Match each alert
        for alert in self.alerts:
            matched_record = self._find_matching_gt(alert, gt_index, matched_gt_indices)

            if matched_record:
                # Mark this ground truth record as matched
                gt_idx = self.ground_truth.index(matched_record)
                matched_gt_indices.add(gt_idx)

                if matched_record['is_attack']:
                    # True Positive: Alert fired and it's an attack
                    self.matched_results['tp'].append({
                        'alert': alert,
                        'ground_truth': matched_record,
                    })
                else:
                    # False Positive: Alert fired but it's benign
                    self.matched_results['fp'].append({
                        'alert': alert,
                        'ground_truth': matched_record,
                    })
            else:
                # No matching ground truth found - likely False Positive
                # (Alert fired but no corresponding traffic in ground truth)
                self.matched_results['fp'].append({
                    'alert': alert,
                    'ground_truth': None,
                })

        # Find False Negatives: Attack in ground truth but no alert
        for idx, record in enumerate(self.ground_truth):
            if idx not in matched_gt_indices and record['is_attack']:
                self.matched_results['fn'].append({
                    'alert': None,
                    'ground_truth': record,
                })

        # Calculate True Negatives: Benign flows with no alerts
        total_benign = sum(1 for r in self.ground_truth if not r['is_attack'])
        benign_with_alerts = sum(1 for match in self.matched_results['fp'] if match['ground_truth'])
        self.matched_results['tn_count'] = total_benign - benign_with_alerts

        # Print summary
        self._print_matching_summary()

    def _create_flow_key(self, src_ip, src_port, dst_ip, dst_port, protocol):
        """Create a unique key for flow matching"""
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"

    def _find_matching_gt(self, alert, gt_index, matched_gt_indices):
        """Find matching ground truth record for an alert"""
        # Try forward direction
        key = self._create_flow_key(
            alert['src_ip'], alert['src_port'],
            alert['dst_ip'], alert['dst_port'],
            alert['protocol']
        )

        candidates = gt_index.get(key, [])

        # Filter candidates based on matching criteria
        for idx in candidates:
            if idx in matched_gt_indices:
                continue  # Already matched

            record = self.ground_truth[idx]

            # Check if 5-tuple matches exactly
            if (alert['src_ip'] == record['src_ip'] and
                alert['src_port'] == record['src_port'] and
                alert['dst_ip'] == record['dst_ip'] and
                alert['dst_port'] == record['dst_port'] and
                alert['protocol'] == record['protocol']):

                # If timestamps available, check time window
                if alert.get('parsed_timestamp') and record.get('parsed_timestamp'):
                    time_diff = abs(alert['parsed_timestamp'] - record['parsed_timestamp'])
                    if time_diff <= self.time_window:
                        return record
                else:
                    # No timestamp - accept 5-tuple match
                    return record

            # Check bidirectional match (alert A->B matches record B->A)
            if (alert['src_ip'] == record['dst_ip'] and
                alert['src_port'] == record['dst_port'] and
                alert['dst_ip'] == record['src_ip'] and
                alert['dst_port'] == record['src_port'] and
                alert['protocol'] == record['protocol']):

                # If timestamps available, check time window
                if alert.get('parsed_timestamp') and record.get('parsed_timestamp'):
                    time_diff = abs(alert['parsed_timestamp'] - record['parsed_timestamp'])
                    if time_diff <= self.time_window:
                        return record
                else:
                    # No timestamp - accept bidirectional match
                    return record

        return None

    def _print_matching_summary(self):
        """Print matching statistics"""
        tp_count = len(self.matched_results['tp'])
        fp_count = len(self.matched_results['fp'])
        fn_count = len(self.matched_results['fn'])
        tn_count = self.matched_results['tn_count']

        total = tp_count + fp_count + fn_count + tn_count

        print("\n=== MATCHING RESULTS ===")
        print(f"True Positives (TP):  {tp_count}")
        print(f"False Positives (FP): {fp_count}")
        print(f"False Negatives (FN): {fn_count}")
        print(f"True Negatives (TN):  {tn_count}")
        print(f"Total:                {total}")

    def save_results(self, output_path):
        """Save matching results to JSON"""
        print(f"\n[*] Saving results to: {output_path}")

        # Convert timestamps to strings for JSON serialization
        results_json = {
            'tp': self._prepare_for_json(self.matched_results['tp']),
            'fp': self._prepare_for_json(self.matched_results['fp']),
            'fn': self._prepare_for_json(self.matched_results['fn']),
            'tn_count': self.matched_results['tn_count'],
            'summary': {
                'tp_count': len(self.matched_results['tp']),
                'fp_count': len(self.matched_results['fp']),
                'fn_count': len(self.matched_results['fn']),
                'tn_count': self.matched_results['tn_count'],
            }
        }

        with open(output_path, 'w') as f:
            json.dump(results_json, f, indent=2)

        print(f"[*] Saved to {output_path}")

    def _prepare_for_json(self, matches):
        """Prepare match list for JSON serialization"""
        json_matches = []

        for match in matches:
            json_match = {}

            if match['alert']:
                alert_copy = match['alert'].copy()
                if alert_copy.get('parsed_timestamp'):
                    alert_copy['parsed_timestamp'] = str(alert_copy['parsed_timestamp'])
                json_match['alert'] = alert_copy
            else:
                json_match['alert'] = None

            if match['ground_truth']:
                gt_copy = match['ground_truth'].copy()
                if gt_copy.get('parsed_timestamp'):
                    gt_copy['parsed_timestamp'] = str(gt_copy['parsed_timestamp'])
                json_match['ground_truth'] = gt_copy
            else:
                json_match['ground_truth'] = None

            json_matches.append(json_match)

        return json_matches

def main():
    parser = argparse.ArgumentParser(description='Match IDS alerts to ground truth labels')
    parser.add_argument('--alerts', required=True, help='Parsed alerts JSON file')
    parser.add_argument('--groundtruth', required=True, help='Ground truth CSV file')
    parser.add_argument('--dataset', required=True,
                       choices=['unsw_nb15', 'cicids2017', 'ton_iot'],
                       help='Dataset type')
    parser.add_argument('--output', required=True, help='Output JSON file')
    parser.add_argument('--time-window', type=int, default=5,
                       help='Time window for matching (seconds, default: 5)')

    args = parser.parse_args()

    # Create matcher
    matcher = GroundTruthMatcher(args.dataset, time_window=args.time_window)

    # Load data
    try:
        matcher.load_alerts(args.alerts)
        matcher.load_ground_truth(args.groundtruth)
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error loading data: {e}")
        sys.exit(1)

    # Perform matching
    matcher.match_alerts()

    # Save results
    matcher.save_results(args.output)

    print(f"\n[✓] Done! Matched {len(matcher.alerts)} alerts to {len(matcher.ground_truth)} ground truth records")

if __name__ == '__main__':
    main()

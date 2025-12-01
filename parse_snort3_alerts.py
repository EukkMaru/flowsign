#!/usr/bin/env python3
"""
Snort3 and FlowSign Alert Parser

Parses alert output from:
1. Snort3 packet-level alerts (community rules, cheat rules)
2. FlowSign flow-level alerts
3. Combined Snort3+FlowSign output

Extracts structured data (5-tuple, timestamp, SID, message) for ground truth matching.

Usage:
    python3 parse_snort3_alerts.py --input alerts.txt --output parsed_alerts.json --format snort3
    python3 parse_snort3_alerts.py --input flowsign_alerts.txt --output parsed_alerts.json --format flowsign
"""

import re
import json
import csv
import argparse
import sys
from datetime import datetime
from collections import defaultdict

class AlertParser:
    def __init__(self, alert_format='snort3'):
        self.alert_format = alert_format
        self.alerts = []

        # Regex patterns for different alert formats
        self.patterns = {
            # [PACKET] SID:123 - msg Flow:1.2.3.4:80->5.6.7.8:443 Proto:TCP
            'custom': re.compile(
                r'\[PACKET\]\s+SID:(?P<sid>\d+)\s+-\s+(?P<msg>.*?)\s+'
                r'Flow:(?P<src_ip>[\d.]+):(?P<src_port>\d+)->(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)\s+'
                r'Proto:(?P<protocol>\w+)'
            ),

            # Standard Snort3 CSV format
            # timestamp,src_ip,src_port,dst_ip,dst_port,protocol,sid,msg
            'csv': None,  # Handle with csv.DictReader

            # Snort3 unified2 / fast alert format
            # 01/15-12:34:56.789012 [**] [1:1000:1] Attack detected [**] {TCP} 1.2.3.4:80 -> 5.6.7.8:443
            'fast': re.compile(
                r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
                r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
                r'(?P<msg>.*?)\s+\[\*\*\]\s+'
                r'\{(?P<protocol>\w+)\}\s+'
                r'(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+'
                r'(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)'
            ),

            # FlowSign alert format (standard)
            # [FLOW] SID:5001 msg:"DoS attack detected" src=1.2.3.4:80 dst=5.6.7.8:443 proto=TCP confidence=0.95
            'flowsign': re.compile(
                r'\[FLOW\]\s+SID:(?P<sid>\d+)\s+'
                r'msg:"(?P<msg>.*?)"\s+'
                r'src=(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+'
                r'dst=(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)\s+'
                r'proto=(?P<protocol>\w+)'
                r'(?:\s+confidence=(?P<confidence>[\d.]+))?'
            ),

            # FlowSign alternate format (SnortSharp actual output)
            # [FLOW] SID:5002 - Exploits - Flow-based detection Flow:14.126.171.149:80->0.176.45.175:26088 Proto:TCP
            'flowsign_alt': re.compile(
                r'\[FLOW\]\s+SID:(?P<sid>\d+)\s+-\s+(?P<msg>.*?)\s+'
                r'Flow:(?P<src_ip>[\d.]+):(?P<src_port>\d+)->(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)\s+'
                r'Proto:(?P<protocol>\w+)'
            ),
        }

    def parse_file(self, input_path):
        """Parse alert file and extract structured data"""
        print(f"[*] Parsing alerts from: {input_path}")
        print(f"[*] Format: {self.alert_format}")

        # Parse text-based alerts (including CSV lines mixed with text)
        with open(input_path, 'r') as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Try CSV format first (Snort3 alert_csv.txt format)
            if ',' in line and ':' in line:
                csv_alert = self._try_parse_snort3_csv(line, line_num)
                if csv_alert:
                    self.alerts.append(csv_alert)
                    continue

            # Try text-based patterns
            alert = self._parse_line(line, line_num)
            if alert:
                self.alerts.append(alert)

        print(f"[*] Parsed {len(self.alerts)} alerts")
        return self.alerts

    def _parse_line(self, line, line_num):
        """Parse a single alert line"""
        # Try all patterns if format is 'auto'
        patterns_to_try = []
        if self.alert_format == 'auto':
            patterns_to_try = ['custom', 'fast', 'flowsign', 'flowsign_alt']
        elif self.alert_format in self.patterns:
            patterns_to_try = [self.alert_format]
        else:
            print(f"[!] Unknown format: {self.alert_format}")
            return None

        for pattern_name in patterns_to_try:
            pattern = self.patterns.get(pattern_name)
            if not pattern:
                continue

            match = pattern.search(line)
            if match:
                alert_data = match.groupdict()

                # Add metadata
                alert_data['line_num'] = line_num
                alert_data['alert_type'] = pattern_name
                alert_data['raw_line'] = line

                # Normalize data types
                alert_data['src_port'] = int(alert_data.get('src_port', 0))
                alert_data['dst_port'] = int(alert_data.get('dst_port', 0))
                alert_data['sid'] = int(alert_data.get('sid', 0))
                alert_data['protocol'] = alert_data.get('protocol', 'tcp').lower()

                # Parse timestamp if present
                if 'timestamp' in alert_data and alert_data['timestamp']:
                    alert_data['parsed_timestamp'] = self._parse_timestamp(alert_data['timestamp'])
                else:
                    alert_data['parsed_timestamp'] = None

                # Add confidence if present
                if 'confidence' in alert_data and alert_data['confidence']:
                    alert_data['confidence'] = float(alert_data['confidence'])

                return alert_data

        # If no pattern matched
        if self.alert_format != 'auto':
            print(f"[!] Line {line_num}: Failed to parse: {line[:80]}...")

        return None

    def _try_parse_snort3_csv(self, line, line_num):
        """Try to parse Snort3 CSV format"""
        # Format: timestamp,pkt_num,proto,pkt_gen,pkt_len,dir,src_ap,dst_ap,rule,action
        try:
            parts = line.split(',')
            if len(parts) < 9:
                return None

            # Parse src_ap and dst_ap (format: IP:PORT)
            src_ap = parts[6].strip()
            dst_ap = parts[7].strip()

            src_parts = src_ap.rsplit(':', 1)
            dst_parts = dst_ap.rsplit(':', 1)

            src_ip = src_parts[0] if len(src_parts) > 0 else ''
            src_port = int(src_parts[1]) if len(src_parts) > 1 else 0
            dst_ip = dst_parts[0] if len(dst_parts) > 0 else ''
            dst_port = int(dst_parts[1]) if len(dst_parts) > 1 else 0

            # Parse rule (format: GID:SID:REV)
            rule = parts[8].strip()
            rule_parts = rule.split(':')
            sid = int(rule_parts[1]) if len(rule_parts) > 1 else 0

            alert_data = {
                'timestamp': parts[0].strip(),
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': parts[2].strip().lower(),
                'sid': sid,
                'msg': f"Snort3 rule {rule}",
                'alert_type': 'snort3_csv',
                'line_num': line_num,
                'raw_line': line
            }

            # Parse timestamp if present - convert to float for compatibility
            if alert_data['timestamp']:
                try:
                    dt = self._parse_timestamp(alert_data['timestamp'])
                    if dt:
                        alert_data['parsed_timestamp'] = dt.timestamp()
                    else:
                        alert_data['parsed_timestamp'] = None
                except:
                    alert_data['parsed_timestamp'] = None
            else:
                alert_data['parsed_timestamp'] = None

            return alert_data
        except (ValueError, IndexError):
            return None

    def _parse_csv(self, input_path):
        """Parse CSV format alerts"""
        print(f"[*] Parsing CSV format")

        with open(input_path, 'r') as f:
            reader = csv.DictReader(f)

            for row_num, row in enumerate(reader, 1):
                try:
                    alert_data = {
                        'src_ip': row.get('src_ip', row.get('source_ip', '')),
                        'dst_ip': row.get('dst_ip', row.get('destination_ip', '')),
                        'src_port': int(row.get('src_port', row.get('source_port', 0))),
                        'dst_port': int(row.get('dst_port', row.get('destination_port', 0))),
                        'protocol': row.get('protocol', 'tcp').lower(),
                        'sid': int(row.get('sid', row.get('signature_id', 0))),
                        'msg': row.get('msg', row.get('message', '')),
                        'timestamp': row.get('timestamp', ''),
                        'line_num': row_num,
                        'alert_type': 'csv',
                        'raw_line': str(row)
                    }

                    # Parse timestamp
                    if alert_data['timestamp']:
                        alert_data['parsed_timestamp'] = self._parse_timestamp(alert_data['timestamp'])
                    else:
                        alert_data['parsed_timestamp'] = None

                    self.alerts.append(alert_data)

                except Exception as e:
                    print(f"[!] Row {row_num}: Failed to parse: {e}")
                    continue

        print(f"[*] Parsed {len(self.alerts)} CSV alerts")
        return self.alerts

    def _parse_timestamp(self, timestamp_str):
        """Parse various timestamp formats"""
        # Try multiple formats
        formats = [
            '%m/%d-%H:%M:%S.%f',  # 01/15-12:34:56.789012
            '%Y-%m-%d %H:%M:%S.%f',  # 2024-01-15 12:34:56.789012
            '%Y-%m-%d %H:%M:%S',  # 2024-01-15 12:34:56
            '%s.%f',  # Unix timestamp with microseconds
            '%s',  # Unix timestamp
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue

        # If all parsing fails, return None
        return None

    def save_json(self, output_path):
        """Save parsed alerts to JSON"""
        print(f"[*] Saving {len(self.alerts)} alerts to JSON: {output_path}")

        # Convert datetime objects to strings
        alerts_json = []
        for alert in self.alerts:
            alert_copy = alert.copy()
            if alert_copy.get('parsed_timestamp'):
                if isinstance(alert_copy['parsed_timestamp'], float):
                    # Already a float, keep as is
                    pass
                elif hasattr(alert_copy['parsed_timestamp'], 'isoformat'):
                    # It's a datetime, convert to string
                    alert_copy['parsed_timestamp'] = alert_copy['parsed_timestamp'].isoformat()
            alerts_json.append(alert_copy)

        with open(output_path, 'w') as f:
            json.dump(alerts_json, f, indent=2)

        print(f"[*] Saved to {output_path}")

    def save_csv(self, output_path):
        """Save parsed alerts to CSV"""
        print(f"[*] Saving {len(self.alerts)} alerts to CSV: {output_path}")

        if not self.alerts:
            print("[!] No alerts to save")
            return

        # Define CSV columns
        columns = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
                   'sid', 'msg', 'timestamp', 'alert_type', 'line_num']

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()

            for alert in self.alerts:
                # Convert timestamp to string
                row = alert.copy()
                if row.get('parsed_timestamp'):
                    row['timestamp'] = row['parsed_timestamp'].isoformat()

                writer.writerow(row)

        print(f"[*] Saved to {output_path}")

    def print_summary(self):
        """Print summary statistics"""
        print("\n=== ALERT PARSING SUMMARY ===")
        print(f"Total Alerts: {len(self.alerts)}")

        if not self.alerts:
            return

        # Count by alert type
        type_counts = defaultdict(int)
        for alert in self.alerts:
            type_counts[alert.get('alert_type', 'unknown')] += 1

        print("\nAlerts by Type:")
        for alert_type, count in sorted(type_counts.items()):
            print(f"  {alert_type}: {count}")

        # Count by protocol
        proto_counts = defaultdict(int)
        for alert in self.alerts:
            proto_counts[alert.get('protocol', 'unknown')] += 1

        print("\nAlerts by Protocol:")
        for protocol, count in sorted(proto_counts.items()):
            print(f"  {protocol}: {count}")

        # Count by SID (top 10)
        sid_counts = defaultdict(int)
        for alert in self.alerts:
            sid_counts[alert.get('sid', 0)] += 1

        print("\nTop 10 Alert SIDs:")
        for sid, count in sorted(sid_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            # Find a message for this SID
            msg = next((a['msg'] for a in self.alerts if a.get('sid') == sid), 'Unknown')
            print(f"  SID {sid}: {count} alerts - {msg[:60]}")

def main():
    parser = argparse.ArgumentParser(description='Parse Snort3 and FlowSign alert files')
    parser.add_argument('--input', required=True, help='Input alert file')
    parser.add_argument('--output', required=True, help='Output file (JSON or CSV)')
    parser.add_argument('--format', default='auto',
                       choices=['auto', 'snort3', 'custom', 'fast', 'flowsign', 'csv'],
                       help='Alert format (default: auto-detect)')
    parser.add_argument('--summary', action='store_true', help='Print summary statistics')

    args = parser.parse_args()

    # Determine output format from extension
    output_format = 'json'
    if args.output.endswith('.csv'):
        output_format = 'csv'

    # Create parser
    alert_parser = AlertParser(alert_format=args.format)

    # Parse alerts
    try:
        alert_parser.parse_file(args.input)
    except FileNotFoundError:
        print(f"[!] Error: Input file not found: {args.input}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error parsing file: {e}")
        sys.exit(1)

    # Save output
    if output_format == 'json':
        alert_parser.save_json(args.output)
    else:
        alert_parser.save_csv(args.output)

    # Print summary if requested
    if args.summary:
        alert_parser.print_summary()

    print(f"\n[✓] Done! Parsed {len(alert_parser.alerts)} alerts")

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Resource monitoring script for IDS performance analysis.
Monitors CPU% and Memory% usage over time for a given process.
Outputs to CSV with timestamp, CPU%, Memory%, RSS(MB).
"""

import psutil
import time
import sys
import csv
import argparse
from datetime import datetime

def monitor_process(pid, output_csv, interval=0.1):
    """
    Monitor a process and log CPU% and Memory% over time.

    Args:
        pid: Process ID to monitor
        output_csv: Output CSV file path
        interval: Sampling interval in seconds (default 0.1s = 100ms)
    """
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        print(f"Error: Process {pid} does not exist", file=sys.stderr)
        return

    # Get system total memory for percentage calculation
    total_memory_mb = psutil.virtual_memory().total / (1024 * 1024)

    print(f"Monitoring PID {pid}: {process.name()}")
    print(f"Output: {output_csv}")
    print(f"Sampling interval: {interval}s")
    print(f"Total system memory: {total_memory_mb:.2f} MB")
    print("Starting monitoring... (Press Ctrl+C to stop)")

    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'elapsed_sec', 'cpu_percent', 'memory_percent', 'rss_mb', 'num_threads']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        start_time = time.time()
        sample_count = 0

        try:
            while True:
                try:
                    # Check if process still exists
                    if not process.is_running():
                        print(f"\nProcess {pid} terminated. Total samples: {sample_count}")
                        break

                    # Get current metrics
                    current_time = time.time()
                    elapsed = current_time - start_time

                    # CPU percent (over interval period)
                    cpu_percent = process.cpu_percent(interval=None)

                    # Memory info
                    mem_info = process.memory_info()
                    rss_mb = mem_info.rss / (1024 * 1024)
                    memory_percent = (mem_info.rss / (total_memory_mb * 1024 * 1024)) * 100

                    # Thread count
                    num_threads = process.num_threads()

                    # Write to CSV
                    writer.writerow({
                        'timestamp': datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                        'elapsed_sec': f'{elapsed:.3f}',
                        'cpu_percent': f'{cpu_percent:.2f}',
                        'memory_percent': f'{memory_percent:.2f}',
                        'rss_mb': f'{rss_mb:.2f}',
                        'num_threads': num_threads
                    })

                    sample_count += 1

                    # Print progress every 50 samples
                    if sample_count % 50 == 0:
                        print(f"Samples: {sample_count}, Elapsed: {elapsed:.1f}s, CPU: {cpu_percent:.1f}%, Mem: {rss_mb:.1f}MB")

                    # Sleep until next interval
                    time.sleep(interval)

                except psutil.NoSuchProcess:
                    print(f"\nProcess {pid} terminated. Total samples: {sample_count}")
                    break

        except KeyboardInterrupt:
            print(f"\nMonitoring stopped by user. Total samples: {sample_count}")

    print(f"Data saved to: {output_csv}")

    # Print summary statistics
    import pandas as pd
    df = pd.read_csv(output_csv)
    print("\nSummary Statistics:")
    print(f"Duration: {df['elapsed_sec'].max():.2f} seconds")
    print(f"CPU%  - Mean: {df['cpu_percent'].mean():.2f}%, Max: {df['cpu_percent'].max():.2f}%, Std: {df['cpu_percent'].std():.2f}%")
    print(f"Memory - Mean: {df['rss_mb'].mean():.2f}MB, Max: {df['rss_mb'].max():.2f}MB, Std: {df['rss_mb'].std():.2f}MB")
    print(f"Memory% - Mean: {df['memory_percent'].mean():.2f}%, Max: {df['memory_percent'].max():.2f}%")

def monitor_command(command, output_csv, interval=0.1):
    """
    Launch a command and monitor its resource usage.

    Args:
        command: Command string to execute
        output_csv: Output CSV file path
        interval: Sampling interval in seconds
    """
    import subprocess

    print(f"Launching command: {command}")
    print(f"Output: {output_csv}")

    # Start the process
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pid = process.pid

    print(f"Process started with PID: {pid}")

    # Monitor the process
    monitor_process(pid, output_csv, interval)

    # Wait for process to complete and get output
    stdout, stderr = process.communicate()
    returncode = process.returncode

    print(f"\nProcess exited with code: {returncode}")

    return returncode, stdout, stderr

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor process resource usage over time')
    parser.add_argument('--pid', type=int, help='Process ID to monitor')
    parser.add_argument('--command', type=str, help='Command to launch and monitor')
    parser.add_argument('--output', type=str, required=True, help='Output CSV file path')
    parser.add_argument('--interval', type=float, default=0.1, help='Sampling interval in seconds (default: 0.1)')

    args = parser.parse_args()

    if args.pid:
        monitor_process(args.pid, args.output, args.interval)
    elif args.command:
        monitor_command(args.command, args.output, args.interval)
    else:
        parser.error("Either --pid or --command must be specified")

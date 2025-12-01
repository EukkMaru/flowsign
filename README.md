# SnortSharp Flow Analyzer

A rolling window flow-based network intrusion detection framework designed to complement Snort's packet-based analysis.

## Overview

This framework implements a circular queue-based rolling window approach for calculating flow-level features compatible with CICFlowMeter. It's designed to be integrated with Snort as a separate thread that processes flow statistics in parallel with Snort's packet-level detection.

## Features

- **Rolling Window Analysis**: Configurable window size and step size for real-time feature calculation
- **CICFlowMeter Compatibility**: Implements all 91+ flow features from CICFlowMeter
- **Bidirectional Flow Tracking**: Separates forward and backward direction statistics
- **Memory Efficient**: Circular queue implementation with configurable capacity
- **Thread-Safe Design**: Designed for parallel execution alongside Snort

## Architecture

```
Snort Packet Processing ──┬── Traditional Rule Matching
                         │
                         └── memcpy() packet data ──► Flow Analyzer Thread
                                                      │
                                                      ├── Circular Queue
                                                      ├── Rolling Window
                                                      └── Feature Calculation
```

## Key Components

### 1. Packet Abstraction (`packet_info_t`)
- Timestamp, IPs, ports, protocol
- Packet/payload lengths, TCP flags
- Direction classification (forward/backward)
- Window sizes for TCP flows

### 2. Flow Features (`flow_features_t`)
- Duration and timing statistics (IAT - Inter-Arrival Time)
- Packet/byte counts and lengths (min/max/mean/std)
- Direction-specific statistics
- TCP flag counters
- Flow rates and ratios

### 3. Circular Queue (`circular_queue_t`)
- Configurable capacity and window size
- Rolling window with step-based updates
- Memory-efficient packet storage

### 4. Flow Analyzer (`flow_analyzer_t`)
- Main processing engine
- Feature calculation on window updates
- Flow state management

## Usage

```c
// Create analyzer with 100 packet capacity, 20 packet window, step size 1
flow_analyzer_t *analyzer = create_flow_analyzer(100, 20, 1);

// Process packets (typically from Snort via memcpy)
packet_info_t packet = /* ... packet data from Snort ... */;
flow_features_t features;

if (process_packet(analyzer, &packet, &features)) {
    // New window completed - features calculated
    // Apply flow-based rules here
    apply_flow_rules(&features);
}
```

## Build Instructions

```bash
make all       # Build library and test
make test      # Run test program
make clean     # Clean build files
```

## Integration with Snort

The integration plan involves:

1. **Snort Modification**: Add hooks in Snort's packet processing pipeline
2. **Memory Copy**: Use `memcpy()` to copy packet abstractions (avoid dangling pointers)
3. **Thread Management**: Run flow analyzer in separate thread
4. **Rule Engine**: Implement flow-based rule matching parallel to packet rules
5. **Decision Fusion**: Combine packet and flow-based detection results

## Flow Features Implemented

Based on CICFlowMeter specification, including:

- **Basic Stats**: Duration, packet counts, byte counts
- **Packet Lengths**: Min/max/mean/std for forward/backward/overall
- **Inter-Arrival Times**: Timing statistics between packets
- **TCP Flags**: Counts of SYN, ACK, FIN, RST, PSH, URG, CWR, ECE
- **Flow Rates**: Bytes/sec, packets/sec
- **Directional Stats**: Separate forward and backward analysis
- **Advanced Features**: Bulk rates, segment sizes, window sizes

## Performance Considerations

- **Memory**: O(window_size) memory per flow
- **Computation**: O(window_size) per feature calculation
- **Threading**: Designed for concurrent execution with Snort
- **Real-time**: Features calculated incrementally as packets arrive

## Future Extensions

1. **Rule Language**: Flow-based rule syntax (e.g., "mean_iat > 1000ms")
2. **ML Integration**: Support for AI/ML model inference on features
3. **Encrypted Traffic**: Enhanced analysis for TLS/encrypted flows
4. **Multi-flow Correlation**: Cross-flow pattern detection
5. **Performance Optimization**: SIMD instructions, memory pools

## Testing

The test program simulates a TCP connection with varying packet sizes and timing, demonstrating:
- 3-way handshake (SYN, SYN-ACK, ACK)
- Data exchange with varying sizes
- Connection teardown (FIN packets)
- Real-time feature calculation as packets arrive

Run `make test` to see the analyzer in action.
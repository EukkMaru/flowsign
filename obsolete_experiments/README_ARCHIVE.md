# Obsolete Experiments Archive

This directory contains experiments and results from the period when we attempted PCAP format conversion approaches, which were later superseded by implementing a native Linux Cooked Capture codec for Snort3.

## Timeline of Archived Work

### Phase 1: PCAP Conversion Attempts (Nov 17, 2024)
**Problem**: UNSW-NB15 PCAPs use Linux cooked capture format (DLT 113) which Snort3 couldn't decode
**Attempted Solutions**:
1. Python-based PCAP conversion using scapy (failed - OOM on 1.9GB files)
2. Streaming PCAP conversion using scapy (failed - created invalid LLC frames)
3. tcprewrite conversion tool (failed - created invalid packets with `[|llc]` errors)

### Phase 2: Native Codec Implementation (Nov 17, 2024)
**Solution**: Implemented `cd_linux_sll.cc` codec directly in Snort3
**Result**: Successfully decodes original UNSW-NB15 PCAPs without conversion

## Archived Components

### Conversion Scripts (Deleted)
- `convert_sll_to_ethernet.py` - Non-streaming scapy converter
- `convert_sll_to_ethernet_streaming.py` - Streaming scapy converter
- `convert_pcap_dlt.py` - Alternative DLT converter
- `convert_all_pcaps.sh` - Batch conversion script
- `convert_unsw_pcaps.sh` - UNSW-specific conversion script

### Experiment Scripts (Deleted)
All CSV-based and old PCAP-based experiment scripts that preceded the proper Snort3 integration.

### Experiment Results (Archived)
- `experiment_results/` subdirectories - Various CSV-based evaluation attempts
- `snort3_results/` - Results from pre-codec experiments
- CSV/JSON result files - Attack classification results from obsolete experiments

### Documentation (Deleted)
- 42 markdown files documenting obsolete experiments
- Kept: CLAUDE.md, README.md, DEPENDENCIES.md, dev.md, exp1_guideline.md

## Why This Work Was Obsolete

The PCAP conversion approach was fundamentally flawed because:
1. Conversion tools couldn't properly reconstruct Ethernet frames from Linux cooked format
2. Memory limitations prevented processing large PCAP files
3. Even when conversions completed, they created malformed packets

The native codec implementation:
- Processes original PCAPs without modification
- Strips 16-byte Linux cooked header cleanly
- Passes proper IP packets to Snort3's processing pipeline
- Successfully extracts real IP addresses (e.g., `14.126.171.149:80`)

## Current State (Post-Cleanup)

### Active Components
- Core source files (flow_analyzer, flow_rules, snortsharp_integration, etc.)
- Snort3 integration (parallel_snort_integration.cpp with Linux SLL codec)
- Rule generation (generate_flowsign_rules.py)
- Test scripts (run_tests.sh, run_phase2_test.sh, test_events.sh, run_unsw_experiment.sh)
- Documentation (CLAUDE.md - comprehensive technical documentation)

### Next Steps
With the Linux SLL codec working, the next phase is:
1. Run full UNSW-NB15 PCAP experiments with proper IP extraction
2. Implement ground truth matching using flow 5-tuple
3. Calculate precision, recall, F1 scores against CSV labels
4. Compare FlowSign detection with traditional Snort3 packet-based rules

## Restoration

If any of these archived files are needed for reference, they are preserved in this directory. However, the conversion-based approach is not recommended - use the native codec implementation instead.

---
**Archive Date**: November 17, 2024
**Archive Reason**: Superseded by native Linux SLL codec implementation
**Status**: Reference only - do not use for active development

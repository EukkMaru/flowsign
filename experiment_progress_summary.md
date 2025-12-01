# Experiment Progress Summary

## Completed Tasks

### Phase 1: Rule Generation

#### UNSW-NB15 Dataset
- ✅ Flow rules (FlowSign): **527 rules** (depth=10)
  - File: `snortsharp-rules/unsw_flowsign_rules_depth10.txt`
  - Attack categories: Exploits, Reconnaissance, DoS, Generic, Shellcode, Fuzzers, Worms, Backdoors, Analysis
  
- ✅ Packet rules (Snort3): **8,000 rules** (consolidated)
  - Files: `snortsharp-rules/unsw_snort3_cheat_consolidated.rules`
  - Source: UNSW-NB15_1.csv + UNSW-NB15_2.csv

#### CIC-IDS-2017 Dataset  
- ✅ Flow rules (FlowSign): **234 rules** (depth=10)
  - File: `snortsharp-rules/cicids2017_flowsign_rules_depth10.txt`
  - Attack categories: PortScan, DDoS, Bot, DoS variants, FTP-Patator, SSH-Patator, Web Attacks

- ⏳ Packet rules (Snort3): **Pending**

#### TON-IoT Dataset
- ⏳ Flow rules: **Pending**
- ⏳ Packet rules: **Pending**

### Phase 2: Resource Monitoring Infrastructure

- ✅ Resource limiter script: `run_with_resource_limits.sh`
  - Enforces Raspberry Pi 4 constraints (4 cores, 4GB RAM)
  - Uses cgroups v2 / systemd-run
  - Monitors: CPU cycles, memory, cache misses, page faults

- ✅ Experiment runner: `run_experiment3_full.sh`
  - Tests 3 IDS configurations:
    1. Vanilla Snort3 with community rules
    2. Vanilla Snort3 with cheat packet rules  
    3. Snort3+FlowSign hybrid (community + flow rules)
  - Applies resource limits to all tests
  - Logs all performance metrics

## Pending Tasks

### Experiment 3
1. Generate TON-IoT rules (flow + packet)
2. Generate CIC-IDS-2017 packet rules
3. Test resource limiter with sample PCAP
4. Run full experiment on all datasets
5. Test DL-based IDS baselines (from baselines/ and ai-ids-analyzer/)

### Experiment 2 (VPN Dataset)
1. Understand VPN dataset structure (ARFF format)
2. Generate flow + packet rules for VPN dataset
3. Run three-way comparison:
   - Vanilla Snort with community rules
   - Vanilla Snort with cheat packet rules
   - Snort+FlowSign hybrid

## Next Steps

1. **Test resource limiter** with a sample PCAP to verify it works
2. **Generate remaining rules** (TON-IoT, CIC-IDS-2017 packets)
3. **Run Experiment 3** with resource profiling
4. **Process VPN dataset** for Experiment 2
5. **Analyze results** and generate comparison tables


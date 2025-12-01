#!/bin/bash
###############################################################################
# Quick test to verify Experiment 3 setup
###############################################################################

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Testing Experiment 3 Setup ===${NC}"

# Test 1: Check Snort binary
echo -e "${GREEN}[1/5] Checking Snort3 binary...${NC}"
if [ -f "snort3/build/src/snort" ]; then
    echo "  ✓ Snort3 binary found"
else
    echo "  ✗ Snort3 binary NOT found"
    exit 1
fi

# Test 2: Check rules
echo -e "${GREEN}[2/5] Checking generated rules...${NC}"
echo "  UNSW-NB15 flow rules: $(wc -l < snortsharp-rules/unsw_flowsign_rules_depth10.txt) lines"
echo "  UNSW-NB15 packet rules: $(wc -l < snortsharp-rules/unsw_snort3_cheat_consolidated.rules) lines"
echo "  CIC-IDS-2017 flow rules: $(wc -l < snortsharp-rules/cicids2017_flowsign_rules_depth10.txt) lines"
echo "  CIC-IDS-2017 packet rules: $(wc -l < snortsharp-rules/cicids2017_snort3_cheat.rules) lines"
echo "  TON-IoT flow rules: $(wc -l < snortsharp-rules/toniot_flowsign_rules_depth10.txt) lines"

# Test 3: Check PCAP files
echo -e "${GREEN}[3/5] Checking PCAP files...${NC}"
UNSW_PCAPS=$(find datasets/UNSW-NB15/pcap_files -name "*.pcap" | wc -l)
CICIDS_PCAPS=$(find datasets/CIC-IDS-2017/PCAPs -name "*.pcap" | wc -l)
echo "  UNSW-NB15 PCAPs: $UNSW_PCAPS files"
echo "  CIC-IDS-2017 PCAPs: $CICIDS_PCAPS files"

# Test 4: Check community rules
echo -e "${GREEN}[4/5] Checking Snort3 community rules...${NC}"
if [ -f "snort3-community-rules/snort3-community.rules" ]; then
    echo "  ✓ Community rules found ($(wc -l < snort3-community-rules/snort3-community.rules) lines)"
else
    echo "  ✗ Community rules NOT found"
fi

# Test 5: Test systemd-run resource limiter
echo -e "${GREEN}[5/5] Testing resource limiter...${NC}"
if command -v systemd-run &> /dev/null; then
    echo "  ✓ systemd-run available"

    # Quick test
    OUTPUT=$(systemd-run --user --scope -p CPUQuota=400% -p MemoryMax=4G -- \
        /home/maru/work/snortsharp/snort3/build/src/snort --version 2>&1 | grep "Version" || true)

    if [ -n "$OUTPUT" ]; then
        echo "  ✓ Resource limiter test passed"
    else
        echo "  ⚠ Resource limiter test failed (may need manual check)"
    fi
else
    echo "  ✗ systemd-run NOT available"
fi

echo ""
echo -e "${BLUE}=== Setup Verification Complete ===${NC}"
echo ""
echo "Ready to run experiments!"
echo ""
echo "Next steps:"
echo "  1. Run quick experiment: ./run_quick_experiment.sh"
echo "  2. Run full experiment: ./run_experiment3_full.sh"

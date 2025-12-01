#!/bin/bash

echo "SnortSharp Event System Test"
echo "============================"
echo

# Check if programs exist
if [ ! -f "./proc1_test" ] || [ ! -f "./proc2_test_events" ]; then
    echo "Error: Programs not found. Please run 'make proc1_test proc2_test_events' first."
    exit 1
fi

# Clean up any existing pipe
rm -f /tmp/snortsharp_events

echo "1. Starting Rule Engine (Event Server) in background..."
./proc2_test_events > /tmp/proc2_output.log 2>&1 &
PROC2_PID=$!

# Give server time to start
sleep 2

echo "2. Checking if server started successfully..."
if ! kill -0 $PROC2_PID 2>/dev/null; then
    echo "Error: Rule Engine failed to start"
    cat /tmp/proc2_output.log
    exit 1
fi

echo "3. Starting Flow Analyzer (Event Broadcaster)..."
./proc1_test > /tmp/proc1_output.log 2>&1 &
PROC1_PID=$!

# Let them run for a bit
echo "4. Letting programs communicate for 10 seconds..."
sleep 10

echo "5. Stopping programs..."
kill $PROC1_PID 2>/dev/null
kill $PROC2_PID 2>/dev/null

# Wait a moment for cleanup
sleep 1

echo "6. Output from Rule Engine (Server):"
echo "===================================="
head -n 20 /tmp/proc2_output.log
echo "... (truncated)"
echo

echo "7. Output from Flow Analyzer (Client):"
echo "======================================"
head -n 20 /tmp/proc1_output.log
echo "... (truncated)"
echo

echo "8. Test completed!"
echo
echo "Full logs available at:"
echo "  - Rule Engine: /tmp/proc2_output.log"
echo "  - Flow Analyzer: /tmp/proc1_output.log"

# Clean up
rm -f /tmp/snortsharp_events
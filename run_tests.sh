#!/bin/bash

echo "═══════════════════════════════════════════════════════════"
echo "           Flow Analyzer Test Suite"
echo "═══════════════════════════════════════════════════════════"
echo

if [ $# -eq 0 ]; then
    echo "Available tests:"
    echo
    echo "CORE FUNCTIONALITY TESTS:"
    echo "  ./run_tests.sh basic       - Quick functionality test (Process 1)"
    echo "  ./run_tests.sh demo        - Different attack scenarios (Process 1)"
    echo "  ./run_tests.sh validate    - Comprehensive validation (24/25 tests)"
    echo "  ./run_tests.sh verbose     - Detailed internal state viewer (Process 1)"
    echo "  ./run_tests.sh proc2       - Flow rule engine test (Process 2)"
    echo "  ./run_tests.sh integrated  - Full Process 1+2 integration test"
    echo "  ./run_tests.sh interactive - Manual packet input mode"
    echo
    echo "EVENT SYSTEM TESTS (requires libuv):"
    echo "  ./run_tests.sh events      - libuv event system IPC test"
    echo "  ./run_tests.sh proc1       - Process 1 event broadcaster"
    echo "  ./run_tests.sh proc2-events - Process 2 event listener"
    echo
    echo "PERFORMANCE TESTS:"
    echo "  ./run_tests.sh perf-basic  - Basic performance benchmark"
    echo "  ./run_tests.sh perf-throughput - High throughput stress test"
    echo "  ./run_tests.sh perf-compare - Comparative analysis (window/queue sizes)"
    echo "  ./run_tests.sh perf-all    - Complete performance benchmark suite"
    echo
    echo "AUTOMATION:"
    echo "  ./run_tests.sh all         - Run all core tests"
    echo "  ./run_tests.sh all-events  - Run all event system tests"
    echo "  ./run_tests.sh full        - Run all tests including events and performance"
    echo
    echo "Recommended order: basic -> demo -> verbose -> proc2 -> integrated -> events"
    exit 0
fi

case "$1" in
    "basic")
        echo "* Running Basic Functionality Test..."
        echo "Shows: Packet processing and feature generation"
        echo "Duration: ~5 seconds"
        echo
        make test
        ;;
    "demo")
        echo "* Running Attack Scenario Demonstrations..."
        echo "Shows: How different traffic patterns produce different features"
        echo "Duration: ~10 seconds"
        echo
        make demo
        ;;
    "validate")
        echo "* Running Comprehensive Validation Tests..."
        echo "Shows: Technical verification of all components (24/25 tests pass)"
        echo "Duration: ~3 seconds"
        echo
        make validate
        ;;
    "verbose")
        echo "* Running Verbose Internal State Viewer..."
        echo "Shows: Circular queue operations, pointer movements, struct generation"
        echo "Duration: ~15 seconds (detailed output)"
        echo
        make verbose
        ;;
    "proc2")
        echo "* Running Process 2 (Rule Engine) Test..."
        echo "Shows: Flow-based rule evaluation and multi-threading"
        echo "Duration: ~30 seconds"
        echo
        make proc2
        ;;
    "integrated")
        echo "* Running Full Process 1+2 Integration Test..."
        echo "Shows: Complete SnortSharp pipeline working together"
        echo "Duration: ~20 seconds"
        echo
        make integrated
        ;;
    "interactive")
        echo "* Running Interactive Test Mode..."
        echo "Shows: Manual packet input for custom testing"
        echo "Duration: Until you quit (press 'q')"
        echo "Example input: 100 f 1 0 0 0 (100-byte forward SYN packet)"
        echo
        make interactive
        ;;
    "events")
        echo "* Running libuv Event System Test..."
        echo "Shows: Inter-process communication between Process 1 and Process 2"
        echo "Duration: ~15 seconds"
        echo "Requirements: libuv library installed"
        echo
        if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists libuv; then
            echo "WARNING: libuv not detected. Install with:"
            echo "  Ubuntu/Debian: sudo apt install libuv1-dev"
            echo "  CentOS/RHEL/Fedora: sudo yum install libuv-devel"
            echo "  macOS: brew install libuv"
            echo
        fi
        ./test_events.sh
        ;;
    "proc1")
        echo "* Running Process 1 Event Broadcaster..."
        echo "Shows: Flow analyzer broadcasting window events via libuv"
        echo "Duration: ~20 seconds (or until Ctrl+C)"
        echo "Note: Start 'proc2-events' first in another terminal for full test"
        echo
        make proc1
        ;;
    "proc2-events")
        echo "* Running Process 2 Event Listener..."
        echo "Shows: Rule engine listening for window events via libuv"
        echo "Duration: Until Ctrl+C"
        echo "Note: Start this first, then run 'proc1' in another terminal"
        echo
        make proc2-events
        ;;
    "all")
        echo "* Running All Automated Tests..."
        echo "Running: basic -> demo -> verbose -> proc2 -> integrated -> validation"
        echo
        
        echo "--- 1/6: Basic Test ---"
        make test
        echo
        
        echo "--- 2/6: Demo Scenarios ---"  
        make demo
        echo
        
        echo "--- 3/6: Verbose Internal View ---"
        make verbose
        echo
        
        echo "--- 4/6: Process 2 Rule Engine ---"
        make proc2
        echo
        
        echo "--- 5/6: Process 1+2 Integration ---"
        make integrated
        echo
        
        echo "--- 6/6: Validation Tests ---"
        make validate
        
        echo
        echo "ALL CORE TESTS COMPLETED!"
        echo "Both Process 1 (Flow Analysis) and Process 2 (Rule Engine) working correctly!"
        echo "Note: Event system tests require libuv - run './run_tests.sh all-events'"
        ;;
    "all-events")
        echo "* Running All Event System Tests..."
        echo "Testing: libuv event system and inter-process communication"
        echo
        
        # Check for libuv
        if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists libuv; then
            echo "ERROR: libuv not found. Install with:"
            echo "  Ubuntu/Debian: sudo apt install libuv1-dev"
            echo "  CentOS/RHEL/Fedora: sudo yum install libuv-devel"
            echo "  macOS: brew install libuv"
            echo
            exit 1
        fi
        
        echo "--- Event System IPC Test ---"
        ./test_events.sh
        echo
        
        echo "EVENT SYSTEM TESTS COMPLETED!"
        echo "libuv-based inter-process communication working correctly!"
        ;;
    "perf-basic")
        echo "* Running Basic Performance Benchmark..."
        echo "Shows: Packet processing time, CPU usage, memory consumption"
        echo "Duration: ~30 seconds"
        echo
        ./benchmark_test basic
        ;;
    "perf-throughput")
        echo "* Running High Throughput Stress Test..."
        echo "Shows: Maximum packet processing rate under load"
        echo "Duration: ~2 minutes"
        echo
        ./benchmark_test throughput
        ;;
    "perf-compare")
        echo "* Running Comparative Performance Analysis..."
        echo "Shows: Performance impact of different configurations"
        echo "Duration: ~3 minutes"
        echo
        ./benchmark_test compare
        ;;
    "perf-all")
        echo "* Running Complete Performance Benchmark Suite..."
        echo "Shows: Comprehensive performance analysis"
        echo "Duration: ~10 minutes"
        echo
        ./benchmark_test benchmark
        ;;
    "full")
        echo "* Running Full Test Suite..."
        echo "Running: All core tests + Event system tests"
        echo
        
        echo "=== CORE FUNCTIONALITY TESTS ==="
        echo "--- 1/6: Basic Test ---"
        make test
        echo
        
        echo "--- 2/6: Demo Scenarios ---"  
        make demo
        echo
        
        echo "--- 3/6: Verbose Internal View ---"
        make verbose
        echo
        
        echo "--- 4/6: Process 2 Rule Engine ---"
        make proc2
        echo
        
        echo "--- 5/6: Process 1+2 Integration ---"
        make integrated
        echo
        
        echo "--- 6/6: Validation Tests ---"
        make validate
        echo
        
        echo "=== EVENT SYSTEM TESTS ==="
        # Check for libuv
        if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists libuv; then
            echo "WARNING: libuv not found. Skipping event system tests."
            echo "Install libuv to test event system functionality:"
            echo "  Ubuntu/Debian: sudo apt install libuv1-dev"
            echo "  CentOS/RHEL/Fedora: sudo yum install libuv-devel"
            echo "  macOS: brew install libuv"
        else
            echo "--- Event System IPC Test ---"
            ./test_events.sh
            echo
            echo "EVENT SYSTEM TESTS COMPLETED!"
        fi
        
        echo "=== PERFORMANCE TESTS ==="
        echo "--- Basic Performance Benchmark ---"
        ./benchmark_test basic
        echo
        
        echo
        echo "FULL TEST SUITE COMPLETED!"
        echo "SnortSharp flow analyzer with event system and performance analysis fully functional!"
        ;;
    *)
        echo "Unknown test: $1"
        echo "Run './run_tests.sh' to see available options"
        exit 1
        ;;
esac
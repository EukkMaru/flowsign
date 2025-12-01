#include <iostream>
#include <memory>
#include <csignal>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <fstream>
#include <cstdlib>
#include <iomanip>
#include "performance_test.hpp"

static std::atomic<bool> running{true};

void signal_handler(int sig) {
    (void)sig;
    std::cout << "\n[BENCHMARK] Interrupted, finishing current test..." << std::endl;
    running = false;
}

void run_benchmark_suite() {
    std::cout << "================================================================" << std::endl;
    std::cout << "              SNORTSHARP PERFORMANCE BENCHMARK" << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << std::endl;
    
    // Test 1: Basic Performance
    std::cout << "TEST 1: Basic Performance Baseline" << std::endl;
    std::cout << "---------------------------------------" << std::endl;
    auto basic_config = get_basic_performance_config();
    auto basic_test = std::make_unique<PerformanceTest>(basic_config);
    
    if(basic_test && running) {
        if(basic_test->run_performance_test()) {
            basic_test->print_summary();
        }
    }
    
    if(!running) return;
    
    // Test 2: High Throughput
    std::cout << "\nTEST 2: High Throughput Stress Test" << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    auto throughput_config = get_high_throughput_config();
    auto throughput_test = std::make_unique<PerformanceTest>(throughput_config);
    
    if(throughput_test && running) {
        if(throughput_test->run_throughput_benchmark()) {
            throughput_test->print_summary();
        }
    }
    
    if(!running) return;
    
    // Test 3: Low Latency
    std::cout << "\nTEST 3: Low Latency Optimization Test" << std::endl;
    std::cout << "------------------------------------------" << std::endl;
    auto latency_config = get_low_latency_config();
    auto latency_test = std::make_unique<PerformanceTest>(latency_config);
    
    if(latency_test && running) {
        if(latency_test->run_latency_benchmark()) {
            latency_test->print_summary();
        }
    }
    
    if(!running) return;
    
    // Test 4: Memory Stress Test
    std::cout << "\nTEST 4: Memory Usage Analysis" << std::endl;
    std::cout << "------------------------------" << std::endl;
    auto memory_config = get_basic_performance_config();
    memory_config.num_packets = 50000;
    memory_config.queue_capacity = 5000;
    memory_config.window_size = 100;
    memory_config.test_name = "Memory Stress Test";
    auto memory_test = std::make_unique<PerformanceTest>(memory_config);
    
    if(memory_test && running) {
        if(memory_test->run_memory_stress_test()) {
            memory_test->print_summary();
        }
    }
    
    if(!running) return;
    
    // Test 5: Event System Performance (if libuv available)
    std::cout << "\nTEST 5: Event System Performance" << std::endl;
    std::cout << "---------------------------------" << std::endl;
    
    // Check if event system can be created
    try {
        auto event_config = get_event_system_config();
        auto event_test = std::make_unique<PerformanceTest>(event_config);
        
        if(event_test && running) {
            if(event_test->run_performance_test()) {
                event_test->print_summary();
            }
        }
    } catch(const std::exception& e) {
        std::cout << "[BENCHMARK] Event system test skipped: " << e.what() << std::endl;
        std::cout << "Install libuv-dev to enable event system performance testing" << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << "              BENCHMARK SUITE COMPLETED" << std::endl;
    std::cout << "================================================================" << std::endl;
}

void run_comparative_benchmark() {
    std::cout << "================================================================" << std::endl;
    std::cout << "           COMPARATIVE PERFORMANCE ANALYSIS" << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << std::endl;
    
    // Test different window sizes
    std::cout << "WINDOW SIZE COMPARISON:" << std::endl;
    std::cout << "─────────────────────" << std::endl;
    
    std::vector<int> window_sizes = {5, 10, 20, 50, 100};
    
    for(int window_size : window_sizes) {
        if(!running) break;
        
        auto config = get_basic_performance_config();
        config.window_size = window_size;
        config.num_packets = 20000;
        config.verbose_output = false;
        config.test_name = "Window Size " + std::to_string(window_size);
        
        auto test = std::make_unique<PerformanceTest>(config);
        if(test) {
            std::cout << "Testing window size " << window_size << "... ";
            std::cout.flush();
            
            if(test->run_performance_test()) {
                const auto& metrics = test->get_metrics();
                std::cout << std::fixed << std::setprecision(2) 
                          << metrics.avg_packet_processing_time_us << " us/packet, "
                          << std::setprecision(0) << metrics.packets_per_second 
                          << " pps" << std::endl;
            } else {
                std::cout << "FAILED" << std::endl;
            }
        }
    }
    
    std::cout << std::endl;
    
    // Test different queue capacities
    std::cout << "QUEUE CAPACITY COMPARISON:" << std::endl;
    std::cout << "────────────────────────" << std::endl;
    
    std::vector<int> capacities = {50, 100, 500, 1000, 5000};
    
    for(int capacity : capacities) {
        if(!running) break;
        
        auto config = get_basic_performance_config();
        config.queue_capacity = capacity;
        config.num_packets = 20000;
        config.verbose_output = false;
        config.test_name = "Queue Capacity " + std::to_string(capacity);
        
        auto test = std::make_unique<PerformanceTest>(config);
        if(test) {
            std::cout << "Testing queue capacity " << capacity << "... ";
            std::cout.flush();
            
            if(test->run_performance_test()) {
                const auto& metrics = test->get_metrics();
                std::cout << std::fixed << std::setprecision(2) 
                          << metrics.avg_packet_processing_time_us << " us/packet, ";
                
                // Format memory inline
                long kb = metrics.peak_memory_kb;
                if(kb >= 1024 * 1024) {
                    std::cout << std::setprecision(1) << (kb / (1024.0 * 1024.0)) << " GB";
                } else if(kb >= 1024) {
                    std::cout << std::setprecision(1) << (kb / 1024.0) << " MB";
                } else {
                    std::cout << kb << " KB";
                }
                std::cout << " peak memory" << std::endl;
            } else {
                std::cout << "FAILED" << std::endl;
            }
        }
    }
    
    std::cout << std::endl;
    std::cout << "================================================================" << std::endl;
}

void run_stress_test() {
    std::cout << "================================================================" << std::endl;
    std::cout << "                 STRESS TEST SUITE" << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << std::endl;
    
    std::cout << "WARNING: This test will push the system to its limits" << std::endl;
    std::cout << "Press Ctrl+C to interrupt if system becomes unresponsive" << std::endl;
    std::cout << "Starting in 3 seconds..." << std::endl;
    
    for(int i = 3; i > 0 && running; i--) {
        std::cout << i << "... ";
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << std::endl << std::endl;
    
    if(!running) return;
    
    // Extreme throughput test
    std::cout << "EXTREME THROUGHPUT TEST:" << std::endl;
    std::cout << "----------------------" << std::endl;
    auto extreme_config = get_high_throughput_config();
    extreme_config.num_packets = 1000000; // 1M packets
    extreme_config.window_size = 3;
    extreme_config.queue_capacity = 10000;
    extreme_config.test_name = "Extreme Throughput Stress Test";
    extreme_config.verbose_output = true;
    
    auto extreme_test = std::make_unique<PerformanceTest>(extreme_config);
    if(extreme_test && running) {
        std::cout << "Processing 1,000,000 packets..." << std::endl;
        if(extreme_test->run_performance_test()) {
            extreme_test->print_summary();
        }
    }
    
    std::cout << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << "                STRESS TEST COMPLETED" << std::endl;
    std::cout << "================================================================" << std::endl;
}

void print_system_info() {
    std::cout << "SYSTEM INFORMATION:" << std::endl;
    std::cout << "-----------------" << std::endl;
    
    // CPU info
    std::ifstream cpuinfo("/proc/cpuinfo");
    if(cpuinfo.is_open()) {
        std::string line;
        while(std::getline(cpuinfo, line)) {
            if(line.find("model name") != std::string::npos) {
                std::cout << "CPU: " << line.substr(line.find(':') + 2) << std::endl;
                break;
            }
        }
        cpuinfo.close();
    }
    
    // Memory info
    std::ifstream meminfo("/proc/meminfo");
    if(meminfo.is_open()) {
        std::string line;
        while(std::getline(meminfo, line)) {
            if(line.find("MemTotal:") != std::string::npos) {
                std::cout << "Memory: " << line.substr(line.find(':') + 2) << std::endl;
                break;
            }
        }
        meminfo.close();
    }
    
    // Compiler info
    std::cout << "Compiler: GCC " << __VERSION__ << std::endl;
    std::cout << "Build flags: -O2 -std=c++17" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Seed random number generator
    srand(time(nullptr));
    
    print_system_info();
    
    if(argc < 2) {
        std::cout << "Usage: " << argv[0] << " <test_type>" << std::endl;
        std::cout << "\nAvailable tests:" << std::endl;
        std::cout << "  benchmark  - Complete benchmark suite" << std::endl;
        std::cout << "  compare    - Comparative analysis (window sizes, queue capacities)" << std::endl;
        std::cout << "  stress     - Stress test with extreme loads" << std::endl;
        std::cout << "  basic      - Single basic performance test" << std::endl;
        std::cout << "  throughput - High throughput test only" << std::endl;
        std::cout << "  latency    - Low latency test only" << std::endl;
        std::cout << "  memory     - Memory usage analysis" << std::endl;
        std::cout << "  events     - Event system performance (requires libuv)" << std::endl;
        return 1;
    }
    
    std::string test_type = argv[1];
    
    if(test_type == "benchmark") {
        run_benchmark_suite();
    } else if(test_type == "compare") {
        run_comparative_benchmark();
    } else if(test_type == "stress") {
        run_stress_test();
    } else if(test_type == "basic") {
        auto config = get_basic_performance_config();
        auto test = std::make_unique<PerformanceTest>(config);
        if(test) {
            test->run_performance_test();
            test->print_summary();
        }
    } else if(test_type == "throughput") {
        auto config = get_high_throughput_config();
        auto test = std::make_unique<PerformanceTest>(config);
        if(test) {
            test->run_throughput_benchmark();
            test->print_summary();
        }
    } else if(test_type == "latency") {
        auto config = get_low_latency_config();
        auto test = std::make_unique<PerformanceTest>(config);
        if(test) {
            test->run_latency_benchmark();
            test->print_summary();
        }
    } else if(test_type == "memory") {
        auto config = get_basic_performance_config();
        config.num_packets = 100000;
        config.queue_capacity = 10000;
        config.window_size = 100;
        config.test_name = "Memory Analysis Test";
        auto test = std::make_unique<PerformanceTest>(config);
        if(test) {
            test->run_memory_stress_test();
            test->print_summary();
        }
    } else if(test_type == "events") {
        auto config = get_event_system_config();
        auto test = std::make_unique<PerformanceTest>(config);
        if(test) {
            test->run_performance_test();
            test->print_summary();
        } else {
            std::cout << "Error: Could not create event system test (libuv not available?)" << std::endl;
            return 1;
        }
    } else {
        std::cout << "Unknown test type: " << test_type << std::endl;
        return 1;
    }
    
    return 0;
}
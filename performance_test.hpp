#ifndef PERFORMANCE_TEST_HPP
#define PERFORMANCE_TEST_HPP

#include "flow_analyzer.hpp"
#include "event_system.hpp"
#include <sys/time.h>
#include <sys/resource.h>
#include <memory>
#include <vector>
#include <string>
#include <chrono>

struct PerformanceMetrics {
    // Time measurements (microseconds)
    double total_processing_time_us = 0.0;
    double avg_packet_processing_time_us = 0.0;
    double min_packet_processing_time_us = 0.0;
    double max_packet_processing_time_us = 0.0;
    
    // Throughput measurements
    double packets_per_second = 0.0;
    double bytes_per_second = 0.0;
    double windows_per_second = 0.0;
    
    // CPU measurements
    double cpu_user_time_ms = 0.0;
    double cpu_system_time_ms = 0.0;
    double cpu_total_time_ms = 0.0;
    double cpu_utilization_percent = 0.0;
    
    // Memory measurements (KB)
    long peak_memory_kb = 0;
    long avg_memory_kb = 0;
    long memory_delta_kb = 0;
    
    // System metrics
    uint64_t total_packets_processed = 0;
    uint64_t total_bytes_processed = 0;
    uint64_t total_windows_generated = 0;
    
    // Event system specific
    uint64_t events_sent = 0;
    uint64_t events_received = 0;
    double avg_event_latency_us = 0.0;
    
    // Error counts
    uint64_t dropped_packets = 0;
    uint64_t failed_allocations = 0;
    uint64_t processing_errors = 0;
};

struct PerformanceConfig {
    int num_packets = 10000;
    int window_size = 10;
    int queue_capacity = 100;
    bool use_events = false;
    bool verbose_output = true;
    std::string test_name = "Performance Test";
    
    // Packet generation parameters
    int min_packet_size = 60;
    int max_packet_size = 1500;
    int packet_rate_us = 1000; // Microseconds between packets
    
    // Test patterns
    bool simulate_realistic_traffic = false;
    bool simulate_attack_patterns = false;
    bool test_concurrent_flows = false;
};

class PerformanceTest {
private:
    PerformanceConfig config_;
    PerformanceMetrics metrics_;
    std::unique_ptr<FlowAnalyzer> analyzer_;
    std::unique_ptr<EventSystem> event_system_;
    
    // Timing data
    std::chrono::high_resolution_clock::time_point start_time_;
    std::chrono::high_resolution_clock::time_point end_time_;
    struct rusage start_usage_;
    struct rusage end_usage_;
    
    // Memory tracking
    long initial_memory_kb_ = 0;
    long peak_memory_kb_ = 0;
    
    // Packet processing times
    std::vector<double> packet_times_us_;

public:
    explicit PerformanceTest(const PerformanceConfig& config);
    ~PerformanceTest() = default;
    
    // disable copy constructor and assignment
    PerformanceTest(const PerformanceTest&) = delete;
    PerformanceTest& operator=(const PerformanceTest&) = delete;
    
    // Test execution functions
    bool run_performance_test();
    bool run_throughput_benchmark();
    bool run_latency_benchmark();
    bool run_memory_stress_test();
    
    // System monitoring functions
    void start_monitoring();
    void stop_monitoring();
    
    // Packet generation functions
    PacketInfo generate_test_packet(int seq, int size, bool realistic_timing);
    PacketInfo generate_attack_packet(int seq, const std::string& attack_type);
    
    // Statistics and analysis functions
    void calculate_stats();
    
    // Reporting functions
    void print_summary() const;
    void print_detailed_report() const;
    
    // Getters
    const PerformanceMetrics& get_metrics() const { return metrics_; }
    const PerformanceConfig& get_config() const { return config_; }

private:
    long get_current_memory_kb() const;
    double timeval_diff_us(const struct timeval& start, const struct timeval& end) const;
    double get_cpu_utilization(const struct rusage& start, const struct rusage& end, double elapsed_time_us) const;
    void print_progress_bar(int current, int total, const std::string& label) const;
    std::string format_throughput(double value) const;
    std::string format_memory(long kb) const;
};

// Factory functions for predefined configurations
PerformanceConfig get_basic_performance_config();
PerformanceConfig get_high_throughput_config();
PerformanceConfig get_low_latency_config();
PerformanceConfig get_memory_stress_config();
PerformanceConfig get_event_system_config();

#endif // PERFORMANCE_TEST_HPP
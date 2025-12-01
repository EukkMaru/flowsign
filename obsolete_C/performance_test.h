#ifndef PERFORMANCE_TEST_H
#define PERFORMANCE_TEST_H

#include "flow_analyzer.h"
#include "event_system.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_PERFORMANCE_RUNS 10
#define BENCHMARK_PACKETS 100000

// Performance metrics structure
typedef struct {
    // Time measurements (microseconds)
    double total_processing_time_us;
    double avg_packet_processing_time_us;
    double min_packet_processing_time_us;
    double max_packet_processing_time_us;
    
    // Throughput measurements
    double packets_per_second;
    double bytes_per_second;
    double windows_per_second;
    
    // CPU measurements
    double cpu_user_time_ms;
    double cpu_system_time_ms;
    double cpu_total_time_ms;
    double cpu_utilization_percent;
    
    // Memory measurements (KB)
    long peak_memory_kb;
    long avg_memory_kb;
    long memory_delta_kb; // Memory growth during test
    
    // System metrics
    uint64_t total_packets_processed;
    uint64_t total_bytes_processed;
    uint64_t total_windows_generated;
    uint64_t context_switches;
    
    // Event system specific
    uint64_t events_sent;
    uint64_t events_received;
    double avg_event_latency_us;
    
    // Error counts
    uint64_t dropped_packets;
    uint64_t failed_allocations;
    uint64_t processing_errors;
} performance_metrics_t;

// Performance test configuration
typedef struct {
    int num_packets;
    int window_size;
    int queue_capacity;
    bool use_events;
    bool verbose_output;
    const char *test_name;
    
    // Packet generation parameters
    int min_packet_size;
    int max_packet_size;
    int packet_rate_us; // Microseconds between packets
    
    // Test patterns
    bool simulate_realistic_traffic;
    bool simulate_attack_patterns;
    bool test_concurrent_flows;
} performance_config_t;

// Performance test runner
typedef struct {
    performance_config_t config;
    performance_metrics_t metrics;
    flow_analyzer_t *analyzer;
    event_system_t *event_system;
    
    // Timing data
    struct timeval start_time;
    struct timeval end_time;
    struct rusage start_usage;
    struct rusage end_usage;
    
    // Memory tracking
    long initial_memory_kb;
    long peak_memory_kb;
    
    // Packet processing times (for detailed analysis)
    double *packet_times_us;
    int packet_times_count;
    int packet_times_capacity;
} performance_test_t;

// Core performance testing functions
performance_test_t* create_performance_test(performance_config_t *config);
void destroy_performance_test(performance_test_t *test);

// Test execution functions
bool run_performance_test(performance_test_t *test);
bool run_throughput_benchmark(performance_test_t *test);
bool run_latency_benchmark(performance_test_t *test);
bool run_memory_stress_test(performance_test_t *test);
bool run_concurrent_flow_test(performance_test_t *test);

// System monitoring functions
void start_performance_monitoring(performance_test_t *test);
void stop_performance_monitoring(performance_test_t *test);
long get_current_memory_kb(void);
double get_cpu_utilization(struct rusage *start, struct rusage *end, double elapsed_time);

// Packet generation functions
packet_info_t generate_test_packet(int seq, int size, bool realistic_timing);
packet_info_t generate_attack_packet(int seq, const char *attack_type);
void generate_packet_burst(packet_info_t *packets, int count, int burst_size);

// Statistics and analysis functions
void calculate_performance_stats(performance_test_t *test);
void analyze_packet_timing_distribution(performance_test_t *test);
void detect_performance_anomalies(performance_test_t *test);

// Reporting functions
void print_performance_summary(const performance_test_t *test);
void print_detailed_performance_report(const performance_test_t *test);
void export_performance_csv(const performance_test_t *test, const char *filename);
void compare_performance_results(const performance_test_t *test1, const performance_test_t *test2);

// Predefined test configurations
performance_config_t get_basic_performance_config(void);
performance_config_t get_high_throughput_config(void);
performance_config_t get_low_latency_config(void);
performance_config_t get_memory_stress_config(void);
performance_config_t get_event_system_config(void);

// Utility functions
double timeval_diff_us(struct timeval *start, struct timeval *end);
void print_progress_bar(int current, int total, const char *label);
const char* format_throughput(double value, char *buffer, size_t size);
const char* format_memory(long kb, char *buffer, size_t size);

#endif // PERFORMANCE_TEST_H
#include "performance_test.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cmath>
#include <random>
#include <algorithm>
#include <thread>
#include <arpa/inet.h>

PerformanceTest::PerformanceTest(const PerformanceConfig& config) 
    : config_(config) {
    
    analyzer_ = std::make_unique<FlowAnalyzer>(config_.queue_capacity, config_.window_size, 1);
    
    if(config_.use_events) {
        event_system_ = std::make_unique<EventSystem>("/tmp/snortsharp_perf", false);
    }
    
    packet_times_us_.reserve(config_.num_packets);
    
    initial_memory_kb_ = get_current_memory_kb();
}

bool PerformanceTest::run_performance_test() {
    if(config_.verbose_output) {
        std::cout << "Running performance test: " << config_.test_name << std::endl;
        std::cout << "Configuration: " << config_.num_packets << " packets, "
                  << "window=" << config_.window_size << ", "
                  << "capacity=" << config_.queue_capacity << std::endl;
    }
    
    start_monitoring();
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> size_dis(config_.min_packet_size, config_.max_packet_size);
    
    FlowFeatures features{};
    int windows_generated = 0;
    
    for(int i = 0; i < config_.num_packets; i++) {
        auto packet_start = std::chrono::high_resolution_clock::now();
        
        int packet_size = size_dis(gen);
        PacketInfo packet = generate_test_packet(i, packet_size, config_.simulate_realistic_traffic);
        
        bool window_ready = analyzer_->process_packet(packet, features);
        if(window_ready) {
            windows_generated++;
        }
        
        auto packet_end = std::chrono::high_resolution_clock::now();
        double packet_time_us = std::chrono::duration<double, std::micro>(packet_end - packet_start).count();
        packet_times_us_.push_back(packet_time_us);
        
        // Update memory tracking
        long current_memory = get_current_memory_kb();
        if(current_memory > peak_memory_kb_) {
            peak_memory_kb_ = current_memory;
        }
        
        // Progress reporting
        if(config_.verbose_output && (i % (config_.num_packets / 10) == 0)) {
            print_progress_bar(i, config_.num_packets, "Processing packets");
        }
        
        // Simulate packet rate if specified
        if(config_.packet_rate_us > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(config_.packet_rate_us));
        }
    }
    
    stop_monitoring();
    calculate_stats();
    
    metrics_.total_windows_generated = windows_generated;
    
    if(config_.verbose_output) {
        std::cout << "\nTest completed successfully!" << std::endl;
    }
    
    return true;
}

bool PerformanceTest::run_throughput_benchmark() {
    config_.packet_rate_us = 0; // No artificial delays
    config_.test_name = "Throughput Benchmark";
    return run_performance_test();
}

bool PerformanceTest::run_latency_benchmark() {
    config_.num_packets = 1000; // Smaller test for latency focus
    config_.test_name = "Latency Benchmark";
    return run_performance_test();
}

bool PerformanceTest::run_memory_stress_test() {
    config_.num_packets = 100000;
    config_.queue_capacity = 10000;
    config_.window_size = 100;
    config_.test_name = "Memory Stress Test";
    return run_performance_test();
}

void PerformanceTest::start_monitoring() {
    start_time_ = std::chrono::high_resolution_clock::now();
    getrusage(RUSAGE_SELF, &start_usage_);
    initial_memory_kb_ = get_current_memory_kb();
}

void PerformanceTest::stop_monitoring() {
    end_time_ = std::chrono::high_resolution_clock::now();
    getrusage(RUSAGE_SELF, &end_usage_);
    peak_memory_kb_ = get_current_memory_kb();
}

PacketInfo PerformanceTest::generate_test_packet(int seq, int size, bool realistic_timing) {
    PacketInfo packet{};
    
    gettimeofday(&packet.timestamp, nullptr);
    
    if(realistic_timing) {
        // Add some jitter to simulate realistic network conditions
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> jitter_dis(0, 1000);
        packet.timestamp.tv_usec += jitter_dis(gen);
        if(packet.timestamp.tv_usec >= 1000000) {
            packet.timestamp.tv_sec++;
            packet.timestamp.tv_usec -= 1000000;
        }
    } else {
        packet.timestamp.tv_usec += seq * 100;
        if(packet.timestamp.tv_usec >= 1000000) {
            packet.timestamp.tv_sec += packet.timestamp.tv_usec / 1000000;
            packet.timestamp.tv_usec %= 1000000;
        }
    }
    
    packet.src_ip = 0xC0A80101 + (seq % 256);  // Varying source IPs
    packet.dst_ip = 0xC0A80201;
    packet.src_port = 10000 + (seq % 55000);
    packet.dst_port = 80;
    packet.protocol = 6;  // TCP
    packet.packet_length = size;
    packet.header_length = 20;
    packet.payload_length = size - 20;
    packet.is_forward = (seq % 2 == 0);
    packet.window_size = 8192;
    
    // Set some TCP flags
    packet.tcp_flags.ack = true;
    if(seq % 10 == 0) packet.tcp_flags.syn = true;
    if(seq % 100 == 0) packet.tcp_flags.psh = true;
    
    return packet;
}

PacketInfo PerformanceTest::generate_attack_packet(int seq, const std::string& attack_type) {
    PacketInfo packet = generate_test_packet(seq, 60, false);
    
    if(attack_type == "port_scan") {
        packet.dst_port = 80 + (seq % 1000);  // Different ports
        packet.tcp_flags.syn = true;
        packet.tcp_flags.ack = false;
    } else if(attack_type == "dos") {
        packet.packet_length = 40;  // Very small packets
        packet.payload_length = 20;
    }
    
    return packet;
}

void PerformanceTest::calculate_stats() {
    if(packet_times_us_.empty()) return;
    
    // Calculate timing statistics
    auto total_time = std::chrono::duration<double, std::micro>(end_time_ - start_time_).count();
    metrics_.total_processing_time_us = total_time;
    
    double sum = 0.0;
    for(double time : packet_times_us_) {
        sum += time;
    }
    metrics_.avg_packet_processing_time_us = sum / packet_times_us_.size();
    
    auto minmax = std::minmax_element(packet_times_us_.begin(), packet_times_us_.end());
    metrics_.min_packet_processing_time_us = *minmax.first;
    metrics_.max_packet_processing_time_us = *minmax.second;
    
    // Calculate throughput
    metrics_.packets_per_second = (config_.num_packets * 1000000.0) / total_time;
    metrics_.bytes_per_second = (metrics_.total_bytes_processed * 1000000.0) / total_time;
    metrics_.windows_per_second = (metrics_.total_windows_generated * 1000000.0) / total_time;
    
    // Calculate CPU utilization
    double user_time_us = timeval_diff_us(start_usage_.ru_utime, end_usage_.ru_utime);
    double system_time_us = timeval_diff_us(start_usage_.ru_stime, end_usage_.ru_stime);
    metrics_.cpu_user_time_ms = user_time_us / 1000.0;
    metrics_.cpu_system_time_ms = system_time_us / 1000.0;
    metrics_.cpu_total_time_ms = metrics_.cpu_user_time_ms + metrics_.cpu_system_time_ms;
    metrics_.cpu_utilization_percent = get_cpu_utilization(start_usage_, end_usage_, total_time);
    
    // Memory statistics
    metrics_.peak_memory_kb = peak_memory_kb_;
    metrics_.memory_delta_kb = peak_memory_kb_ - initial_memory_kb_;
    
    // Packet statistics
    metrics_.total_packets_processed = config_.num_packets;
    metrics_.total_bytes_processed = config_.num_packets * ((config_.min_packet_size + config_.max_packet_size) / 2);
}

void PerformanceTest::print_summary() const {
    std::cout << "\n================================================" << std::endl;
    std::cout << "Performance Test Summary: " << config_.test_name << std::endl;
    std::cout << "================================================" << std::endl;
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Packets: " << config_.num_packets << std::endl;
    std::cout << "  Window Size: " << config_.window_size << std::endl;
    std::cout << "  Queue Capacity: " << config_.queue_capacity << std::endl;
    
    std::cout << "\nTiming Results:" << std::endl;
    std::cout << "  Total Time: " << std::fixed << std::setprecision(2) 
              << (metrics_.total_processing_time_us / 1000.0) << " ms" << std::endl;
    std::cout << "  Avg/packet: " << metrics_.avg_packet_processing_time_us << " us" << std::endl;
    std::cout << "  Min/packet: " << metrics_.min_packet_processing_time_us << " us" << std::endl;
    std::cout << "  Max/packet: " << metrics_.max_packet_processing_time_us << " us" << std::endl;
    
    std::cout << "\nThroughput:" << std::endl;
    std::cout << "  Packets/sec: " << format_throughput(metrics_.packets_per_second) << std::endl;
    std::cout << "  Bytes/sec: " << format_throughput(metrics_.bytes_per_second) << std::endl;
    std::cout << "  Windows/sec: " << format_throughput(metrics_.windows_per_second) << std::endl;
    
    std::cout << "\nSystem Usage:" << std::endl;
    std::cout << "  CPU: " << std::setprecision(1) << metrics_.cpu_utilization_percent << "%" << std::endl;
    std::cout << "  Peak Memory: " << format_memory(metrics_.peak_memory_kb) << std::endl;
    std::cout << "  Memory Delta: " << format_memory(metrics_.memory_delta_kb) << std::endl;
    
    std::cout << std::endl;
}

void PerformanceTest::print_detailed_report() const {
    print_summary();
    
    std::cout << "Detailed Analysis:" << std::endl;
    std::cout << "  Windows Generated: " << metrics_.total_windows_generated << std::endl;
    std::cout << "  CPU User Time: " << metrics_.cpu_user_time_ms << " ms" << std::endl;
    std::cout << "  CPU System Time: " << metrics_.cpu_system_time_ms << " ms" << std::endl;
    
    if(!packet_times_us_.empty()) {
        // Calculate standard deviation
        double mean = metrics_.avg_packet_processing_time_us;
        double sum_sq_diff = 0.0;
        for(double time : packet_times_us_) {
            sum_sq_diff += (time - mean) * (time - mean);
        }
        double std_dev = std::sqrt(sum_sq_diff / packet_times_us_.size());
        std::cout << "  Timing Std Dev: " << std_dev << " us" << std::endl;
    }
}

long PerformanceTest::get_current_memory_kb() const {
    std::ifstream file("/proc/self/status");
    if(!file.is_open()) return -1;
    
    std::string line;
    while(std::getline(file, line)) {
        if(line.substr(0, 6) == "VmRSS:") {
            std::istringstream iss(line.substr(6));
            long memory_kb;
            iss >> memory_kb;
            return memory_kb;
        }
    }
    return -1;
}

double PerformanceTest::timeval_diff_us(const struct timeval& start, const struct timeval& end) const {
    return (end.tv_sec - start.tv_sec) * 1000000.0 + (end.tv_usec - start.tv_usec);
}

double PerformanceTest::get_cpu_utilization(const struct rusage& start, const struct rusage& end, double elapsed_time_us) const {
    double user_time_us = timeval_diff_us(start.ru_utime, end.ru_utime);
    double system_time_us = timeval_diff_us(start.ru_stime, end.ru_stime);
    double total_cpu_us = user_time_us + system_time_us;
    
    return (total_cpu_us / elapsed_time_us) * 100.0;
}

void PerformanceTest::print_progress_bar(int current, int total, const std::string& label) const {
    const int bar_width = 50;
    float progress = static_cast<float>(current) / total;
    int pos = static_cast<int>(bar_width * progress);
    
    std::cout << label << " [";
    for(int i = 0; i < bar_width; ++i) {
        if(i < pos) std::cout << "=";
        else if(i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << std::setw(3) << static_cast<int>(progress * 100.0) << "%\r";
    std::cout.flush();
}

std::string PerformanceTest::format_throughput(double value) const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(0);
    
    if(value >= 1000000.0) {
        oss << (value / 1000000.0) << "M";
    } else if(value >= 1000.0) {
        oss << (value / 1000.0) << "K";
    } else {
        oss << value;
    }
    
    return oss.str();
}

std::string PerformanceTest::format_memory(long kb) const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    
    if(kb >= 1024 * 1024) {
        oss << (kb / (1024.0 * 1024.0)) << " GB";
    } else if(kb >= 1024) {
        oss << (kb / 1024.0) << " MB";
    } else {
        oss << kb << " KB";
    }
    
    return oss.str();
}

// Factory functions for predefined configurations
PerformanceConfig get_basic_performance_config() {
    PerformanceConfig config;
    config.num_packets = 10000;
    config.window_size = 10;
    config.queue_capacity = 100;
    config.test_name = "Basic Performance Test";
    return config;
}

PerformanceConfig get_high_throughput_config() {
    PerformanceConfig config;
    config.num_packets = 100000;
    config.window_size = 5;
    config.queue_capacity = 1000;
    config.packet_rate_us = 0;  // No delays
    config.test_name = "High Throughput Test";
    return config;
}

PerformanceConfig get_low_latency_config() {
    PerformanceConfig config;
    config.num_packets = 1000;
    config.window_size = 3;
    config.queue_capacity = 50;
    config.test_name = "Low Latency Test";
    return config;
}

PerformanceConfig get_memory_stress_config() {
    PerformanceConfig config;
    config.num_packets = 50000;
    config.window_size = 100;
    config.queue_capacity = 5000;
    config.test_name = "Memory Stress Test";
    return config;
}

PerformanceConfig get_event_system_config() {
    PerformanceConfig config;
    config.num_packets = 5000;
    config.window_size = 10;
    config.queue_capacity = 200;
    config.use_events = true;
    config.test_name = "Event System Performance Test";
    return config;
}
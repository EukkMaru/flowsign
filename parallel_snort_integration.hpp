#ifndef PARALLEL_SNORT_INTEGRATION_HPP
#define PARALLEL_SNORT_INTEGRATION_HPP

#include "snortsharp_integration.hpp"
#include "flow_analyzer.hpp"
#include "flow_rules.hpp"
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <chrono>

// Forward declarations for Snort3 types
namespace snort {
    class SnortConfig;
    class Packet;
}

// Enhanced packet structure with deep copy capabilities
struct ParallelPacket {
    // packet metadata
    timeval timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t packet_length;
    uint16_t header_length;
    uint16_t payload_length;
    bool is_forward;
    uint16_t window_size;
    
    // tcp flags
    struct TCPFlags {
        bool fin = false;
        bool syn = false;
        bool rst = false;
        bool psh = false;
        bool ack = false;
        bool urg = false;
        bool cwr = false;
        bool ece = false;
    } tcp_flags;
    
    // deep copy of packet payload for thread safety
    std::vector<uint8_t> payload_data;
    
    // snort3 processing results to communicate back
    struct SnortResults {
        bool processed = false;
        std::vector<std::string> snort_alerts;
        int priority = 0;
        std::string classification;
    } snort_results;
    
    // flow processing results 
    struct FlowResults {
        bool processed = false;
        FlowFeatures features;
        std::vector<FlowAlert> flow_alerts;
    } flow_results;
};

// Thread-safe packet queue for inter-engine communication
class ParallelPacketQueue {
private:
    std::queue<std::shared_ptr<ParallelPacket>> queue_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    size_t max_size_;
    std::atomic<size_t> dropped_packets_{0};
    
public:
    explicit ParallelPacketQueue(size_t max_size = 10000) : max_size_(max_size) {}
    
    bool enqueue(std::shared_ptr<ParallelPacket> packet) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if(queue_.size() >= max_size_) {
            // drop oldest packet to prevent memory buildup
            queue_.pop();
            dropped_packets_++;
        }
        
        queue_.push(packet);
        condition_.notify_one();
        return true;
    }
    
    std::shared_ptr<ParallelPacket> dequeue(std::chrono::milliseconds timeout = std::chrono::milliseconds(100)) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if(condition_.wait_for(lock, timeout, [this] { return !queue_.empty(); })) {
            auto packet = queue_.front();
            queue_.pop();
            return packet;
        }
        
        return nullptr;
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    size_t get_dropped_count() const { return dropped_packets_.load(); }
    void reset_dropped_count() { dropped_packets_ = 0; }
};

// Enhanced parallel engine with bidirectional communication
class ParallelSnortSharpEngine {
private:
    // core engines
    std::unique_ptr<FlowAnalyzer> flow_analyzer_;
    std::unique_ptr<FlowRuleEngine> rule_engine_;
    
    // communication queues
    std::unique_ptr<ParallelPacketQueue> snort_to_flow_queue_;
    std::unique_ptr<ParallelPacketQueue> flow_to_snort_queue_;
    
    // processing threads
    std::thread flow_processing_thread_;
    std::thread communication_thread_;
    
    // control flags
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
    
    // statistics
    std::atomic<size_t> total_packets_processed_{0};
    std::atomic<size_t> snort_alerts_generated_{0};
    std::atomic<size_t> flow_alerts_generated_{0};
    std::atomic<size_t> combined_alerts_{0};
    std::atomic<double> avg_snort_processing_us_{0.0};
    std::atomic<double> avg_flow_processing_us_{0.0};
    
    // configuration
    int window_size_;
    int queue_capacity_;
    std::string rules_file_;
    
    // thread functions
    void flow_processing_thread_func();
    void communication_thread_func();
    
    // packet processing
    std::shared_ptr<ParallelPacket> convert_snort_packet_deep_copy(const void* snort_packet);
    void process_packet_through_flow_engine(std::shared_ptr<ParallelPacket> packet);
    void correlate_alerts(std::shared_ptr<ParallelPacket> packet);
    
public:
    ParallelSnortSharpEngine(int window_size = 50, int queue_capacity = 10000, 
                            const std::string& rules_file = "snortsharp_rules.txt");
    ~ParallelSnortSharpEngine();
    
    // initialization
    bool initialize();
    void shutdown();
    
    // main processing entry point - called from snort3 inspector
    bool process_snort_packet_parallel(const void* snort_packet);

    // NEW: Direct enqueue for already-copied packets (from bridge)
    bool enqueue_copied_packet(std::shared_ptr<ParallelPacket> copied_packet);

    // alert retrieval
    bool get_next_combined_alert(FlowAlert& alert);
    std::vector<FlowAlert> get_all_pending_alerts();
    
    // configuration
    bool load_flow_rules(const std::string& rules_file);
    bool add_flow_rule(const std::string& rule_string);
    
    // statistics and monitoring
    void print_parallel_stats() const;
    void reset_stats();
    
    // getters for monitoring
    size_t get_total_packets_processed() const { return total_packets_processed_.load(); }
    size_t get_snort_alerts_generated() const { return snort_alerts_generated_.load(); }
    size_t get_flow_alerts_generated() const { return flow_alerts_generated_.load(); }
    size_t get_combined_alerts() const { return combined_alerts_.load(); }
    double get_avg_snort_processing_us() const { return avg_snort_processing_us_.load(); }
    double get_avg_flow_processing_us() const { return avg_flow_processing_us_.load(); }
    
    // queue monitoring
    size_t get_snort_to_flow_queue_size() const { return snort_to_flow_queue_->size(); }
    size_t get_flow_to_snort_queue_size() const { return flow_to_snort_queue_->size(); }
    size_t get_dropped_packet_count() const { return snort_to_flow_queue_->get_dropped_count(); }
};

// Enhanced inspector that uses parallel processing
class ParallelSnortSharpInspector {
private:
    std::unique_ptr<ParallelSnortSharpEngine> parallel_engine_;
    std::atomic<bool> initialized_{false};
    
    // configuration parameters
    int window_size_ = 50;
    int queue_capacity_ = 10000;
    std::string rules_file_ = "snortsharp_rules.txt";
    
    // statistics for inspector
    std::atomic<size_t> packets_received_{0};
    std::atomic<size_t> packets_processed_{0};
    std::atomic<size_t> processing_errors_{0};
    
    void initialize_parallel_engine();
    void process_alerts();
    
public:
    ParallelSnortSharpInspector();
    ~ParallelSnortSharpInspector();
    
    // snort3 inspector interface
    bool configure(snort::SnortConfig* config);
    void show(const snort::SnortConfig* config) const;
    void eval(snort::Packet* packet);
    
    // enhanced functionality
    bool block_flow(const FlowAlert& alert);
    void print_parallel_stats() const;
    
    // configuration setters
    void set_window_size(int size) { window_size_ = size; }
    void set_queue_capacity(int capacity) { queue_capacity_ = capacity; }
    void set_rules_file(const std::string& file) { rules_file_ = file; }
};

// utility functions for parallel processing
std::shared_ptr<ParallelPacket> create_parallel_packet_from_snort3(const void* snort_packet);
void print_parallel_alert(const FlowAlert& alert);
bool is_packet_duplicate(const ParallelPacket& p1, const ParallelPacket& p2);

#endif // PARALLEL_SNORT_INTEGRATION_HPP
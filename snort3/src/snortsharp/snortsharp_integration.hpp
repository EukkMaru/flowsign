#ifndef SNORTSHARP_INTEGRATION_HPP
#define SNORTSHARP_INTEGRATION_HPP

#include "flow_analyzer.hpp"
#include "flow_rules.hpp"
#include "event_system.hpp"
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <chrono>

constexpr int MAX_FEATURE_QUEUE_SIZE = 1000;

template<typename T>
class FeatureQueue {
private:
    std::vector<T> features_;
    int capacity_;
    int count_;
    int head_;
    int tail_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    bool is_full_;

public:
    explicit FeatureQueue(int capacity) 
        : features_(capacity), capacity_(capacity), count_(0), head_(0), tail_(0), is_full_(false) {}
    
    bool enqueue(const T& features) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        while(count_ == capacity_) {
            // queue is full, drop oldest features
            head_ = (head_ + 1) % capacity_;
            count_--;
        }
        
        features_[tail_] = features;
        tail_ = (tail_ + 1) % capacity_;
        count_++;
        
        not_empty_.notify_one();
        return true;
    }
    
    bool dequeue(T& features) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        while(count_ == 0) {
            not_empty_.wait(lock);
        }
        
        features = features_[head_];
        head_ = (head_ + 1) % capacity_;
        count_--;
        
        not_full_.notify_one();
        return true;
    }
    
    bool try_dequeue(T& features) {
        std::lock_guard<std::mutex> lock(mutex_);
        if(count_ == 0) return false;
        
        features = features_[head_];
        head_ = (head_ + 1) % capacity_;
        count_--;
        
        not_full_.notify_one();
        return true;
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return count_;
    }
    
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return count_ == 0;
    }
};

struct SnortPacket {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t packet_length;
    uint16_t header_length;
    bool is_forward;
    struct timeval timestamp;
    
    struct {
        bool fin : 1;
        bool syn : 1;
        bool rst : 1;
        bool psh : 1;
        bool ack : 1;
        bool urg : 1;
    } tcp_flags;
    
    uint16_t window_size;
    
    SnortPacket() : src_ip(0), dst_ip(0), src_port(0), dst_port(0), protocol(0), 
                   packet_length(0), header_length(0), is_forward(false), 
                   timestamp{}, tcp_flags{}, window_size(0) {}
};

class SnortSharpEngine {
private:
    // process 1: flow analysis
    std::unique_ptr<FlowAnalyzer> flow_analyzer_;
    
    // process 2: rule engine  
    std::unique_ptr<FlowRuleEngine> rule_engine_;
    
    // communication between processes
    std::unique_ptr<FeatureQueue<FlowFeatures>> feature_queue_;
    std::unique_ptr<EventSystem> event_system_;
    bool use_events_;  // whether to use libuv events or traditional queue
    
    // threading
    std::thread process1_thread_;
    std::thread process2_thread_;
    std::atomic<bool> running_;
    bool threads_created_;
    
    // statistics
    std::atomic<uint64_t> total_packets_processed_{0};
    std::atomic<uint64_t> total_features_generated_{0};
    std::atomic<uint64_t> total_alerts_generated_{0};
    
    struct {
        std::atomic<uint64_t> features_dropped{0};      // when queue is full
        std::atomic<uint64_t> processing_errors{0};     // processing failures
        std::atomic<double> avg_processing_time_us{0.0}; // average processing time
    } stats_;

public:
    SnortSharpEngine(int window_size, int queue_capacity, int alert_capacity);
    SnortSharpEngine(int window_size, int queue_capacity, int alert_capacity, const std::string& event_pipe);
    ~SnortSharpEngine();
    
    // disable copy constructor and assignment
    SnortSharpEngine(const SnortSharpEngine&) = delete;
    SnortSharpEngine& operator=(const SnortSharpEngine&) = delete;
    
    bool start();
    void stop();
    
    // packet processing (called from snort integration)
    bool process_snort_packet(const SnortPacket& snort_packet);
    
    // alert retrieval
    bool get_next_alert(FlowAlert& alert);
    
    // rule management
    bool load_flow_rules(const std::string& rules_file);
    bool add_flow_rule(const std::string& rule_string);
    
    // statistics and monitoring
    void print_stats() const;
    void reset_stats();
    
    // getters
    uint64_t get_total_packets_processed() const { return total_packets_processed_.load(); }
    uint64_t get_total_features_generated() const { return total_features_generated_.load(); }
    uint64_t get_total_alerts_generated() const { return total_alerts_generated_.load(); }
    uint64_t get_features_dropped() const { return stats_.features_dropped.load(); }
    uint64_t get_processing_errors() const { return stats_.processing_errors.load(); }
    double get_avg_processing_time_us() const { return stats_.avg_processing_time_us.load(); }
    
    FlowRuleEngine* get_rule_engine() { return rule_engine_.get(); }

private:
    void process1_thread_func();
    void process2_thread_func();
    PacketInfo convert_snort_packet(const SnortPacket& snort_packet);
};

// utility functions
std::unique_ptr<SnortPacket> convert_snort_packet_from_raw(const void* snort_internal_packet);
void print_flow_alert(const FlowAlert& alert);

#endif // SNORTSHARP_INTEGRATION_HPP
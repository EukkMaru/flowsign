#ifndef FLOW_RULES_HPP
#define FLOW_RULES_HPP

#include "flow_analyzer.hpp"
#include <memory>
#include <vector>
#include <string>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>

constexpr int MAX_RULE_LENGTH = 1024;
constexpr int MAX_RULES = 1000;
constexpr int MAX_RULE_MSG = 256;
constexpr int MAX_CONDITIONS = 10;

enum class FlowConditionType {
    FLOW_DURATION,
    FWD_PACKETS,
    BWD_PACKETS,
    FWD_BYTES,
    BWD_BYTES,
    PACKET_LENGTH_MEAN,
    PACKET_LENGTH_STD,
    FWD_PACKET_LENGTH_MEAN,
    BWD_PACKET_LENGTH_MEAN,
    FLOW_BYTES_PER_SEC,
    FLOW_PACKETS_PER_SEC,
    FLOW_IAT_MEAN,
    FLOW_IAT_STD,
    FLOW_IAT_MIN,
    FLOW_IAT_MAX,
    FWD_IAT_MEAN,
    BWD_IAT_MEAN,
    SYN_FLAG_COUNT,
    ACK_FLAG_COUNT,
    FIN_FLAG_COUNT,
    RST_FLAG_COUNT,
    PSH_FLAG_COUNT,
    URG_FLAG_COUNT,
    DOWN_UP_RATIO,
    AVG_PACKET_SIZE
};

enum class FlowOperator {
    GT,    // >
    LT,    // <
    GTE,   // >=
    LTE,   // <=
    EQ,    // ==
    NEQ    // !=
};

enum class FlowLogic {
    AND,
    OR
};

struct FlowCondition {
    FlowConditionType type;
    FlowOperator operator_;
    double value;
    
    FlowCondition() = default;
    FlowCondition(FlowConditionType t, FlowOperator op, double val) 
        : type(t), operator_(op), value(val) {}
};

struct FlowRule {
    uint32_t sid;
    std::string msg;
    bool enabled;
    uint32_t priority;
    
    std::vector<FlowCondition> conditions;
    FlowLogic logic_operator;
    
    // statistics
    std::atomic<uint64_t> matches{0};
    std::atomic<uint64_t> evaluations{0};
    
    FlowRule() : sid(0), enabled(true), priority(1), logic_operator(FlowLogic::AND) {}
};

struct FlowAlert {
    uint32_t rule_id;
    std::string message;
    struct timeval timestamp;
    FlowFeatures features;

    // Flow 5-tuple for ground truth matching
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    FlowAlert() : rule_id(0), timestamp{}, features{},
                  src_ip(0), dst_ip(0), src_port(0), dst_port(0), protocol(0) {}
};

class FlowRuleset {
private:
    std::vector<std::unique_ptr<FlowRule>> rules_;
    mutable std::mutex mutex_;

public:
    FlowRuleset() = default;
    ~FlowRuleset() = default;
    
    // disable copy constructor and assignment
    FlowRuleset(const FlowRuleset&) = delete;
    FlowRuleset& operator=(const FlowRuleset&) = delete;
    
    bool add_rule_from_string(const std::string& rule_str);
    bool load_rules_from_file(const std::string& filename);
    void print_ruleset() const;
    void print_rule_stats() const;
    
    size_t get_rule_count() const;
    bool evaluate_rule(size_t rule_index, const FlowFeatures& features);
    const FlowRule* get_rule(size_t index) const;
    
    // expose for FlowRuleEngine friend access
    bool evaluate_condition(const FlowCondition& condition, const FlowFeatures& features) const;
    double get_feature_value(const FlowFeatures& features, FlowConditionType type) const;
    
private:
    bool parse_rule_string(const std::string& rule_str, FlowRule& rule);
    FlowConditionType string_to_condition_type(const std::string& str) const;
    FlowOperator string_to_operator(const std::string& str) const;
};

template<typename T>
class ThreadSafeQueue {
private:
    std::vector<T> queue_;
    int capacity_;
    int count_;
    int head_;
    int tail_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    bool is_full_;

public:
    explicit ThreadSafeQueue(int capacity) 
        : queue_(capacity), capacity_(capacity), count_(0), head_(0), tail_(0), is_full_(false) {}
    
    bool enqueue(const T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        while(count_ == capacity_) {
            // queue is full, drop oldest
            head_ = (head_ + 1) % capacity_;
            count_--;
        }
        
        queue_[tail_] = item;
        tail_ = (tail_ + 1) % capacity_;
        count_++;
        
        not_empty_.notify_one();
        return true;
    }
    
    bool dequeue(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        while(count_ == 0) {
            not_empty_.wait(lock);
        }
        
        item = queue_[head_];
        head_ = (head_ + 1) % capacity_;
        count_--;
        
        not_full_.notify_one();
        return true;
    }
    
    bool try_dequeue(T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if(count_ == 0) return false;
        
        item = queue_[head_];
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

using FlowAlertQueue = ThreadSafeQueue<FlowAlert>;

class FlowRuleEngine {
private:
    std::unique_ptr<FlowRuleset> ruleset_;
    std::unique_ptr<FlowAlertQueue> alert_queue_;
    std::thread thread_;
    std::atomic<bool> running_;
    bool thread_created_;
    
    // statistics
    std::atomic<uint64_t> total_evaluations_{0};
    std::atomic<uint64_t> total_matches_{0};
    std::atomic<uint64_t> total_features_processed_{0};

public:
    explicit FlowRuleEngine(int alert_capacity);
    ~FlowRuleEngine();
    
    // disable copy constructor and assignment
    FlowRuleEngine(const FlowRuleEngine&) = delete;
    FlowRuleEngine& operator=(const FlowRuleEngine&) = delete;
    
    bool start_engine_thread();
    void stop_engine_thread();
    void process_flow_features(const FlowFeatures& features);
    
    bool get_next_alert(FlowAlert& alert);
    FlowRuleset* get_ruleset() { return ruleset_.get(); }
    
    // statistics
    uint64_t get_total_evaluations() const { return total_evaluations_.load(); }
    uint64_t get_total_matches() const { return total_matches_.load(); }
    uint64_t get_total_features_processed() const { return total_features_processed_.load(); }

private:
    void engine_thread_func();
    bool evaluate_condition(const FlowCondition& condition, const FlowFeatures& features);
    double get_feature_value(const FlowFeatures& features, FlowConditionType type);
};

// utility functions
const char* condition_type_to_string(FlowConditionType type);
const char* operator_to_string(FlowOperator op);

#endif // FLOW_RULES_HPP
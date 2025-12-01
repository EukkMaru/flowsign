#include "flow_rules.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <sys/time.h>
#include <chrono>
#include <thread>
#include <unordered_map>

// FlowRuleset Implementation

bool FlowRuleset::add_rule_from_string(const std::string& rule_str) {
    if(rules_.size() >= MAX_RULES) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto rule = std::make_unique<FlowRule>();
    if(!parse_rule_string(rule_str, *rule)) {
        return false;
    }
    
    rules_.push_back(std::move(rule));
    return true;
}

bool FlowRuleset::load_rules_from_file(const std::string& filename) {
    std::ifstream file(filename);
    if(!file.is_open()) {
        return false;
    }
    
    std::string line;
    while(std::getline(file, line)) {
        // skip empty lines and comments
        if(line.empty() || line[0] == '#') continue;
        
        if(!add_rule_from_string(line)) {
            std::cerr << "Failed to parse rule: " << line << std::endl;
        }
    }
    
    return true;
}

void FlowRuleset::print_ruleset() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::cout << "Flow Ruleset (" << rules_.size() << " rules):" << std::endl;
    std::cout << "===========================================" << std::endl;
    
    for(size_t i = 0; i < rules_.size(); ++i) {
        const auto& rule = rules_[i];
        
        std::cout << "Rule " << (i + 1) << " (SID: " << rule->sid 
                  << ", Priority: " << rule->priority 
                  << ", " << (rule->enabled ? "Enabled" : "Disabled") << "):" << std::endl;
        std::cout << "  Message: " << rule->msg << std::endl;
        std::cout << "  Conditions (" << (rule->logic_operator == FlowLogic::AND ? "AND" : "OR") << " logic):" << std::endl;
        
        for(const auto& cond : rule->conditions) {
            std::cout << "    " << condition_type_to_string(cond.type) 
                      << " " << operator_to_string(cond.operator_) 
                      << " " << cond.value << std::endl;
        }
        
        uint64_t matches = rule->matches.load();
        uint64_t evaluations = rule->evaluations.load();
        double match_rate = evaluations > 0 ? (matches * 100.0 / evaluations) : 0.0;
        
        std::cout << "  Stats: " << matches << " matches / " << evaluations 
                  << " evaluations (" << match_rate << "%)" << std::endl;
        std::cout << std::endl;
    }
}

void FlowRuleset::print_rule_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::cout << "Rule Statistics:" << std::endl;
    std::cout << "=================" << std::endl;
    
    for(size_t i = 0; i < rules_.size(); ++i) {
        const auto& rule = rules_[i];
        uint64_t matches = rule->matches.load();
        uint64_t evaluations = rule->evaluations.load();
        double match_rate = evaluations > 0 ? (matches * 100.0 / evaluations) : 0.0;
        
        std::cout << "SID " << rule->sid << ": " << matches << " / " << evaluations 
                  << " (" << match_rate << "%)" << std::endl;
    }
}

size_t FlowRuleset::get_rule_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.size();
}

bool FlowRuleset::evaluate_rule(size_t rule_index, const FlowFeatures& features) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if(rule_index >= rules_.size()) return false;
    
    const auto& rule = rules_[rule_index];
    if(!rule->enabled || rule->conditions.empty()) return false;
    
    rule->evaluations++;
    
    // evaluate first condition
    bool result = evaluate_condition(rule->conditions[0], features);
    
    // evaluate remaining conditions with logic operator
    for(size_t i = 1; i < rule->conditions.size(); ++i) {
        bool current_result = evaluate_condition(rule->conditions[i], features);
        
        if(rule->logic_operator == FlowLogic::AND) {
            result = result && current_result;
        } else {
            result = result || current_result;
        }
    }
    
    if(result) {
        rule->matches++;
    }
    
    return result;
}

const FlowRule* FlowRuleset::get_rule(size_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if(index >= rules_.size()) return nullptr;
    return rules_[index].get();
}

bool FlowRuleset::parse_rule_string(const std::string& rule_str, FlowRule& rule) {
    // parse rule format: "sid:1001 msg:\"Port Scan Detected\" flow_iat_mean < 1000 AND syn_flag_count > 5"
    std::istringstream iss(rule_str);
    std::string token;
    
    rule.enabled = true;
    rule.priority = 3;
    rule.logic_operator = FlowLogic::AND;
    rule.conditions.clear();
    
    std::vector<std::string> tokens;
    while(iss >> token) {
        tokens.push_back(token);
    }
    
    for(size_t i = 0; i < tokens.size(); ++i) {
        const std::string& token = tokens[i];
        
        if(token.substr(0, 4) == "sid:") {
            rule.sid = std::stoul(token.substr(4));
        }
        else if(token.substr(0, 4) == "msg:") {
            // handle quoted message
            if(token.size() > 5 && token[4] == '"') {
                std::string msg = token.substr(5);
                // find closing quote in the same or subsequent tokens
                while(i < tokens.size() - 1 && msg.back() != '"') {
                    ++i;
                    msg += " " + tokens[i];
                }
                if(!msg.empty() && msg.back() == '"') {
                    msg.pop_back();
                }
                rule.msg = msg;
            }
        }
        else if(token.substr(0, 9) == "priority:") {
            rule.priority = std::stoul(token.substr(9));
        }
        else if(token == "OR") {
            rule.logic_operator = FlowLogic::OR;
        }
        else if(token == "AND") {
            rule.logic_operator = FlowLogic::AND;
            // Skip - handled above
        }
        else {
            // try to parse as condition: feature operator value
            // Only parse if we can verify this is a valid feature name
            if(i + 2 < tokens.size()) {
                // Check if this token is a valid condition type
                FlowConditionType cond_type = string_to_condition_type(token);
                FlowOperator op = string_to_operator(tokens[i + 1]);

                // Try to parse value - if it fails, skip this token
                try {
                    double value = std::stod(tokens[i + 2]);
                    rule.conditions.emplace_back(cond_type, op, value);
                    i += 2; // skip operator and value tokens
                } catch(const std::exception&) {
                    // Invalid value, skip this token
                }
            }
        }
    }
    
    return !rule.conditions.empty();
}

bool FlowRuleset::evaluate_condition(const FlowCondition& condition, const FlowFeatures& features) const {
    double feature_value = get_feature_value(features, condition.type);
    double rule_value = condition.value;
    
    switch(condition.operator_) {
        case FlowOperator::GT: return feature_value > rule_value;
        case FlowOperator::LT: return feature_value < rule_value;
        case FlowOperator::GTE: return feature_value >= rule_value;
        case FlowOperator::LTE: return feature_value <= rule_value;
        case FlowOperator::EQ: return feature_value == rule_value;
        case FlowOperator::NEQ: return feature_value != rule_value;
        default: return false;
    }
}

double FlowRuleset::get_feature_value(const FlowFeatures& features, FlowConditionType type) const {
    switch(type) {
        case FlowConditionType::FLOW_DURATION: return features.flow_duration;
        case FlowConditionType::FWD_PACKETS: return static_cast<double>(features.total_fwd_packets);
        case FlowConditionType::BWD_PACKETS: return static_cast<double>(features.total_bwd_packets);
        case FlowConditionType::FWD_BYTES: return static_cast<double>(features.total_fwd_bytes);
        case FlowConditionType::BWD_BYTES: return static_cast<double>(features.total_bwd_bytes);
        case FlowConditionType::PACKET_LENGTH_MEAN: return features.packet_length_mean;
        case FlowConditionType::PACKET_LENGTH_STD: return features.packet_length_std;
        case FlowConditionType::FWD_PACKET_LENGTH_MEAN: return features.fwd_packet_length_mean;
        case FlowConditionType::BWD_PACKET_LENGTH_MEAN: return features.bwd_packet_length_mean;
        case FlowConditionType::FLOW_BYTES_PER_SEC: return features.flow_bytes_per_sec;
        case FlowConditionType::FLOW_PACKETS_PER_SEC: return features.flow_packets_per_sec;
        case FlowConditionType::FLOW_IAT_MEAN: return features.flow_iat_mean;
        case FlowConditionType::FLOW_IAT_STD: return features.flow_iat_std;
        case FlowConditionType::FLOW_IAT_MIN: return features.flow_iat_min;
        case FlowConditionType::FLOW_IAT_MAX: return features.flow_iat_max;
        case FlowConditionType::FWD_IAT_MEAN: return features.fwd_iat_mean;
        case FlowConditionType::BWD_IAT_MEAN: return features.bwd_iat_mean;
        case FlowConditionType::SYN_FLAG_COUNT: return static_cast<double>(features.syn_flag_count);
        case FlowConditionType::ACK_FLAG_COUNT: return static_cast<double>(features.ack_flag_count);
        case FlowConditionType::FIN_FLAG_COUNT: return static_cast<double>(features.fin_flag_count);
        case FlowConditionType::RST_FLAG_COUNT: return static_cast<double>(features.rst_flag_count);
        case FlowConditionType::PSH_FLAG_COUNT: return static_cast<double>(features.psh_flag_count);
        case FlowConditionType::URG_FLAG_COUNT: return static_cast<double>(features.urg_flag_count);
        case FlowConditionType::DOWN_UP_RATIO: return features.down_up_ratio;
        case FlowConditionType::AVG_PACKET_SIZE: return features.avg_packet_size;
        default: return 0.0;
    }
}

FlowConditionType FlowRuleset::string_to_condition_type(const std::string& str) const {
    static const std::unordered_map<std::string, FlowConditionType> condition_map = {
        {"flow_duration", FlowConditionType::FLOW_DURATION},
        {"fwd_packets", FlowConditionType::FWD_PACKETS},
        {"bwd_packets", FlowConditionType::BWD_PACKETS},
        {"fwd_bytes", FlowConditionType::FWD_BYTES},
        {"bwd_bytes", FlowConditionType::BWD_BYTES},
        {"packet_length_mean", FlowConditionType::PACKET_LENGTH_MEAN},
        {"packet_length_std", FlowConditionType::PACKET_LENGTH_STD},
        {"fwd_packet_length_mean", FlowConditionType::FWD_PACKET_LENGTH_MEAN},
        {"bwd_packet_length_mean", FlowConditionType::BWD_PACKET_LENGTH_MEAN},
        {"flow_bytes_per_sec", FlowConditionType::FLOW_BYTES_PER_SEC},
        {"flow_packets_per_sec", FlowConditionType::FLOW_PACKETS_PER_SEC},
        {"flow_iat_mean", FlowConditionType::FLOW_IAT_MEAN},
        {"flow_iat_std", FlowConditionType::FLOW_IAT_STD},
        {"flow_iat_min", FlowConditionType::FLOW_IAT_MIN},
        {"flow_iat_max", FlowConditionType::FLOW_IAT_MAX},
        {"fwd_iat_mean", FlowConditionType::FWD_IAT_MEAN},
        {"bwd_iat_mean", FlowConditionType::BWD_IAT_MEAN},
        {"syn_flag_count", FlowConditionType::SYN_FLAG_COUNT},
        {"ack_flag_count", FlowConditionType::ACK_FLAG_COUNT},
        {"fin_flag_count", FlowConditionType::FIN_FLAG_COUNT},
        {"rst_flag_count", FlowConditionType::RST_FLAG_COUNT},
        {"psh_flag_count", FlowConditionType::PSH_FLAG_COUNT},
        {"urg_flag_count", FlowConditionType::URG_FLAG_COUNT},
        {"down_up_ratio", FlowConditionType::DOWN_UP_RATIO},
        {"avg_packet_size", FlowConditionType::AVG_PACKET_SIZE}
    };
    
    auto it = condition_map.find(str);
    return (it != condition_map.end()) ? it->second : FlowConditionType::FLOW_DURATION;
}

FlowOperator FlowRuleset::string_to_operator(const std::string& str) const {
    static const std::unordered_map<std::string, FlowOperator> operator_map = {
        {">", FlowOperator::GT},
        {"<", FlowOperator::LT},
        {">=", FlowOperator::GTE},
        {"<=", FlowOperator::LTE},
        {"==", FlowOperator::EQ},
        {"!=", FlowOperator::NEQ}
    };
    
    auto it = operator_map.find(str);
    return (it != operator_map.end()) ? it->second : FlowOperator::GT;
}

// FlowRuleEngine Implementation

FlowRuleEngine::FlowRuleEngine(int alert_capacity) 
    : ruleset_(std::make_unique<FlowRuleset>()),
      alert_queue_(std::make_unique<FlowAlertQueue>(alert_capacity)),
      running_(false),
      thread_created_(false) {
}

FlowRuleEngine::~FlowRuleEngine() {
    if(thread_created_ && running_.load()) {
        stop_engine_thread();
    }
}

bool FlowRuleEngine::start_engine_thread() {
    if(thread_created_) return false;
    
    running_.store(true);
    
    try {
        thread_ = std::thread(&FlowRuleEngine::engine_thread_func, this);
        thread_created_ = true;
        return true;
    } catch(const std::exception&) {
        running_.store(false);
        return false;
    }
}

void FlowRuleEngine::stop_engine_thread() {
    if(thread_created_) {
        running_.store(false);
        if(thread_.joinable()) {
            thread_.join();
        }
        thread_created_ = false;
    }
}

void FlowRuleEngine::process_flow_features(const FlowFeatures& features) {
    if(!ruleset_) return;
    
    total_features_processed_++;
    
    size_t rule_count = ruleset_->get_rule_count();
    for(size_t i = 0; i < rule_count; ++i) {
        total_evaluations_++;
        
        if(ruleset_->evaluate_rule(i, features)) {
            total_matches_++;
            
            // create alert
            FlowAlert alert;
            const FlowRule* rule = ruleset_->get_rule(i);
            if(rule) {
                alert.rule_id = rule->sid;
                alert.message = rule->msg;
                gettimeofday(&alert.timestamp, nullptr);
                alert.features = features;
                
                alert_queue_->enqueue(alert);
            }
        }
    }
}

bool FlowRuleEngine::get_next_alert(FlowAlert& alert) {
    return alert_queue_->try_dequeue(alert);
}

void FlowRuleEngine::engine_thread_func() {
    while(running_.load()) {
        // in a real implementation, this would wait for flow features
        // from Process 1. For now, we'll just sleep.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool FlowRuleEngine::evaluate_condition(const FlowCondition& condition, const FlowFeatures& features) {
    return ruleset_->evaluate_condition(condition, features);
}

double FlowRuleEngine::get_feature_value(const FlowFeatures& features, FlowConditionType type) {
    return ruleset_->get_feature_value(features, type);
}

// Utility Functions

const char* condition_type_to_string(FlowConditionType type) {
    switch(type) {
        case FlowConditionType::FLOW_DURATION: return "flow_duration";
        case FlowConditionType::FWD_PACKETS: return "fwd_packets";
        case FlowConditionType::BWD_PACKETS: return "bwd_packets";
        case FlowConditionType::FWD_BYTES: return "fwd_bytes";
        case FlowConditionType::BWD_BYTES: return "bwd_bytes";
        case FlowConditionType::PACKET_LENGTH_MEAN: return "packet_length_mean";
        case FlowConditionType::PACKET_LENGTH_STD: return "packet_length_std";
        case FlowConditionType::FWD_PACKET_LENGTH_MEAN: return "fwd_packet_length_mean";
        case FlowConditionType::BWD_PACKET_LENGTH_MEAN: return "bwd_packet_length_mean";
        case FlowConditionType::FLOW_BYTES_PER_SEC: return "flow_bytes_per_sec";
        case FlowConditionType::FLOW_PACKETS_PER_SEC: return "flow_packets_per_sec";
        case FlowConditionType::FLOW_IAT_MEAN: return "flow_iat_mean";
        case FlowConditionType::FLOW_IAT_STD: return "flow_iat_std";
        case FlowConditionType::FLOW_IAT_MIN: return "flow_iat_min";
        case FlowConditionType::FLOW_IAT_MAX: return "flow_iat_max";
        case FlowConditionType::FWD_IAT_MEAN: return "fwd_iat_mean";
        case FlowConditionType::BWD_IAT_MEAN: return "bwd_iat_mean";
        case FlowConditionType::SYN_FLAG_COUNT: return "syn_flag_count";
        case FlowConditionType::ACK_FLAG_COUNT: return "ack_flag_count";
        case FlowConditionType::FIN_FLAG_COUNT: return "fin_flag_count";
        case FlowConditionType::RST_FLAG_COUNT: return "rst_flag_count";
        case FlowConditionType::PSH_FLAG_COUNT: return "psh_flag_count";
        case FlowConditionType::URG_FLAG_COUNT: return "urg_flag_count";
        case FlowConditionType::DOWN_UP_RATIO: return "down_up_ratio";
        case FlowConditionType::AVG_PACKET_SIZE: return "avg_packet_size";
        default: return "unknown";
    }
}

const char* operator_to_string(FlowOperator op) {
    switch(op) {
        case FlowOperator::GT: return ">";
        case FlowOperator::LT: return "<";
        case FlowOperator::GTE: return ">=";
        case FlowOperator::LTE: return "<=";
        case FlowOperator::EQ: return "==";
        case FlowOperator::NEQ: return "!=";
        default: return "?";
    }
}
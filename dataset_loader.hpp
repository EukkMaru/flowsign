#ifndef DATASET_LOADER_HPP
#define DATASET_LOADER_HPP

#include "flow_analyzer.hpp"
#include "snortsharp_integration.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <chrono>

// flow identification key for packet-to-flow matching
struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    FlowKey(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, uint8_t proto)
        : src_ip(sip), dst_ip(dip), src_port(sp), dst_port(dp), protocol(proto) {}
    
    // bidirectional flow key - handles both directions
    FlowKey get_canonical() const {
        // create canonical key by ordering IPs
        if(src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port)) {
            return *this;
        } else {
            return FlowKey(dst_ip, src_ip, dst_port, src_port, protocol);
        }
    }
    
    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

// hash function for FlowKey
struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const {
        size_t h1 = std::hash<uint32_t>{}(key.src_ip);
        size_t h2 = std::hash<uint32_t>{}(key.dst_ip);
        size_t h3 = std::hash<uint16_t>{}(key.src_port);
        size_t h4 = std::hash<uint16_t>{}(key.dst_port);
        size_t h5 = std::hash<uint8_t>{}(key.protocol);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
    }
};

// dataset record from UNSW-NB15 CSV
struct DatasetRecord {
    // raw packet data
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    double timestamp;
    uint32_t packet_size;
    uint8_t tcp_flags;
    
    // flow-level features for validation
    double flow_duration;
    uint32_t total_fwd_packets;
    uint32_t total_bwd_packets;
    uint64_t total_fwd_bytes;
    uint64_t total_bwd_bytes;
    double flow_bytes_per_sec;
    double flow_packets_per_sec;
    double flow_iat_mean;
    double flow_iat_std;
    double fwd_iat_mean;
    double bwd_iat_mean;
    double packet_length_mean;
    double packet_length_std;
    
    // ground truth label
    std::string attack_category;
    bool is_attack; // binary classification
    
    DatasetRecord() : src_ip(0), dst_ip(0), src_port(0), dst_port(0), 
                     protocol(0), timestamp(0.0), packet_size(0), tcp_flags(0),
                     flow_duration(0.0), total_fwd_packets(0), total_bwd_packets(0),
                     total_fwd_bytes(0), total_bwd_bytes(0), flow_bytes_per_sec(0.0),
                     flow_packets_per_sec(0.0), flow_iat_mean(0.0), flow_iat_std(0.0),
                     fwd_iat_mean(0.0), bwd_iat_mean(0.0), packet_length_mean(0.0),
                     packet_length_std(0.0), is_attack(false) {}
};

// flow matching result
struct FlowMatchResult {
    bool matched;
    double timestamp_diff;
    double feature_similarity;
    std::string mismatch_reason;
    
    FlowMatchResult() : matched(false), timestamp_diff(0.0), feature_similarity(0.0) {}
};

// matching tolerances for packet-to-flow synchronization
struct MatchingTolerances {
    double timestamp_tolerance_sec = 1.0;        // allow 1 second timestamp difference
    double feature_similarity_threshold = 0.85;  // require 85% feature similarity
    uint32_t packet_count_tolerance = 2;         // allow +/- 2 packets difference
    double byte_count_tolerance_percent = 0.1;   // allow 10% byte count difference
    
    MatchingTolerances() = default;
    MatchingTolerances(double ts_tol, double feat_sim, uint32_t pkt_tol, double byte_tol)
        : timestamp_tolerance_sec(ts_tol), feature_similarity_threshold(feat_sim),
          packet_count_tolerance(pkt_tol), byte_count_tolerance_percent(byte_tol) {}
};

// evaluation metrics for benchmarking
struct EvaluationMetrics {
    uint32_t true_positives = 0;
    uint32_t true_negatives = 0;
    uint32_t false_positives = 0;
    uint32_t false_negatives = 0;
    
    uint32_t total_flows_processed = 0;
    uint32_t matched_flows = 0;
    uint32_t unmatched_flows = 0;
    
    double precision() const {
        return (true_positives + false_positives) > 0 ? 
               static_cast<double>(true_positives) / (true_positives + false_positives) : 0.0;
    }
    
    double recall() const {
        return (true_positives + false_negatives) > 0 ?
               static_cast<double>(true_positives) / (true_positives + false_negatives) : 0.0;
    }
    
    double f1_score() const {
        double p = precision();
        double r = recall();
        return (p + r) > 0 ? 2.0 * (p * r) / (p + r) : 0.0;
    }
    
    double accuracy() const {
        uint32_t total = true_positives + true_negatives + false_positives + false_negatives;
        return total > 0 ? static_cast<double>(true_positives + true_negatives) / total : 0.0;
    }
    
    double matching_rate() const {
        return total_flows_processed > 0 ?
               static_cast<double>(matched_flows) / total_flows_processed : 0.0;
    }
};

class DatasetLoader {
private:
    std::vector<DatasetRecord> records_;
    std::unordered_map<FlowKey, std::vector<size_t>, FlowKeyHash> flow_index_;
    MatchingTolerances tolerances_;
    
public:
    explicit DatasetLoader(const MatchingTolerances& tolerances = MatchingTolerances());
    ~DatasetLoader() = default;
    
    // dataset loading
    bool load_unsw_nb15_csv(const std::string& csv_path);
    bool load_custom_csv(const std::string& csv_path, const std::vector<std::string>& column_mapping);
    
    // packet generation from dataset
    std::vector<SnortPacket> generate_packets_from_records(size_t max_packets = 0);
    SnortPacket convert_record_to_packet(const DatasetRecord& record);
    
    // flow matching for desync handling
    FlowMatchResult match_flow_to_record(const FlowFeatures& features, 
                                        const FlowKey& flow_key,
                                        double flow_start_time);
    
    std::vector<size_t> find_candidate_records(const FlowKey& flow_key, 
                                             double timestamp,
                                             double time_window = 2.0);
    
    // evaluation and benchmarking  
    EvaluationMetrics evaluate_against_dataset(SnortSharpEngine& engine,
                                              size_t max_records = 0,
                                              bool verbose = false);
    
    // feature comparison utilities
    double calculate_feature_similarity(const FlowFeatures& generated_features,
                                       const DatasetRecord& dataset_record);
    
    bool validate_flow_match(const FlowFeatures& features,
                           const DatasetRecord& record,
                           const MatchingTolerances& tolerances);
    
    // statistics and reporting
    void print_dataset_summary() const;
    void print_evaluation_report(const EvaluationMetrics& metrics) const;
    
    // getters
    size_t get_record_count() const { return records_.size(); }
    const DatasetRecord& get_record(size_t index) const { return records_.at(index); }
    const MatchingTolerances& get_tolerances() const { return tolerances_; }
    
private:
    // CSV parsing helpers
    std::vector<std::string> parse_csv_line(const std::string& line);
    uint32_t parse_ip_address(const std::string& ip_str);
    double parse_double_safe(const std::string& str);
    uint32_t parse_uint_safe(const std::string& str);
    uint8_t parse_tcp_flags(const std::string& flags_str);
    
    // indexing helpers
    void build_flow_index();
    FlowKey extract_flow_key(const DatasetRecord& record);
    
    // matching helpers
    double calculate_timestamp_diff(double dataset_time, double flow_time);
    bool is_within_tolerance(double value1, double value2, double tolerance_percent);
};

// utility functions
std::string attack_category_to_string(const std::string& category);
std::string evaluation_summary_to_string(const EvaluationMetrics& metrics);

#endif // DATASET_LOADER_HPP
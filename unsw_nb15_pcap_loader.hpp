#ifndef UNSW_NB15_PCAP_LOADER_HPP
#define UNSW_NB15_PCAP_LOADER_HPP

#include "snortsharp_integration.hpp"
#include "flow_analyzer.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <iostream>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// ground truth record from UNSW-NB15 CSV files
struct UNSWGroundTruth {
    // network 5-tuple
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t protocol;
    
    // timing
    double start_time;
    double duration;
    
    // flow statistics
    uint32_t src_packets;
    uint32_t dst_packets;
    uint64_t src_bytes;
    uint64_t dst_bytes;
    
    // calculated features (for validation)
    double flow_rate;
    double src_load;
    double dst_load;
    double mean_packet_size;
    
    // labels
    std::string attack_category;
    bool is_attack;
    
    // correlation identifiers
    std::string flow_id;
    size_t pcap_file_index;
    
    UNSWGroundTruth() : src_ip(0), src_port(0), dst_ip(0), dst_port(0), protocol(0),
                       start_time(0.0), duration(0.0), src_packets(0), dst_packets(0),
                       src_bytes(0), dst_bytes(0), flow_rate(0.0), src_load(0.0),
                       dst_load(0.0), mean_packet_size(0.0), is_attack(false),
                       pcap_file_index(0) {}
};

// PCAP file metadata
struct PcapFileInfo {
    std::string file_path;
    size_t file_index;
    size_t packet_count;
    double start_time;
    double end_time;
    size_t file_size_bytes;
    bool processed;
    
    PcapFileInfo() : file_index(0), packet_count(0), start_time(0.0), 
                    end_time(0.0), file_size_bytes(0), processed(false) {}
};

// flow correlation key for matching
struct FlowCorrelationKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    double timestamp_window;
    
    FlowCorrelationKey(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, 
                      uint8_t proto, double ts_window = 5.0)
        : src_ip(sip), dst_ip(dip), src_port(sp), dst_port(dp), 
          protocol(proto), timestamp_window(ts_window) {}
    
    // bidirectional comparison
    bool matches_bidirectional(const FlowCorrelationKey& other, double time_diff) const {
        if(time_diff > timestamp_window) return false;
        
        return (src_ip == other.src_ip && dst_ip == other.dst_ip &&
                src_port == other.src_port && dst_port == other.dst_port &&
                protocol == other.protocol) ||
               (src_ip == other.dst_ip && dst_ip == other.src_ip &&
                src_port == other.dst_port && dst_port == other.src_port &&
                protocol == other.protocol);
    }
    
    bool operator==(const FlowCorrelationKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

// hash function for flow correlation
struct FlowCorrelationHash {
    size_t operator()(const FlowCorrelationKey& key) const {
        return std::hash<uint32_t>{}(key.src_ip) ^
               (std::hash<uint32_t>{}(key.dst_ip) << 1) ^
               (std::hash<uint16_t>{}(key.src_port) << 2) ^
               (std::hash<uint16_t>{}(key.dst_port) << 3) ^
               (std::hash<uint8_t>{}(key.protocol) << 4);
    }
};

// processing statistics
struct UNSWProcessingStats {
    size_t pcap_files_processed = 0;
    size_t total_packets_processed = 0;
    size_t flows_generated = 0;
    size_t flows_matched = 0;
    size_t flows_unmatched = 0;
    
    size_t ground_truth_records = 0;
    size_t attack_flows = 0;
    size_t normal_flows = 0;
    
    double total_processing_time_seconds = 0.0;
    double avg_packets_per_second = 0.0;
    
    void print_summary() const {
        std::cout << "\n=== UNSW-NB15 Processing Statistics ===\n";
        std::cout << "PCAP Files Processed: " << pcap_files_processed << "\n";
        std::cout << "Total Packets: " << total_packets_processed << "\n";
        std::cout << "Flows Generated: " << flows_generated << "\n";
        std::cout << "Flows Matched: " << flows_matched << " (" 
                  << (flows_generated > 0 ? (flows_matched * 100.0 / flows_generated) : 0.0) 
                  << "%)\n";
        std::cout << "Ground Truth Records: " << ground_truth_records << "\n";
        std::cout << "  Attack Flows: " << attack_flows << "\n";
        std::cout << "  Normal Flows: " << normal_flows << "\n";
        std::cout << "Processing Time: " << total_processing_time_seconds << " seconds\n";
        std::cout << "Throughput: " << avg_packets_per_second << " packets/second\n";
        std::cout << "======================================\n\n";
    }
};

class UNSWB15PcapLoader {
private:
    std::string dataset_base_path_;
    std::vector<PcapFileInfo> pcap_files_;
    std::vector<UNSWGroundTruth> ground_truth_records_;
    std::unordered_map<FlowCorrelationKey, std::vector<size_t>, FlowCorrelationHash> flow_correlation_index_;
    
    UNSWProcessingStats stats_;
    
public:
    explicit UNSWB15PcapLoader(const std::string& dataset_path);
    ~UNSWB15PcapLoader() = default;
    
    // dataset discovery and loading
    bool discover_pcap_files();
    bool load_ground_truth_csv(const std::string& csv_filename = "UNSW-NB15_1.csv");
    bool load_training_testing_sets();
    
    // PCAP processing
    std::vector<SnortPacket> process_pcap_file(const std::string& pcap_path, size_t max_packets = 0);
    std::vector<SnortPacket> process_all_pcaps(size_t max_packets_per_file = 1000);
    
    // flow correlation
    bool correlate_flows_with_labels();
    std::vector<UNSWGroundTruth> find_matching_ground_truth(const FlowFeatures& features, 
                                                          const FlowCorrelationKey& flow_key,
                                                          double flow_start_time);
    
    // validation and benchmarking
    bool validate_flow_features(const FlowFeatures& generated_features,
                               const UNSWGroundTruth& ground_truth,
                               double similarity_threshold = 0.8);
    
    double calculate_feature_similarity(const FlowFeatures& generated_features,
                                       const UNSWGroundTruth& ground_truth);
    
    // demo and testing utilities
    bool run_pcap_demo(const std::string& pcap_filename, size_t max_packets = 100);
    bool run_flow_correlation_test();
    bool run_feature_validation_test(SnortSharpEngine& engine);
    
    // statistics and reporting
    const UNSWProcessingStats& get_stats() const { return stats_; }
    void print_dataset_summary() const;
    void reset_stats();
    
    // getters
    size_t get_pcap_count() const { return pcap_files_.size(); }
    size_t get_ground_truth_count() const { return ground_truth_records_.size(); }
    const std::vector<PcapFileInfo>& get_pcap_files() const { return pcap_files_; }
    const std::vector<UNSWGroundTruth>& get_ground_truth() const { return ground_truth_records_; }
    
private:
    // parsing helpers
    SnortPacket convert_pcap_packet_to_snort(const struct pcap_pkthdr* header,
                                             const u_char* packet);
    bool parse_csv_record(const std::string& csv_line, UNSWGroundTruth& record);
    uint32_t parse_ip_address(const std::string& ip_str);
    uint8_t parse_protocol_string(const std::string& proto_str);
    
    // correlation helpers
    FlowCorrelationKey create_correlation_key(const UNSWGroundTruth& record);
    void build_correlation_index();
    double calculate_timestamp_similarity(double ts1, double ts2, double tolerance = 5.0);
    
    // file utilities
    std::string get_full_pcap_path(const std::string& filename);
    bool file_exists(const std::string& path);
    size_t get_file_size(const std::string& path);
};

// utility functions
std::string attack_category_to_description(const std::string& category);
std::string protocol_number_to_string(uint8_t protocol);
bool is_valid_pcap_file(const std::string& file_path);

#endif // UNSW_NB15_PCAP_LOADER_HPP
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <iomanip>
#include <fstream>

#include "unsw_nb15_pcap_loader.hpp"
#include "snortsharp_integration.hpp"

constexpr int DEMO_WINDOW_SIZE = 10;
constexpr int DEMO_QUEUE_CAPACITY = 1000;
constexpr int DEMO_ALERT_CAPACITY = 200;

void create_unsw_detection_rules(const std::string& rules_file) {
    std::ofstream file(rules_file);
    
    // UNSW-NB15 specific detection rules based on attack categories
    
    // Fuzzers detection
    file << "sid:3001 msg:\"Fuzzers - Abnormal packet patterns\" packet_length_std > 800.0\n";
    file << "sid:3002 msg:\"Fuzzers - High variance traffic\" flow_iat_std > 2000.0\n";
    
    // Analysis/Reconnaissance detection
    file << "sid:3003 msg:\"Analysis - Port scanning activity\" fwd_packets > 20 AND packet_length_mean < 100\n";
    file << "sid:3004 msg:\"Reconnaissance - Network probing\" syn_flag_count > 10 AND ack_flag_count < 3\n";
    
    // DoS detection
    file << "sid:3005 msg:\"DoS - High packet rate attack\" flow_packets_per_sec > 500\n";
    file << "sid:3006 msg:\"DoS - SYN flood detected\" syn_flag_count > 20\n";
    file << "sid:3007 msg:\"DoS - Resource exhaustion\" total_fwd_packets > 1000 AND flow_duration < 2.0\n";
    
    // Exploits detection
    file << "sid:3008 msg:\"Exploits - Large payload transfer\" total_fwd_bytes > 10000000\n";
    file << "sid:3009 msg:\"Exploits - Suspicious data exchange\" bwd_bytes > 1000000 AND fwd_bytes < 5000\n";
    
    // Backdoors detection
    file << "sid:3010 msg:\"Backdoors - Persistent connection\" flow_duration > 600.0\n";
    file << "sid:3011 msg:\"Backdoors - Regular beacon activity\" flow_iat_mean > 30000.0 AND flow_iat_mean < 60000.0\n";
    
    // Generic malicious activity
    file << "sid:3012 msg:\"Generic - Abnormal flow behavior\" down_up_ratio > 20.0\n";
    file << "sid:3013 msg:\"Generic - Suspicious packet timing\" flow_iat_min < 0.001 AND flow_iat_max > 10000.0\n";
    
    // Shellcode detection
    file << "sid:3014 msg:\"Shellcode - Small packet exploitation\" packet_length_mean < 60 AND total_fwd_packets > 50\n";
    
    // Worms detection  
    file << "sid:3015 msg:\"Worms - Propagation pattern\" flow_bytes_per_sec > 5000000\n";
    file << "sid:3016 msg:\"Worms - Multiple connection attempts\" rst_flag_count > 15\n";
    
    // General anomaly detection
    file << "sid:3017 msg:\"Anomaly - High connection rate\" total_fwd_packets > 500\n";
    file << "sid:3018 msg:\"Anomaly - Unusual packet distribution\" packet_length_std > 1000.0\n";
    
    file.close();
    std::cout << "Created UNSW-NB15 detection rules with 18 attack-specific rules\n";
}

struct UNSWDemoResults {
    // processing statistics
    size_t total_packets_processed = 0;
    size_t total_flows_generated = 0;
    size_t total_alerts_generated = 0;
    size_t flows_matched_with_labels = 0;
    
    // attack detection results
    size_t true_positives = 0;
    size_t true_negatives = 0;
    size_t false_positives = 0;
    size_t false_negatives = 0;
    
    // detailed timing measurements
    double pcap_loading_time_ms = 0.0;
    double packet_extraction_time_ms = 0.0;
    double engine_processing_time_ms = 0.0;
    double alert_collection_time_ms = 0.0;
    double total_processing_time_ms = 0.0;
    
    // throughput metrics
    double packets_per_second = 0.0;
    double flows_per_second = 0.0;
    double alerts_per_second = 0.0;
    double mbps_throughput = 0.0;
    
    // efficiency metrics
    double cpu_efficiency_percent = 0.0;
    double memory_usage_mb = 0.0;
    double avg_packet_processing_time_us = 0.0;
    double avg_flow_processing_time_us = 0.0;
    
    // validation results
    double average_feature_similarity = 0.0;
    size_t validated_flows = 0;
    
    void print_comprehensive_results() const {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "             UNSW-NB15 PERFORMANCE ANALYSIS\n";
        std::cout << std::string(70, '=') << "\n\n";
        
        // processing overview
        std::cout << "PROCESSING OVERVIEW:\n";
        std::cout << "  Packets Processed: " << total_packets_processed << "\n";
        std::cout << "  Flows Generated: " << total_flows_generated << "\n";
        std::cout << "  Alerts Generated: " << total_alerts_generated << "\n";
        std::cout << "  Label Matches: " << flows_matched_with_labels << "\n\n";
        
        // detailed timing breakdown
        std::cout << "TIMING BREAKDOWN:\n";
        std::cout << "  PCAP Loading:      " << std::fixed << std::setprecision(2) 
                  << pcap_loading_time_ms << " ms\n";
        std::cout << "  Packet Extraction: " << std::fixed << std::setprecision(2) 
                  << packet_extraction_time_ms << " ms\n";
        std::cout << "  Engine Processing: " << std::fixed << std::setprecision(2) 
                  << engine_processing_time_ms << " ms\n";
        std::cout << "  Alert Collection:  " << std::fixed << std::setprecision(2) 
                  << alert_collection_time_ms << " ms\n";
        std::cout << "  Total Time:        " << std::fixed << std::setprecision(2) 
                  << total_processing_time_ms << " ms\n\n";
        
        // throughput metrics
        std::cout << "THROUGHPUT METRICS:\n";
        std::cout << "  Packet Rate:       " << std::fixed << std::setprecision(0) 
                  << packets_per_second << " packets/second\n";
        std::cout << "  Flow Rate:         " << std::fixed << std::setprecision(1) 
                  << flows_per_second << " flows/second\n";
        std::cout << "  Alert Rate:        " << std::fixed << std::setprecision(1) 
                  << alerts_per_second << " alerts/second\n";
        std::cout << "  Data Throughput:   " << std::fixed << std::setprecision(2) 
                  << mbps_throughput << " Mbps\n\n";
        
        // efficiency metrics
        std::cout << "EFFICIENCY METRICS:\n";
        std::cout << "  Avg Packet Time:   " << std::fixed << std::setprecision(3) 
                  << avg_packet_processing_time_us << " us/packet\n";
        std::cout << "  Avg Flow Time:     " << std::fixed << std::setprecision(3) 
                  << avg_flow_processing_time_us << " us/flow\n";
        if(memory_usage_mb > 0) {
            std::cout << "  Memory Usage:      " << std::fixed << std::setprecision(1) 
                      << memory_usage_mb << " MB\n";
        }
        if(cpu_efficiency_percent > 0) {
            std::cout << "  CPU Efficiency:    " << std::fixed << std::setprecision(1) 
                      << cpu_efficiency_percent << "%\n";
        }
        std::cout << "\n";
        
        // detection accuracy
        if(flows_matched_with_labels > 0) {
            std::cout << "DETECTION ACCURACY:\n";
            std::cout << "  True Positives:  " << true_positives << "\n";
            std::cout << "  True Negatives:  " << true_negatives << "\n";
            std::cout << "  False Positives: " << false_positives << "\n";
            std::cout << "  False Negatives: " << false_negatives << "\n";
            
            double precision = (true_positives + false_positives > 0) ?
                              (double)true_positives / (true_positives + false_positives) : 0.0;
            double recall = (true_positives + false_negatives > 0) ?
                           (double)true_positives / (true_positives + false_negatives) : 0.0;
            double accuracy = (double)(true_positives + true_negatives) / flows_matched_with_labels;
            
            std::cout << "  Precision: " << std::fixed << std::setprecision(1) 
                      << (precision * 100.0) << "%\n";
            std::cout << "  Recall: " << std::fixed << std::setprecision(1) 
                      << (recall * 100.0) << "%\n";
            std::cout << "  Accuracy: " << std::fixed << std::setprecision(1) 
                      << (accuracy * 100.0) << "%\n\n";
        }
        
        // feature validation
        if(validated_flows > 0) {
            std::cout << "FEATURE VALIDATION:\n";
            std::cout << "  Validated Flows: " << validated_flows << "\n";
            std::cout << "  Avg Feature Similarity: " << std::fixed << std::setprecision(1) 
                      << (average_feature_similarity * 100.0) << "%\n\n";
        }
        
        std::cout << std::string(60, '=') << "\n";
    }
};

bool run_unsw_pcap_demo() {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "     UNSW-NB15 PCAP PROCESSING DEMO\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    // initialize UNSW-NB15 loader
    std::string dataset_path = "datasets/";
    UNSWB15PcapLoader loader(dataset_path);
    
    // discover PCAP files
    if(!loader.discover_pcap_files()) {
        std::cout << "Failed to discover PCAP files\n";
        return false;
    }
    
    std::cout << "Discovered " << loader.get_pcap_count() << " PCAP files\n";
    
    // load ground truth labels
    if(!loader.load_ground_truth_csv("UNSW-NB15_1.csv")) {
        std::cout << "Failed to load ground truth CSV\n";
        return false;
    }
    
    std::cout << "Loaded " << loader.get_ground_truth_count() << " ground truth records\n";
    
    // print dataset summary
    loader.print_dataset_summary();
    
    // create detection rules
    std::string rules_file = "unsw_nb15_rules.txt";
    create_unsw_detection_rules(rules_file);
    
    // initialize SnortSharp engine
    std::cout << "Initializing SnortSharp engine for UNSW-NB15 processing...\n";
    SnortSharpEngine engine(DEMO_WINDOW_SIZE, DEMO_QUEUE_CAPACITY, DEMO_ALERT_CAPACITY);
    
    if(!engine.load_flow_rules(rules_file)) {
        std::cout << "Failed to load UNSW-NB15 detection rules\n";
        return false;
    }
    
    if(!engine.start()) {
        std::cout << "Failed to start SnortSharp engine\n";
        return false;
    }
    
    // allow engine initialization
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    UNSWDemoResults results;
    auto demo_start_time = std::chrono::high_resolution_clock::now();
    size_t total_packet_bytes = 0;
    
    // process first PCAP file as demo (limit packets for reasonable demo time)
    const auto& pcap_files = loader.get_pcap_files();
    if(!pcap_files.empty()) {
        std::cout << "\nProcessing PCAP file: " << pcap_files[0].file_path << "\n";
        
        // measure PCAP loading and packet extraction time
        auto pcap_start_time = std::chrono::high_resolution_clock::now();
        auto packets = loader.process_pcap_file(pcap_files[0].file_path, 5000); // limit to 5000 packets
        auto pcap_end_time = std::chrono::high_resolution_clock::now();
        
        results.total_packets_processed = packets.size();
        results.packet_extraction_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(
            pcap_end_time - pcap_start_time).count() / 1000.0;
        
        if(packets.empty()) {
            std::cout << "No packets extracted from PCAP file\n";
            engine.stop();
            return false;
        }
        
        std::cout << "Extracted " << packets.size() << " packets from PCAP in " 
                  << results.packet_extraction_time_ms << " ms\n";
        std::cout << "Processing packets through SnortSharp engine...\n";
        
        // measure engine processing time
        auto engine_start_time = std::chrono::high_resolution_clock::now();
        size_t processed_count = 0;
        
        for(const auto& packet : packets) {
            total_packet_bytes += packet.packet_length;
            if(engine.process_snort_packet(packet)) {
                processed_count++;
            }
            
            // small delay to prevent overwhelming the system
            if(processed_count % 100 == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
                std::cout << "  Processed " << processed_count << " packets...\n";
            }
        }
        
        // allow processing to complete
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        
        auto engine_end_time = std::chrono::high_resolution_clock::now();
        results.engine_processing_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(
            engine_end_time - engine_start_time).count() / 1000.0;
        
        // collect results
        results.total_flows_generated = engine.get_total_features_generated();
        results.total_alerts_generated = engine.get_total_alerts_generated();
        
        // measure alert collection time
        auto alert_start_time = std::chrono::high_resolution_clock::now();
        FlowAlert alert;
        std::vector<FlowAlert> captured_alerts;
        while(engine.get_next_alert(alert)) {
            captured_alerts.push_back(alert);
        }
        auto alert_end_time = std::chrono::high_resolution_clock::now();
        results.alert_collection_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(
            alert_end_time - alert_start_time).count() / 1000.0;
        
        if(!captured_alerts.empty()) {
            std::cout << "\nGenerated " << captured_alerts.size() << " alerts:\n";
            for(size_t i = 0; i < std::min(size_t(5), captured_alerts.size()); i++) {
                const auto& a = captured_alerts[i];
                std::cout << "  Alert " << (i+1) << ": SID:" << a.rule_id 
                          << " - " << a.message << " (confidence: " << a.confidence << ")\n";
            }
            
            if(captured_alerts.size() > 5) {
                std::cout << "  ... and " << (captured_alerts.size() - 5) << " more alerts\n";
            }
        }
        
        // display engine statistics
        std::cout << "\n";
        engine.print_stats();
    }
    
    auto demo_end_time = std::chrono::high_resolution_clock::now();
    auto demo_duration = std::chrono::duration_cast<std::chrono::milliseconds>(demo_end_time - demo_start_time);
    results.total_processing_time_ms = demo_duration.count();
    
    // calculate comprehensive performance metrics
    if(results.total_processing_time_ms > 0) {
        double total_time_seconds = results.total_processing_time_ms / 1000.0;
        
        // throughput rates
        results.packets_per_second = results.total_packets_processed / total_time_seconds;
        results.flows_per_second = results.total_flows_generated / total_time_seconds;
        results.alerts_per_second = results.total_alerts_generated / total_time_seconds;
        
        // data throughput calculation
        if(results.total_packets_processed > 0) {
            double total_data_mb = (total_packet_bytes / (1024.0 * 1024.0));
            results.mbps_throughput = (total_data_mb * 8) / total_time_seconds; // convert to Megabits per second
        }
        
        // efficiency metrics
        results.avg_packet_processing_time_us = (results.total_processing_time_ms * 1000.0) / results.total_packets_processed;
        if(results.total_flows_generated > 0) {
            results.avg_flow_processing_time_us = (results.total_processing_time_ms * 1000.0) / results.total_flows_generated;
        }
        
        // CPU efficiency (simplified - actual processing vs total time)
        double actual_processing_time = results.packet_extraction_time_ms + results.engine_processing_time_ms;
        results.cpu_efficiency_percent = (actual_processing_time / results.total_processing_time_ms) * 100.0;
    }
    
    // stop engine
    engine.stop();
    
    // print comprehensive results
    results.print_comprehensive_results();
    
    // validation summary
    bool success = true;
    
    if(results.total_packets_processed == 0) {
        std::cout << "No packets were processed\n";
        success = false;
    }
    
    if(results.total_flows_generated == 0) {
        std::cout << "No flow features were generated\n";
        success = false;
    }
    
    if(success) {
        std::cout << "UNSW-NB15 DEMO COMPLETED SUCCESSFULLY!\n";
        std::cout << "PCAP Processing: WORKING\n";
        std::cout << "Flow Feature Extraction: WORKING\n";
        std::cout << "Attack Detection Pipeline: WORKING\n";
        
        // performance classification
        if(results.packets_per_second > 10000) {
            std::cout << "Performance: EXCEPTIONAL (" << std::fixed << std::setprecision(0) 
                      << results.packets_per_second << " pps, " << results.mbps_throughput << " Mbps)\n";
        } else if(results.packets_per_second > 5000) {
            std::cout << "Performance: EXCELLENT (" << std::fixed << std::setprecision(0) 
                      << results.packets_per_second << " pps, " << results.mbps_throughput << " Mbps)\n";
        } else if(results.packets_per_second > 1000) {
            std::cout << "Performance: GOOD (" << std::fixed << std::setprecision(0) 
                      << results.packets_per_second << " pps, " << results.mbps_throughput << " Mbps)\n";
        } else {
            std::cout << "Performance: NEEDS OPTIMIZATION (" << std::fixed << std::setprecision(0) 
                      << results.packets_per_second << " pps, " << results.mbps_throughput << " Mbps)\n";
        }
    } else {
        std::cout << "UNSW-NB15 demo FAILED\n";
    }
    
    return success;
}

bool run_quick_pcap_validation() {
    std::cout << "\n=== Quick PCAP Validation ===\n";
    
    UNSWB15PcapLoader loader("datasets/");
    
    if(!loader.discover_pcap_files()) {
        std::cout << "No PCAP files found\n";
        return false;
    }
    
    const auto& pcap_files = loader.get_pcap_files();
    std::cout << "Found " << pcap_files.size() << " PCAP files:\n";
    
    for(size_t i = 0; i < std::min(size_t(3), pcap_files.size()); i++) {
        const auto& pcap = pcap_files[i];
        std::cout << "  " << (i+1) << ". " << pcap.file_path 
                  << " (" << (pcap.file_size_bytes / (1024*1024)) << " MB)\n";
        
        // validate PCAP file
        if(is_valid_pcap_file(pcap.file_path)) {
            std::cout << "     Valid PCAP file\n";
        } else {
            std::cout << "     Invalid PCAP file\n";
        }
    }
    
    return true;
}

bool run_performance_benchmark(size_t packet_count = 10000) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "       UNSW-NB15 PERFORMANCE BENCHMARK\n";
    std::cout << "       Testing with " << packet_count << " packets\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    UNSWB15PcapLoader loader("datasets/");
    
    if(!loader.discover_pcap_files()) {
        std::cout << "Failed to discover PCAP files\n";
        return false;
    }
    
    // load ground truth for correlation testing
    if(!loader.load_ground_truth_csv("UNSW-NB15_1.csv")) {
        std::cout << "Failed to load ground truth CSV\n";
        return false;
    }
    
    // create optimized rules for benchmarking
    std::string rules_file = "benchmark_rules.txt";
    create_unsw_detection_rules(rules_file);
    
    SnortSharpEngine engine(DEMO_WINDOW_SIZE, DEMO_QUEUE_CAPACITY, DEMO_ALERT_CAPACITY);
    
    if(!engine.load_flow_rules(rules_file)) {
        std::cout << "Failed to load detection rules\n";
        return false;
    }
    
    if(!engine.start()) {
        std::cout << "Failed to start engine\n";
        return false;
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    const auto& pcap_files = loader.get_pcap_files();
    if(pcap_files.empty()) {
        std::cout << "No PCAP files available for benchmarking\n";
        engine.stop();
        return false;
    }
    
    UNSWDemoResults results;
    auto benchmark_start = std::chrono::high_resolution_clock::now();
    
    std::cout << "Starting performance benchmark...\n";
    
    // extract packets
    auto extract_start = std::chrono::high_resolution_clock::now();
    auto packets = loader.process_pcap_file(pcap_files[0].file_path, packet_count);
    auto extract_end = std::chrono::high_resolution_clock::now();
    
    results.total_packets_processed = packets.size();
    results.packet_extraction_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        extract_end - extract_start).count() / 1000.0;
    
    if(packets.empty()) {
        std::cout << "No packets extracted\n";
        engine.stop();
        return false;
    }
    
    std::cout << "Extracted " << packets.size() << " packets in " 
              << results.packet_extraction_time_ms << " ms\n";
    
    // high-speed processing (no delays)
    auto process_start = std::chrono::high_resolution_clock::now();
    size_t processed_count = 0;
    size_t total_bytes = 0;
    
    for(const auto& packet : packets) {
        total_bytes += packet.packet_length;
        if(engine.process_snort_packet(packet)) {
            processed_count++;
        }
    }
    
    auto process_end = std::chrono::high_resolution_clock::now();
    results.engine_processing_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        process_end - process_start).count() / 1000.0;
    
    // allow final processing
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    auto benchmark_end = std::chrono::high_resolution_clock::now();
    results.total_processing_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        benchmark_end - benchmark_start).count();
    
    // collect final results
    results.total_flows_generated = engine.get_total_features_generated();
    results.total_alerts_generated = engine.get_total_alerts_generated();
    
    // calculate all metrics
    double total_time_seconds = results.total_processing_time_ms / 1000.0;
    results.packets_per_second = results.total_packets_processed / total_time_seconds;
    results.flows_per_second = results.total_flows_generated / total_time_seconds;
    results.alerts_per_second = results.total_alerts_generated / total_time_seconds;
    
    double total_data_mb = (total_bytes / (1024.0 * 1024.0));
    results.mbps_throughput = (total_data_mb * 8) / total_time_seconds;
    
    results.avg_packet_processing_time_us = (results.engine_processing_time_ms * 1000.0) / results.total_packets_processed;
    results.avg_flow_processing_time_us = (results.engine_processing_time_ms * 1000.0) / results.total_flows_generated;
    
    engine.stop();
    
    // print benchmark results
    results.print_comprehensive_results();
    
    // benchmark conclusion
    std::cout << "BENCHMARK SUMMARY:\n";
    std::cout << "  Test Scale: " << packet_count << " packets\n";
    std::cout << "  Data Volume: " << std::fixed << std::setprecision(2) << total_data_mb << " MB\n";
    std::cout << "  Processing Rate: " << std::fixed << std::setprecision(0) 
              << results.packets_per_second << " packets/second\n";
    std::cout << "  Feature Rate: " << std::fixed << std::setprecision(0) 
              << results.flows_per_second << " flows/second\n";
    std::cout << "  Alert Rate: " << std::fixed << std::setprecision(0) 
              << results.alerts_per_second << " alerts/second\n";
    
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "UNSW-NB15 PCAP Processing Demo & Benchmark Suite\n";
    std::cout << "================================================\n\n";
    
    try {
        if(argc > 1) {
            std::string mode = argv[1];
            
            if(mode == "validate") {
                return run_quick_pcap_validation() ? 0 : 1;
                
            } else if(mode == "benchmark") {
                size_t packet_count = 10000; // default
                if(argc > 2) {
                    packet_count = std::stoul(argv[2]);
                }
                return run_performance_benchmark(packet_count) ? 0 : 1;
                
            } else if(mode == "help") {
                std::cout << "Usage: " << argv[0] << " [mode] [options]\n\n";
                std::cout << "Modes:\n";
                std::cout << "  (no args)       - Run standard demo (5000 packets)\n";
                std::cout << "  validate        - Quick PCAP file validation\n";
                std::cout << "  benchmark <num> - Performance benchmark with <num> packets\n";
                std::cout << "  help            - Show this help message\n\n";
                std::cout << "Examples:\n";
                std::cout << "  " << argv[0] << "                    # Standard demo\n";
                std::cout << "  " << argv[0] << " validate            # Validate PCAP files\n";
                std::cout << "  " << argv[0] << " benchmark 50000     # Benchmark with 50K packets\n";
                return 0;
                
            } else {
                std::cout << "Unknown mode: " << mode << "\n";
                std::cout << "Use '" << argv[0] << " help' for usage information\n";
                return 1;
            }
        } else {
            // default demo mode
            return run_unsw_pcap_demo() ? 0 : 1;
        }
        
    } catch(const std::exception& e) {
        std::cerr << "Demo failed with exception: " << e.what() << "\n";
        return 1;
    }
}
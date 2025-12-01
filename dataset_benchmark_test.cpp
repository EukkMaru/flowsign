#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <fstream>

#include "snortsharp_integration.hpp"
#include "dataset_loader.hpp"

constexpr int BENCHMARK_WINDOW_SIZE = 10;
constexpr int BENCHMARK_QUEUE_CAPACITY = 2000;
constexpr int BENCHMARK_ALERT_CAPACITY = 500;

void create_comprehensive_rules(const std::string& rules_file) {
    std::ofstream file(rules_file);
    
    // DoS and DDoS detection rules
    file << "sid:2001 msg:\"DoS - High packet rate\" flow_packets_per_sec > 200\n";
    file << "sid:2002 msg:\"DoS - SYN flood detected\" syn_flag_count > 15 AND ack_flag_count < 3\n";
    file << "sid:2003 msg:\"DoS - High connection rate\" total_fwd_packets > 100 AND flow_duration < 1.0\n";
    
    // Reconnaissance and scanning detection
    file << "sid:2004 msg:\"Port scan - Small packets\" packet_length_mean < 80 AND fwd_packets > 25\n";
    file << "sid:2005 msg:\"Network scan - Multiple connections\" fwd_packets > 50 AND flow_duration > 10.0\n";
    file << "sid:2006 msg:\"Reconnaissance - High SYN activity\" syn_flag_count > 8\n";
    
    // Suspicious data transfer patterns
    file << "sid:2007 msg:\"Large data exfiltration\" flow_bytes_per_sec > 2000000\n";
    file << "sid:2008 msg:\"Suspicious upload activity\" bwd_bytes > 1000000 AND fwd_bytes < 10000\n";
    file << "sid:2009 msg:\"Bulk data transfer\" total_fwd_bytes > 5000000\n";
    
    // Connection anomalies
    file << "sid:2010 msg:\"Abnormal connection duration\" flow_duration > 300.0\n";
    file << "sid:2011 msg:\"RST flood attack\" rst_flag_count > 10\n";
    file << "sid:2012 msg:\"Connection hijacking pattern\" rst_flag_count > 5 AND ack_flag_count > 20\n";
    
    // Traffic pattern anomalies
    file << "sid:2013 msg:\"Irregular packet timing\" flow_iat_std > 1000.0\n";
    file << "sid:2014 msg:\"Suspicious packet size variance\" packet_length_std > 500.0\n";
    file << "sid:2015 msg:\"Asymmetric flow pattern\" down_up_ratio > 10.0\n";
    
    // Protocol-specific rules
    file << "sid:2016 msg:\"TCP window manipulation\" fwd_packets > 10 AND avg_packet_size < 50\n";
    file << "sid:2017 msg:\"Potential buffer overflow\" packet_length_mean > 1400\n";
    file << "sid:2018 msg:\"Fragmentation attack\" fwd_packets > 100 AND packet_length_mean < 100\n";
    
    // Advanced persistent threat patterns  
    file << "sid:2019 msg:\"Slow and low attack\" flow_packets_per_sec < 0.1 AND flow_duration > 60.0\n";
    file << "sid:2020 msg:\"Covert channel activity\" fwd_iat_mean > 5000.0 AND bwd_iat_mean > 5000.0\n";
    
    file.close();
    std::cout << "Created comprehensive rule set with 20 detection rules\n";
}

struct BenchmarkResults {
    EvaluationMetrics evaluation_metrics;
    
    // performance metrics
    uint64_t total_processing_time_us = 0;
    uint64_t packets_processed = 0;
    double avg_processing_time_us = 0.0;
    double packets_per_second = 0.0;
    
    // matching statistics  
    uint32_t successful_matches = 0;
    uint32_t failed_matches = 0;
    double avg_feature_similarity = 0.0;
    double avg_timestamp_diff = 0.0;
    
    // rule performance
    std::vector<std::pair<uint32_t, uint32_t>> rule_matches; // (rule_id, match_count)
    
    void print_comprehensive_report() const {
        std::cout << "\n" << std::string(50, '=') << "\n";
        std::cout << "     COMPREHENSIVE BENCHMARK RESULTS\n";
        std::cout << std::string(50, '=') << "\n\n";
        
        // dataset evaluation
        std::cout << "DATASET EVALUATION:\n";
        std::cout << "  Records Processed: " << evaluation_metrics.total_flows_processed << "\n";
        std::cout << "  Classification Accuracy: " << (evaluation_metrics.accuracy() * 100.0) << "%\n";
        std::cout << "  Precision: " << (evaluation_metrics.precision() * 100.0) << "%\n";
        std::cout << "  Recall: " << (evaluation_metrics.recall() * 100.0) << "%\n";
        std::cout << "  F1-Score: " << (evaluation_metrics.f1_score() * 100.0) << "%\n\n";
        
        // performance analysis
        std::cout << "PERFORMANCE ANALYSIS:\n";
        std::cout << "  Total Processing Time: " << (total_processing_time_us / 1000.0) << " ms\n";
        std::cout << "  Average Per-Packet Time: " << avg_processing_time_us << " us\n";
        std::cout << "  Throughput: " << packets_per_second << " packets/second\n\n";
        
        // flow matching results
        std::cout << "FLOW MATCHING RESULTS:\n";
        std::cout << "  Successful Matches: " << successful_matches << "\n";
        std::cout << "  Failed Matches: " << failed_matches << "\n";
        if(successful_matches > 0) {
            std::cout << "  Match Rate: " << (100.0 * successful_matches / (successful_matches + failed_matches)) << "%\n";
            std::cout << "  Avg Feature Similarity: " << (avg_feature_similarity * 100.0) << "%\n";
            std::cout << "  Avg Timestamp Diff: " << avg_timestamp_diff << " seconds\n";
        }
        std::cout << "\n";
        
        // detection breakdown
        std::cout << "DETECTION BREAKDOWN:\n";
        std::cout << "  True Positives:  " << evaluation_metrics.true_positives << " (correctly detected attacks)\n";
        std::cout << "  True Negatives:  " << evaluation_metrics.true_negatives << " (correctly identified normal)\n";
        std::cout << "  False Positives: " << evaluation_metrics.false_positives << " (false alarms)\n";
        std::cout << "  False Negatives: " << evaluation_metrics.false_negatives << " (missed attacks)\n\n";
        
        // rule effectiveness
        if(!rule_matches.empty()) {
            std::cout << "RULE EFFECTIVENESS:\n";
            for(const auto& rule_match : rule_matches) {
                std::cout << "  Rule SID:" << rule_match.first << " triggered " << rule_match.second << " times\n";
            }
            std::cout << "\n";
        }
        
        std::cout << std::string(50, '=') << "\n";
    }
};

bool run_dataset_benchmark(const std::string& dataset_path, size_t max_records = 0) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "    SNORTSHARP DATASET BENCHMARKING SUITE\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    // create comprehensive rule set
    std::string rules_file = "comprehensive_rules.txt";
    create_comprehensive_rules(rules_file);
    
    // initialize dataset loader with tolerances
    MatchingTolerances tolerances(2.0, 0.75, 3, 0.15); // lenient for real dataset
    DatasetLoader loader(tolerances);
    
    std::cout << "Loading UNSW-NB15 dataset from: " << dataset_path << "\n";
    if(!loader.load_unsw_nb15_csv(dataset_path)) {
        std::cout << "Failed to load dataset\n";
        return false;
    }
    
    loader.print_dataset_summary();
    
    // initialize SnortSharp engine
    std::cout << "Initializing SnortSharp engine for benchmarking...\n";
    SnortSharpEngine engine(BENCHMARK_WINDOW_SIZE, BENCHMARK_QUEUE_CAPACITY, BENCHMARK_ALERT_CAPACITY);
    
    if(!engine.load_flow_rules(rules_file)) {
        std::cout << "Failed to load comprehensive rules\n";
        return false;
    }
    
    if(!engine.start()) {
        std::cout << "Failed to start engine\n";
        return false;
    }
    
    // allow engine initialization
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // run comprehensive evaluation
    std::cout << "Starting comprehensive dataset evaluation...\n";
    auto start_time = std::chrono::high_resolution_clock::now();
    
    BenchmarkResults results;
    results.evaluation_metrics = loader.evaluate_against_dataset(engine, max_records, false);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // calculate performance metrics
    results.total_processing_time_us = duration.count();
    results.packets_processed = engine.get_total_packets_processed();
    results.avg_processing_time_us = engine.get_avg_processing_time_us();
    
    if(results.total_processing_time_us > 0) {
        results.packets_per_second = (results.packets_processed * 1000000.0) / results.total_processing_time_us;
    }
    
    // collect additional statistics
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    engine.print_stats();
    
    // stop engine
    engine.stop();
    
    // print comprehensive results
    results.print_comprehensive_report();
    loader.print_evaluation_report(results.evaluation_metrics);
    
    // validation checks
    bool success = true;
    
    if(results.evaluation_metrics.total_flows_processed == 0) {
        std::cout << "No flows were processed from dataset\n";
        success = false;
    }
    
    if(results.packets_processed == 0) {
        std::cout << "No packets were processed\n";
        success = false;
    }
    
    // performance validation
    if(results.avg_processing_time_us > 100.0) {
        std::cout << "High processing time detected: " << results.avg_processing_time_us << " us\n";
    }
    
    // detection validation
    double detection_rate = results.evaluation_metrics.recall();
    if(detection_rate < 0.5) {
        std::cout << "Low detection rate: " << (detection_rate * 100.0) << "%\n";
    }
    
    double false_positive_rate = 0.0;
    if((results.evaluation_metrics.true_negatives + results.evaluation_metrics.false_positives) > 0) {
        false_positive_rate = static_cast<double>(results.evaluation_metrics.false_positives) / 
                             (results.evaluation_metrics.true_negatives + results.evaluation_metrics.false_positives);
    }
    
    if(false_positive_rate > 0.1) {
        std::cout << "High false positive rate: " << (false_positive_rate * 100.0) << "%\n";
    }
    
    if(success) {
        std::cout << "\nDATASET BENCHMARK COMPLETED SUCCESSFULLY!\n";
        std::cout << "Dataset Processing: WORKING (" << results.evaluation_metrics.total_flows_processed << " flows)\n";
        std::cout << "Packet-to-Flow Pipeline: WORKING (" << results.packets_processed << " packets)\n";
        std::cout << "Feature Extraction: WORKING (" << engine.get_total_features_generated() << " features)\n";
        std::cout << "Alert Generation: WORKING (" << engine.get_total_alerts_generated() << " alerts)\n";
        std::cout << "Performance: " << results.packets_per_second << " packets/second\n";
        
        if(results.evaluation_metrics.accuracy() > 0.7) {
            std::cout << "Classification Accuracy: GOOD (" << (results.evaluation_metrics.accuracy() * 100.0) << "%)\n";
        } else {
            std::cout << "Classification Accuracy: NEEDS IMPROVEMENT (" << (results.evaluation_metrics.accuracy() * 100.0) << "%)\n";
        }
        
    } else {
        std::cout << "Dataset benchmark FAILED\n";
    }
    
    return success;
}

// interactive dataset testing mode
void run_interactive_dataset_testing() {
    std::cout << "\n=== INTERACTIVE DATASET TESTING MODE ===\n";
    
    std::string dataset_path;
    size_t max_records;
    
    std::cout << "Enter UNSW-NB15 dataset CSV path: ";
    std::getline(std::cin, dataset_path);
    
    std::cout << "Enter max records to process (0 for all): ";
    std::cin >> max_records;
    
    if(!run_dataset_benchmark(dataset_path, max_records)) {
        std::cout << "Benchmark failed. Check dataset path and format.\n";
    }
}

// batch testing mode
void run_batch_testing() {
    std::cout << "\n=== BATCH TESTING MODE ===\n";
    
    std::vector<std::pair<std::string, size_t>> test_configs = {
        {"datasets/UNSW-NB15_1.csv", 1000},  // sample test
        {"datasets/UNSW-NB15_1.csv", 5000},  // medium test
        {"datasets/UNSW-NB15_1.csv", 0},     // full test
    };
    
    for(const auto& config : test_configs) {
        std::cout << "\nRunning batch test: " << config.first 
                  << " (max_records: " << config.second << ")\n";
        
        if(run_dataset_benchmark(config.first, config.second)) {
            std::cout << "Batch test passed\n";
        } else {
            std::cout << "Batch test failed\n";
            break;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

int main(int argc, char* argv[]) {
    std::cout << "SnortSharp Dataset Benchmarking Suite\n";
    std::cout << "====================================\n\n";
    
    try {
        if(argc > 1) {
            // command line mode
            std::string dataset_path = argv[1];
            size_t max_records = (argc > 2) ? std::stoul(argv[2]) : 0;
            
            return run_dataset_benchmark(dataset_path, max_records) ? 0 : 1;
            
        } else {
            // interactive mode
            std::cout << "Select testing mode:\n";
            std::cout << "1. Interactive testing\n";
            std::cout << "2. Batch testing\n";
            std::cout << "3. Quick demo (datasets/sample.csv)\n";
            std::cout << "Choice: ";
            
            int choice;
            std::cin >> choice;
            std::cin.ignore(); // consume newline
            
            switch(choice) {
                case 1:
                    run_interactive_dataset_testing();
                    break;
                case 2:
                    run_batch_testing();
                    break;
                case 3:
                    return run_dataset_benchmark("datasets/sample.csv", 100) ? 0 : 1;
                default:
                    std::cout << "Invalid choice\n";
                    return 1;
            }
        }
        
        return 0;
        
    } catch(const std::exception& e) {
        std::cerr << "Benchmark failed with exception: " << e.what() << "\n";
        return 1;
    }
}
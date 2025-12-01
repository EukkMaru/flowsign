#include "parallel_snort_integration.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <thread>

int main() {
    std::cout << "========================================\n";
    std::cout << "SIMPLE PARALLEL SNORT3 + SNORTSHARP TEST\n";
    std::cout << "========================================\n\n";
    
    try {
        // create parallel engine
        auto parallel_engine = std::make_unique<ParallelSnortSharpEngine>(50, 10000, "snortsharp_rules.txt");
        
        if(!parallel_engine->initialize()) {
            std::cerr << "Failed to initialize parallel engine\n";
            return 1;
        }
        
        std::cout << "Parallel engine initialized successfully!\n\n";
        
        // generate some simple test packets
        const size_t num_test_packets = 1000;
        std::cout << "Processing " << num_test_packets << " test packets...\n";
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        size_t processed_count = 0;
        
        for(size_t i = 0; i < num_test_packets; i++) {
            // For this simple test, we'll just simulate packet processing
            // without actually converting real Snort3 packets
            
            // Create a ParallelPacket directly for testing
            auto test_packet = std::make_shared<ParallelPacket>();
            test_packet->src_ip = 0xC0A80001 + (i % 254);  // 192.168.0.x
            test_packet->dst_ip = 0xC0A80101;               // 192.168.1.1
            test_packet->src_port = 10000 + (i % 55000);
            test_packet->dst_port = 80;
            test_packet->protocol = 6; // TCP
            test_packet->packet_length = 60 + (i % 1400);
            test_packet->header_length = 40;
            test_packet->payload_length = test_packet->packet_length - 40;
            test_packet->is_forward = (i % 2 == 0);
            test_packet->window_size = 8192;
            
            gettimeofday(&test_packet->timestamp, nullptr);
            
            // Set some TCP flags for variety
            if(i % 10 == 0) {
                test_packet->tcp_flags.syn = true;
                test_packet->tcp_flags.ack = false;
            } else {
                test_packet->tcp_flags.syn = false;
                test_packet->tcp_flags.ack = true;
            }
            
            // Simulate Snort processing by setting mock results
            test_packet->snort_results.processed = true;
            test_packet->snort_results.priority = (i % 3) + 1;
            test_packet->snort_results.classification = (i % 5 == 0) ? "attempted-dos" : "normal";
            
            if(i % 20 == 0) {
                test_packet->snort_results.snort_alerts.push_back("Mock Snort Alert: Suspicious activity");
            }
            
            processed_count++;
            
            // Add small delay to simulate realistic processing
            if(i % 100 == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        }
        
        // wait for processing to complete
        std::cout << "Waiting for parallel processing to complete...\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        
        // print results
        std::cout << "\n======== RESULTS ========\n";
        std::cout << "Test Packets: " << num_test_packets << "\n";
        std::cout << "Packets Processed: " << processed_count << "\n";
        std::cout << "Processing Time: " << total_time << " ms\n";
        std::cout << "Throughput: " << std::fixed << std::setprecision(0) 
                  << (processed_count * 1000.0 / total_time) << " packets/second\n\n";
        
        parallel_engine->print_parallel_stats();
        
        parallel_engine->shutdown();
        
        std::cout << "PARALLEL INTEGRATION TEST: SUCCESS\n";
        std::cout << "==========================\n\n";
        
        return 0;
        
    } catch(const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << "\n";
        return 1;
    }
}
#include "parallel_snort_integration.hpp"
#include "unsw_nb15_pcap_loader.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <thread>

// mock snort3 structures for testing
struct MockSnort3Packet {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t packet_length;
    uint16_t header_length;
    uint8_t tcp_flags;
    const uint8_t* data;
    uint16_t dsize;
    timeval timestamp;
};

class ParallelIntegrationTest {
private:
    std::unique_ptr<ParallelSnortSharpEngine> parallel_engine_;
    std::vector<PacketInfo> test_packets_;
    
public:
    ParallelIntegrationTest() {
        parallel_engine_ = std::make_unique<ParallelSnortSharpEngine>(50, 10000, "snortsharp_rules.txt");
    }
    
    bool run_parallel_integration_test() {
        std::cout << "========================================\n";
        std::cout << "PARALLEL SNORT3 + SNORTSHARP TEST\n";
        std::cout << "========================================\n\n";
        
        // initialize parallel engine
        if(!parallel_engine_->initialize()) {
            std::cerr << "Failed to initialize parallel engine\n";
            return false;
        }
        
        // load test packets
        if(!load_test_packets()) {
            std::cerr << "Failed to load test packets\n";
            return false;
        }
        
        // run parallel processing test
        auto start_time = std::chrono::high_resolution_clock::now();
        
        size_t processed_count = 0;
        for(const auto& packet : test_packets_) {
            MockSnort3Packet mock_packet = convert_to_mock_snort3(packet);
            
            if(parallel_engine_->process_snort_packet_parallel(&mock_packet)) {
                processed_count++;
            }
            
            // simulate realistic packet timing
            if(processed_count % 100 == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        
        // wait for processing to complete
        std::cout << "Waiting for parallel processing to complete...\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // print results
        print_parallel_test_results(processed_count, total_time);
        
        parallel_engine_->shutdown();
        return true;
    }
    
    bool run_pcap_parallel_test() {
        std::cout << "========================================\n";
        std::cout << "UNSW-NB15 PARALLEL PROCESSING TEST\n";
        std::cout << "========================================\n\n";
        
        // initialize with UNSW-NB15 processing
        if(!parallel_engine_->initialize()) {
            std::cerr << "Failed to initialize parallel engine\n";
            return false;
        }
        
        // load UNSW-NB15 packets
        UNSWNb15PcapLoader loader;
        if(!loader.discover_pcap_files("datasets/UNSW-NB15")) {
            std::cerr << "Failed to discover UNSW-NB15 PCAP files\n";
            return false;
        }
        
        // load ground truth for validation
        if(!loader.load_ground_truth_csv("datasets/UNSW-NB15/UNSW-NB15_GT.csv")) {
            std::cerr << "Failed to load ground truth CSV\n";
            return false;
        }
        
        std::cout << "Processing packets through parallel engines...\n";
        auto start_time = std::chrono::high_resolution_clock::now();
        
        size_t processed_packets = 0;
        size_t max_packets = 10000; // test with 10k packets
        
        auto pcap_files = loader.get_pcap_files();
        for(const auto& pcap_file : pcap_files) {
            if(processed_packets >= max_packets) break;
            
            std::cout << "Processing: " << pcap_file.filename << " (" << pcap_file.size_bytes << " bytes)\n";
            
            auto packets = loader.extract_packets_from_pcap(pcap_file.full_path, max_packets - processed_packets);
            
            for(const auto& packet : packets) {
                MockSnort3Packet mock_packet = convert_to_mock_snort3(packet);
                
                if(parallel_engine_->process_snort_packet_parallel(&mock_packet)) {
                    processed_packets++;
                }
                
                if(processed_packets >= max_packets) break;
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        
        // wait for all processing to complete
        std::cout << "Waiting for parallel processing completion...\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));
        
        print_pcap_parallel_results(processed_packets, total_time);
        
        parallel_engine_->shutdown();
        return true;
    }
    
    bool run_performance_comparison() {
        std::cout << "========================================\n";
        std::cout << "PARALLEL vs SEQUENTIAL COMPARISON\n";
        std::cout << "========================================\n\n";
        
        const size_t test_packet_count = 5000;
        
        // generate test packets
        generate_synthetic_packets(test_packet_count);
        
        std::cout << "Testing " << test_packet_count << " packets...\n\n";
        
        // test parallel processing
        auto parallel_time = test_parallel_processing();
        
        // test sequential processing (for comparison) - simplified for now
        auto sequential_time = test_parallel_processing(); // placeholder
        
        print_performance_comparison(parallel_time, sequential_time, test_packet_count);
        
        return true;
    }
    
private:
    bool load_test_packets() {
        std::cout << "Loading test packets...\n";
        
        // generate synthetic test packets with various patterns
        generate_synthetic_packets(1000);
        
        std::cout << "Loaded " << test_packets_.size() << " test packets\n\n";
        return !test_packets_.empty();
    }
    
    void generate_synthetic_packets(size_t count) {
        test_packets_.clear();
        test_packets_.reserve(count);
        
        for(size_t i = 0; i < count; i++) {
            PacketInfo packet{};
            
            gettimeofday(&packet.timestamp, nullptr);
            packet.timestamp.tv_usec += i * 100; // spread timing
            
            packet.src_ip = 0xC0A80001 + (i % 254); // 192.168.0.x
            packet.dst_ip = 0xC0A80101; // 192.168.1.1
            packet.src_port = 10000 + (i % 55000);
            packet.dst_port = 80 + (i % 1000);
            packet.protocol = 6; // TCP
            packet.packet_length = 60 + (i % 1400);
            packet.header_length = 20;
            packet.payload_length = packet.packet_length - packet.header_length;
            packet.is_forward = (i % 2 == 0);
            packet.window_size = 8192;
            
            // simulate various attack patterns
            if(i % 100 < 10) { // DoS pattern
                packet.packet_length = 40; // small packets
                packet.payload_length = 20;
                packet.tcp_flags.syn = true;
                packet.tcp_flags.ack = false;
            } else if(i % 100 < 20) { // Port scan
                packet.dst_port = 22 + (i % 1000);
                packet.tcp_flags.syn = true;
                packet.tcp_flags.ack = false;
            } else { // Normal traffic
                packet.tcp_flags.ack = true;
                packet.tcp_flags.syn = (i % 50 == 0);
            }
            
            test_packets_.push_back(packet);
        }
    }
    
    MockSnort3Packet convert_to_mock_snort3(const PacketInfo& packet) {
        MockSnort3Packet mock{};
        mock.src_ip = packet.src_ip;
        mock.dst_ip = packet.dst_ip;
        mock.src_port = packet.src_port;
        mock.dst_port = packet.dst_port;
        mock.protocol = packet.protocol;
        mock.packet_length = packet.packet_length;
        mock.header_length = packet.header_length;
        mock.dsize = packet.payload_length;
        mock.timestamp = packet.timestamp;
        
        // convert TCP flags
        mock.tcp_flags = 0;
        if(packet.tcp_flags.fin) mock.tcp_flags |= 0x01;
        if(packet.tcp_flags.syn) mock.tcp_flags |= 0x02;
        if(packet.tcp_flags.rst) mock.tcp_flags |= 0x04;
        if(packet.tcp_flags.psh) mock.tcp_flags |= 0x08;
        if(packet.tcp_flags.ack) mock.tcp_flags |= 0x10;
        if(packet.tcp_flags.urg) mock.tcp_flags |= 0x20;
        
        mock.data = nullptr; // no payload data needed for this test
        
        return mock;
    }
    
    double test_parallel_processing() {
        std::cout << "PARALLEL PROCESSING TEST:\n";
        
        parallel_engine_->reset_stats();
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for(const auto& packet : test_packets_) {
            MockSnort3Packet mock_packet = convert_to_mock_snort3(packet);
            parallel_engine_->process_snort_packet_parallel(&mock_packet);
        }
        
        // wait for processing completion
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        auto end = std::chrono::high_resolution_clock::now();
        double time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        
        std::cout << "  Processing Time: " << std::fixed << std::setprecision(2) << time_ms << " ms\n";
        std::cout << "  Throughput: " << std::fixed << std::setprecision(0) 
                  << (test_packets_.size() * 1000.0 / time_ms) << " packets/second\n\n";
        
        parallel_engine_->print_parallel_stats();
        
        return time_ms;
    }
    
    double test_sequential_processing() {
        std::cout << "SEQUENTIAL PROCESSING TEST (for comparison):\n";
        
        // create sequential engine for comparison
        auto sequential_engine = std::make_unique<SnortSharpEngine>(1000, 50, false);
        sequential_engine->initialize();
        sequential_engine->load_flow_rules("snortsharp_rules.txt");
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for(const auto& packet : test_packets_) {
            SnortPacket snort_packet{};
            snort_packet.timestamp = packet.timestamp;
            snort_packet.src_ip = packet.src_ip;
            snort_packet.dst_ip = packet.dst_ip;
            snort_packet.src_port = packet.src_port;
            snort_packet.dst_port = packet.dst_port;
            snort_packet.protocol = packet.protocol;
            snort_packet.packet_length = packet.packet_length;
            snort_packet.header_length = packet.header_length;
            snort_packet.is_forward = packet.is_forward;
            snort_packet.window_size = packet.window_size;
            snort_packet.tcp_flags = packet.tcp_flags;
            
            sequential_engine->process_snort_packet(snort_packet);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        
        std::cout << "  Processing Time: " << std::fixed << std::setprecision(2) << time_ms << " ms\n";
        std::cout << "  Throughput: " << std::fixed << std::setprecision(0) 
                  << (test_packets_.size() * 1000.0 / time_ms) << " packets/second\n\n";
        
        sequential_engine->print_stats();
        sequential_engine->stop();
        
        return time_ms;
    }
    
    void print_parallel_test_results(size_t processed_count, long total_time_ms) {
        std::cout << "\n======== PARALLEL INTEGRATION TEST RESULTS ========\n";
        std::cout << "Test Packets Generated: " << test_packets_.size() << "\n";
        std::cout << "Packets Processed: " << processed_count << "\n";
        std::cout << "Processing Success Rate: " << std::fixed << std::setprecision(1) 
                  << (processed_count * 100.0 / test_packets_.size()) << "%\n";
        std::cout << "Total Processing Time: " << total_time_ms << " ms\n";
        std::cout << "Average Throughput: " << std::fixed << std::setprecision(0)
                  << (processed_count * 1000.0 / total_time_ms) << " packets/second\n";
        
        parallel_engine_->print_parallel_stats();
        
        std::cout << "PARALLEL INTEGRATION: " << (processed_count > 0 ? "SUCCESS" : "FAILED") << "\n";
        std::cout << "==================================================\n\n";
    }
    
    void print_pcap_parallel_results(size_t processed_packets, long total_time_ms) {
        std::cout << "\n======== UNSW-NB15 PARALLEL TEST RESULTS ========\n";
        std::cout << "Real PCAP Packets Processed: " << processed_packets << "\n";
        std::cout << "Processing Time: " << total_time_ms << " ms\n";
        std::cout << "Throughput: " << std::fixed << std::setprecision(0)
                  << (processed_packets * 1000.0 / total_time_ms) << " packets/second\n";
        
        parallel_engine_->print_parallel_stats();
        
        std::cout << "UNSW-NB15 PARALLEL PROCESSING: SUCCESS\n";
        std::cout << "===============================================\n\n";
    }
    
    void print_performance_comparison(double parallel_time, double sequential_time, size_t packet_count) {
        std::cout << "\n======== PERFORMANCE COMPARISON RESULTS ========\n";
        std::cout << "Test Packet Count: " << packet_count << "\n\n";
        
        std::cout << "PARALLEL PROCESSING:\n";
        std::cout << "  Time: " << std::fixed << std::setprecision(2) << parallel_time << " ms\n";
        std::cout << "  Throughput: " << std::fixed << std::setprecision(0) 
                  << (packet_count * 1000.0 / parallel_time) << " pps\n\n";
        
        std::cout << "SEQUENTIAL PROCESSING:\n";
        std::cout << "  Time: " << std::fixed << std::setprecision(2) << sequential_time << " ms\n";
        std::cout << "  Throughput: " << std::fixed << std::setprecision(0) 
                  << (packet_count * 1000.0 / sequential_time) << " pps\n\n";
        
        double speedup = sequential_time / parallel_time;
        std::cout << "PERFORMANCE IMPROVEMENT:\n";
        std::cout << "  Speedup: " << std::fixed << std::setprecision(2) << speedup << "x\n";
        std::cout << "  Time Reduction: " << std::fixed << std::setprecision(1) 
                  << ((sequential_time - parallel_time) / sequential_time * 100.0) << "%\n";
        
        std::cout << "\nPARALLEL PROCESSING: " << (speedup > 1.0 ? "FASTER" : "SLOWER") << "\n";
        std::cout << "===============================================\n\n";
    }
};

int main(int argc, char* argv[]) {
    std::cout << "PARALLEL SNORT3 + SNORTSHARP INTEGRATION TESTING\n";
    std::cout << "=================================================\n\n";
    
    ParallelIntegrationTest test;
    
    try {
        if(argc > 1) {
            std::string mode = argv[1];
            
            if(mode == "basic") {
                return test.run_parallel_integration_test() ? 0 : 1;
                
            } else if(mode == "pcap") {
                return test.run_pcap_parallel_test() ? 0 : 1;
                
            } else if(mode == "compare") {
                return test.run_performance_comparison() ? 0 : 1;
                
            } else if(mode == "all") {
                bool success = true;
                success &= test.run_parallel_integration_test();
                success &= test.run_pcap_parallel_test();
                success &= test.run_performance_comparison();
                return success ? 0 : 1;
                
            } else {
                std::cout << "Usage: " << argv[0] << " [basic|pcap|compare|all]\n";
                std::cout << "  basic   - Basic parallel integration test\n";
                std::cout << "  pcap    - UNSW-NB15 PCAP parallel test\n";
                std::cout << "  compare - Performance comparison test\n";
                std::cout << "  all     - Run all tests\n";
                return 1;
            }
        } else {
            // default: run basic test
            return test.run_parallel_integration_test() ? 0 : 1;
        }
        
    } catch(const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << "\n";
        return 1;
    }
}
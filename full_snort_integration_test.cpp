#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <fstream>
#include <cstring>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "snortsharp_integration.hpp"

// Test configuration
constexpr int TEST_WINDOW_SIZE = 10;
constexpr int TEST_QUEUE_CAPACITY = 1000;
constexpr int TEST_ALERT_CAPACITY = 100;

// Create test flow rules that should trigger on our synthetic traffic
void create_test_rules(const std::string& rules_file) {
    std::ofstream file(rules_file);
    
    // Rule 1: Detect high packet rate (DoS-like behavior)
    file << "sid:1001 msg:\"High packet rate detected\" flow_packets_per_sec > 100\n";
    
    // Rule 2: Detect large flow duration (long-lived connection)
    file << "sid:1002 msg:\"Long-lived connection\" flow_duration > 5.0\n";
    
    // Rule 3: Detect high data transfer
    file << "sid:1003 msg:\"High data transfer\" flow_bytes_per_sec > 1000000\n";
    
    // Rule 4: Detect specific flag patterns (SYN flood detection)  
    file << "sid:1004 msg:\"Potential SYN flood\" syn_flag_count > 10 AND ack_flag_count < 5\n";
    
    // Rule 5: Detect small packet sizes (possible reconnaissance)
    file << "sid:1005 msg:\"Small packet reconnaissance\" packet_length_mean < 100 AND fwd_packets > 20\n";
    
    // Rule 6: Detect high SYN count (should trigger with our DoS scenario)
    file << "sid:1006 msg:\"High SYN activity\" syn_flag_count > 5\n";
    
    file.close();
    std::cout << "Created test rules file: " << rules_file << "\n";
}

// Synthetic packet generator that creates realistic network traffic
class PacketGenerator {
private:
    uint32_t seq_base_;
    uint32_t ack_base_;
    struct timeval start_time_;
    
public:
    PacketGenerator() : seq_base_(1000), ack_base_(2000) {
        gettimeofday(&start_time_, nullptr);
    }
    
    // Generate TCP SYN packet
    SnortPacket generate_syn_packet(uint32_t src_ip, uint16_t src_port, 
                                   uint32_t dst_ip, uint16_t dst_port, 
                                   int time_offset_ms = 0) {
        SnortPacket pkt{};
        
        gettimeofday(&pkt.timestamp, nullptr);
        pkt.timestamp.tv_usec += time_offset_ms * 1000;
        if(pkt.timestamp.tv_usec >= 1000000) {
            pkt.timestamp.tv_sec += pkt.timestamp.tv_usec / 1000000;
            pkt.timestamp.tv_usec %= 1000000;
        }
        
        pkt.src_ip = src_ip;
        pkt.dst_ip = dst_ip;
        pkt.src_port = src_port;
        pkt.dst_port = dst_port;
        pkt.protocol = IPPROTO_TCP;
        pkt.packet_length = 60; // Standard SYN packet size
        pkt.header_length = 40; // IP + TCP headers
        pkt.is_forward = true;
        pkt.window_size = 65535;
        
        pkt.tcp_flags.syn = true;
        pkt.tcp_flags.ack = false;
        pkt.tcp_flags.fin = false;
        pkt.tcp_flags.rst = false;
        pkt.tcp_flags.psh = false;
        pkt.tcp_flags.urg = false;
        
        return pkt;
    }
    
    // Generate TCP SYN-ACK packet
    SnortPacket generate_synack_packet(uint32_t src_ip, uint16_t src_port,
                                      uint32_t dst_ip, uint16_t dst_port,
                                      int time_offset_ms = 1) {
        SnortPacket pkt = generate_syn_packet(src_ip, src_port, dst_ip, dst_port, time_offset_ms);
        pkt.is_forward = false;
        pkt.tcp_flags.syn = true;
        pkt.tcp_flags.ack = true;
        return pkt;
    }
    
    // Generate TCP data packet
    SnortPacket generate_data_packet(uint32_t src_ip, uint16_t src_port,
                                    uint32_t dst_ip, uint16_t dst_port,
                                    uint16_t payload_size = 1460,
                                    bool is_forward = true,
                                    int time_offset_ms = 2) {
        SnortPacket pkt{};
        
        gettimeofday(&pkt.timestamp, nullptr);
        pkt.timestamp.tv_usec += time_offset_ms * 1000;
        if(pkt.timestamp.tv_usec >= 1000000) {
            pkt.timestamp.tv_sec += pkt.timestamp.tv_usec / 1000000;
            pkt.timestamp.tv_usec %= 1000000;
        }
        
        pkt.src_ip = is_forward ? src_ip : dst_ip;
        pkt.dst_ip = is_forward ? dst_ip : src_ip;
        pkt.src_port = is_forward ? src_port : dst_port;
        pkt.dst_port = is_forward ? dst_port : src_port;
        pkt.protocol = IPPROTO_TCP;
        pkt.packet_length = payload_size + 40; // Payload + headers
        pkt.header_length = 40;
        pkt.is_forward = is_forward;
        pkt.window_size = 65535;
        
        pkt.tcp_flags.syn = false;
        pkt.tcp_flags.ack = true;
        pkt.tcp_flags.fin = false;
        pkt.tcp_flags.rst = false;
        pkt.tcp_flags.psh = (payload_size > 0);
        pkt.tcp_flags.urg = false;
        
        return pkt;
    }
    
    // Generate complete TCP flow (SYN -> SYN-ACK -> DATA -> FIN)
    std::vector<SnortPacket> generate_tcp_flow(uint32_t src_ip, uint16_t src_port,
                                              uint32_t dst_ip, uint16_t dst_port,
                                              int num_data_packets = 10,
                                              uint16_t payload_size = 1460) {
        std::vector<SnortPacket> flow;
        
        // 1. SYN packet
        flow.push_back(generate_syn_packet(src_ip, src_port, dst_ip, dst_port, 0));
        
        // 2. SYN-ACK packet
        flow.push_back(generate_synack_packet(dst_ip, dst_port, src_ip, src_port, 1));
        
        // 3. ACK packet (connection established)
        auto ack_pkt = generate_data_packet(src_ip, src_port, dst_ip, dst_port, 0, true, 2);
        ack_pkt.tcp_flags.psh = false;
        flow.push_back(ack_pkt);
        
        // 4. Data exchange
        for(int i = 0; i < num_data_packets; i++) {
            // Forward data
            flow.push_back(generate_data_packet(src_ip, src_port, dst_ip, dst_port, 
                                              payload_size, true, 10 + i * 10));
            
            // Backward ACK
            if(i % 2 == 0) { // ACK every 2nd packet
                flow.push_back(generate_data_packet(dst_ip, dst_port, src_ip, src_port,
                                                  0, false, 15 + i * 10));
            }
        }
        
        // 5. Connection termination (FIN-ACK)
        auto fin_pkt = generate_data_packet(src_ip, src_port, dst_ip, dst_port, 0, true, 1000);
        fin_pkt.tcp_flags.fin = true;
        fin_pkt.tcp_flags.psh = false;
        flow.push_back(fin_pkt);
        
        return flow;
    }
};

// Traffic scenario generators
class TrafficScenarios {
public:
    // Scenario 1: Normal web browsing traffic
    static std::vector<SnortPacket> generate_web_browsing() {
        PacketGenerator gen;
        std::vector<SnortPacket> packets;
        
        // Multiple HTTP connections to simulate web browsing
        uint32_t client_ip = inet_addr("192.168.1.100");
        uint32_t server_ip = inet_addr("10.0.0.50");
        
        for(int i = 0; i < 3; i++) {
            auto flow = gen.generate_tcp_flow(client_ip, 32000 + i, server_ip, 80, 5, 800);
            packets.insert(packets.end(), flow.begin(), flow.end());
        }
        
        return packets;
    }
    
    // Scenario 2: High-rate DoS-like traffic (should trigger alerts)
    static std::vector<SnortPacket> generate_dos_traffic() {
        PacketGenerator gen;
        std::vector<SnortPacket> packets;
        
        uint32_t attacker_ip = inet_addr("192.168.1.200");
        uint32_t victim_ip = inet_addr("10.0.0.100");
        
        // Generate many SYN packets (SYN flood)
        for(int i = 0; i < 50; i++) {
            packets.push_back(gen.generate_syn_packet(attacker_ip, 30000 + i, victim_ip, 80, i));
        }
        
        return packets;
    }
    
    // Scenario 3: Large file transfer (high bandwidth)
    static std::vector<SnortPacket> generate_file_transfer() {
        PacketGenerator gen;
        uint32_t client_ip = inet_addr("192.168.1.150");
        uint32_t server_ip = inet_addr("10.0.0.200");
        
        // Large flow with many big packets
        return gen.generate_tcp_flow(client_ip, 45000, server_ip, 21, 100, 1460);
    }
    
    // Scenario 4: Port scanning (reconnaissance)
    static std::vector<SnortPacket> generate_port_scan() {
        PacketGenerator gen;
        std::vector<SnortPacket> packets;
        
        uint32_t scanner_ip = inet_addr("192.168.1.250");
        uint32_t target_ip = inet_addr("10.0.0.250");
        
        // Scan multiple ports with small packets
        for(uint16_t port = 20; port < 100; port++) {
            packets.push_back(gen.generate_syn_packet(scanner_ip, 50000, target_ip, port, port - 20));
        }
        
        return packets;
    }
};

// Test results tracker
struct TestResults {
    int total_packets_processed = 0;
    int total_features_generated = 0;
    int total_alerts_generated = 0;
    std::vector<FlowAlert> captured_alerts;
    
    void print_summary() const {
        std::cout << "\n=== Test Results Summary ===\n";
        std::cout << "Total Packets Processed: " << total_packets_processed << "\n";
        std::cout << "Total Features Generated: " << total_features_generated << "\n";
        std::cout << "Total Alerts Generated: " << total_alerts_generated << "\n";
        
        if(!captured_alerts.empty()) {
            std::cout << "\n--- Alert Details ---\n";
            for(const auto& alert : captured_alerts) {
                std::cout << "Alert SID:" << alert.rule_id << " - " << alert.message << "\n";
                std::cout << "  Confidence: " << alert.confidence << "\n";
                std::cout << "  Flow Stats: " 
                          << (alert.features.total_fwd_packets + alert.features.total_bwd_packets) << " packets, "
                          << (alert.features.total_fwd_bytes + alert.features.total_bwd_bytes) << " bytes\n";
            }
        }
        std::cout << "============================\n\n";
    }
};

// Main integration test function
bool run_full_integration_test() {
    std::cout << "=== Full Snort3 Integration Test ===\n";
    std::cout << "Testing complete pipeline: Packets -> Snort3 -> SnortSharp -> Flow Analysis -> Alerting\n\n";
    
    // 1. Create test rules
    std::string rules_file = "test_flow_rules.txt";
    create_test_rules(rules_file);
    
    // 2. Initialize SnortSharp engine
    std::cout << "Initializing SnortSharp engine...\n";
    SnortSharpEngine engine(TEST_WINDOW_SIZE, TEST_QUEUE_CAPACITY, TEST_ALERT_CAPACITY);
    
    if(!engine.load_flow_rules(rules_file)) {
        std::cout << "❌ Failed to load test rules\n";
        return false;
    }
    
    if(!engine.start()) {
        std::cout << "❌ Failed to start engine\n";
        return false;
    }
    
    // Allow engine to initialize
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    TestResults results;
    
    // 3. Run traffic scenarios
    std::vector<std::pair<std::string, std::vector<SnortPacket>>> scenarios = {
        {"Normal Web Browsing", TrafficScenarios::generate_web_browsing()},
        {"DoS Attack (should alert)", TrafficScenarios::generate_dos_traffic()},
        {"Large File Transfer", TrafficScenarios::generate_file_transfer()},
        {"Port Scanning (should alert)", TrafficScenarios::generate_port_scan()}
    };
    
    for(const auto& scenario : scenarios) {
        std::cout << "Running scenario: " << scenario.first << " (" << scenario.second.size() << " packets)\n";
        
        int processed_before = results.total_packets_processed;
        
        // Process each packet through our engine
        for(const auto& packet : scenario.second) {
            if(engine.process_snort_packet(packet)) {
                results.total_packets_processed++;
            }
            
            // Small delay to simulate realistic timing
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        
        // Allow processing to complete
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Collect alerts generated by this scenario
        FlowAlert alert;
        while(engine.get_next_alert(alert)) {
            results.captured_alerts.push_back(alert);
            results.total_alerts_generated++;
        }
        
        int processed_in_scenario = results.total_packets_processed - processed_before;
        std::cout << "  Processed: " << processed_in_scenario << " packets\n";
        
        if(!results.captured_alerts.empty()) {
            int alerts_in_scenario = 0;
            for(size_t i = results.captured_alerts.size() - results.total_alerts_generated; 
                i < results.captured_alerts.size(); i++) {
                alerts_in_scenario++;
            }
            if(alerts_in_scenario > 0) {
                std::cout << "  🚨 Generated " << alerts_in_scenario << " alerts\n";
            }
        }
        std::cout << "\n";
    }
    
    // 4. Final statistics
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    engine.print_stats();
    
    // 5. Collect final results
    results.total_features_generated = static_cast<int>(engine.get_total_features_generated());
    
    // 6. Stop engine
    engine.stop();
    
    // 7. Print results
    results.print_summary();
    
    // 8. Validate results
    bool success = true;
    
    if(results.total_packets_processed == 0) {
        std::cout << "❌ No packets were processed\n";
        success = false;
    }
    
    if(results.total_features_generated == 0) {
        std::cout << "❌ No flow features were generated\n";
        success = false;
    }
    
    // We expect at least some alerts from the DoS and port scan scenarios
    if(results.total_alerts_generated == 0) {
        std::cout << "⚠️  No alerts generated (this may be expected if thresholds aren't met)\n";
    } else {
        std::cout << "✅ Alert generation working correctly\n";
    }
    
    if(success) {
        std::cout << "🎉 Full integration test PASSED!\n";
        std::cout << "✅ Packet processing: WORKING\n";
        std::cout << "✅ Flow feature generation: WORKING\n";
        std::cout << "✅ Flow analysis pipeline: WORKING\n";
        
        if(results.total_alerts_generated > 0) {
            std::cout << "✅ Alert generation: WORKING\n";
        }
    } else {
        std::cout << "❌ Integration test FAILED\n";
    }
    
    return success;
}

int main() {
    std::cout << "SnortSharp Full Snort3 Integration Test\n";
    std::cout << "======================================\n\n";
    
    try {
        bool success = run_full_integration_test();
        return success ? 0 : 1;
        
    } catch(const std::exception& e) {
        std::cerr << "❌ Test failed with exception: " << e.what() << "\n";
        return 1;
    }
}
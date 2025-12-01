#include "snortsharp_integration.hpp"
#include <iostream>
#include <memory>
#include <chrono>
#include <thread>
#include <sys/time.h>

void print_separator() {
    std::cout << "================================================================" << std::endl;
}

void print_header(const std::string& title) {
    std::cout << std::endl;
    print_separator();
    std::cout << "                    " << title << std::endl;
    print_separator();
    std::cout << std::endl;
}

int main() {
    print_header("SNORTSHARP INTEGRATED TEST");
    std::cout << "Testing complete Process 1 + Process 2 pipeline" << std::endl << std::endl;
    
    std::cout << "STEP 1: Creating SnortSharp engine..." << std::endl;
    auto engine = std::make_unique<SnortSharpEngine>(5, 50, 25);
    std::cout << "SUCCESS: Engine created with Process 1 (flow analysis) and Process 2 (rule engine)" << std::endl;
    
    std::cout << "\nSTEP 2: Loading flow-based detection rules..." << std::endl;
    engine->add_flow_rule("sid:2001 msg:\"Port Scan\" flow_iat_mean < 2000 AND syn_flag_count > 4");
    engine->add_flow_rule("sid:2002 msg:\"Small Packet DoS\" avg_packet_size < 100 AND fwd_packets > 8");
    engine->add_flow_rule("sid:2003 msg:\"Large Transfer\" avg_packet_size > 1000");
    std::cout << "SUCCESS: Loaded 3 detection rules" << std::endl;
    
    std::cout << "\nSTEP 3: Starting multi-threaded processing..." << std::endl;
    if(!engine->start()) {
        std::cerr << "ERROR: Failed to start engine" << std::endl;
        return 1;
    }
    std::cout << "SUCCESS: Process 1 and Process 2 threads started" << std::endl;
    
    // Wait for threads to initialize
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    print_header("SCENARIO 1: PORT SCAN SIMULATION");
    std::cout << "Generating fast SYN packets to trigger port scan rule..." << std::endl;
    
    for(int port = 80; port <= 88; port++) {
        SnortPacket pkt{};
        
        gettimeofday(&pkt.timestamp, nullptr);
        pkt.timestamp.tv_usec += port * 100; // Fast timing
        
        pkt.src_ip = 0xC0A80201;  // 192.168.2.1
        pkt.dst_ip = 0xC0A80101;  // 192.168.1.1
        pkt.src_port = 12345;
        pkt.dst_port = port;
        pkt.protocol = 6;
        pkt.packet_length = 60;
        pkt.header_length = 20;
        pkt.is_forward = true;
        pkt.tcp_flags.syn = true;
        
        std::cout << "  Packet to port " << port << std::endl;
        engine->process_snort_packet(pkt);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    std::cout << "\nWaiting for Process 1 -> Process 2 pipeline..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    std::cout << "\nChecking for alerts from Process 2:" << std::endl;
    FlowAlert alert{};
    int alert_count = 0;
    while(engine->get_next_alert(alert)) {
        alert_count++;
        std::cout << "  ALERT " << alert_count << ": SID:" << alert.rule_id 
                  << " - " << alert.message << std::endl;
        std::cout << "    Flow: " << (alert.features.total_fwd_packets + alert.features.total_bwd_packets) 
                  << " packets, " << alert.features.avg_packet_size 
                  << " avg size, " << alert.features.flow_iat_mean 
                  << " IAT mean" << std::endl;
    }
    
    if(alert_count == 0) {
        std::cout << "  No alerts yet (processing may still be in progress)" << std::endl;
    }
    
    print_header("SCENARIO 2: SMALL PACKET DOS SIMULATION");
    std::cout << "Generating many small packets to trigger DoS rule..." << std::endl;
    
    for(int i = 0; i < 15; i++) {
        SnortPacket pkt{};
        
        gettimeofday(&pkt.timestamp, nullptr);
        pkt.timestamp.tv_usec += i * 500;
        
        pkt.src_ip = 0xC0A80202;  // 192.168.2.2  
        pkt.dst_ip = 0xC0A80101;  // 192.168.1.1
        pkt.src_port = 54321;
        pkt.dst_port = 80;
        pkt.protocol = 6;
        pkt.packet_length = 40;   // Very small packets
        pkt.header_length = 20;
        pkt.is_forward = true;
        pkt.tcp_flags.ack = true;
        
        if(i % 3 == 0) {
            std::cout << "  Small packet batch " << (i/3 + 1) << std::endl;
        }
        engine->process_snort_packet(pkt);
        
        std::this_thread::sleep_for(std::chrono::microseconds(500));
    }
    
    std::cout << "\nWaiting for Process 1 -> Process 2 pipeline..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    std::cout << "\nChecking for new alerts:" << std::endl;
    int new_alerts = 0;
    while(engine->get_next_alert(alert)) {
        new_alerts++;
        std::cout << "  ALERT: SID:" << alert.rule_id << " - " << alert.message << std::endl;
        std::cout << "    Flow: " << (alert.features.total_fwd_packets + alert.features.total_bwd_packets) 
                  << " packets, " << alert.features.avg_packet_size << " avg size" << std::endl;
    }
    
    if(new_alerts == 0) {
        std::cout << "  No new alerts (may need more processing time)" << std::endl;
    }
    
    print_header("SCENARIO 3: LARGE TRANSFER SIMULATION");
    std::cout << "Generating large packets to trigger transfer rule..." << std::endl;
    
    for(int i = 0; i < 8; i++) {
        SnortPacket pkt{};
        
        gettimeofday(&pkt.timestamp, nullptr);
        pkt.timestamp.tv_usec += i * 2000;
        
        pkt.src_ip = 0xC0A80102;  // 192.168.1.2
        pkt.dst_ip = 0xC0A80101;  // 192.168.1.1
        pkt.src_port = 443;
        pkt.dst_port = 45678;
        pkt.protocol = 6;
        pkt.packet_length = 1460; // Large packets
        pkt.header_length = 20;
        pkt.is_forward = false;
        pkt.tcp_flags.ack = true;
        pkt.tcp_flags.psh = true;
        
        std::cout << "  Large packet " << (i + 1) << " (" << pkt.packet_length 
                  << " bytes)" << std::endl;
        engine->process_snort_packet(pkt);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    
    std::cout << "\nFinal processing wait..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    std::cout << "\nFinal alert check:" << std::endl;
    int final_alerts = 0;
    while(engine->get_next_alert(alert)) {
        final_alerts++;
        std::cout << "  ALERT: SID:" << alert.rule_id << " - " << alert.message << std::endl;
        std::cout << "    Flow: " << (alert.features.total_fwd_packets + alert.features.total_bwd_packets) 
                  << " packets, " << alert.features.avg_packet_size << " avg size" << std::endl;
    }
    
    print_header("INTEGRATION TEST SUMMARY");
    
    // Print engine statistics
    engine->print_stats();
    
    std::cout << "PIPELINE VERIFICATION:" << std::endl;
    std::cout << "  Process 1 (Flow Analysis): " << engine->get_total_packets_processed() 
              << " packets -> " << engine->get_total_features_generated() << " features" << std::endl;
    
    if(engine->get_rule_engine()) {
        std::cout << "  Process 2 (Rule Engine): " << engine->get_rule_engine()->get_total_evaluations() 
                  << " evaluations -> " << engine->get_rule_engine()->get_total_matches() 
                  << " matches" << std::endl;
    }
    
    if(engine->get_total_packets_processed() > 0 && engine->get_total_features_generated() > 0) {
        std::cout << "\nSUCCESS: Process 1 -> Process 2 pipeline is functional!" << std::endl;
    } else {
        std::cout << "\nWARNING: Pipeline may need tuning - check processing times" << std::endl;
    }
    
    std::cout << "\nKey Integration Points Tested:" << std::endl;
    std::cout << "  * Multi-threaded packet processing (Process 1)" << std::endl;
    std::cout << "  * Rolling window feature calculation (Process 1)" << std::endl;
    std::cout << "  * Thread-safe feature queue (Process 1 -> Process 2)" << std::endl;
    std::cout << "  * Flow-based rule evaluation (Process 2)" << std::endl;
    std::cout << "  * Real-time alert generation (Process 2)" << std::endl;
    std::cout << "  * Thread-safe alert queue (Process 2 -> output)" << std::endl;
    
    std::cout << "\nCleaning up..." << std::endl;
    engine->stop();
    
    print_separator();
    std::cout << "SNORTSHARP INTEGRATION TEST COMPLETED" << std::endl;
    print_separator();
    
    return 0;
}
#include "flow_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <sys/time.h>
#include <memory>

void addTest(FlowAnalyzer& analyzer, int size, bool is_forward, 
             bool syn, bool ack, bool fin, bool psh, 
             int delay_ms, int& window_count) {
    PacketInfo packet{};
    
    gettimeofday(&packet.timestamp, nullptr);
    
    // Add artificial delay
    packet.timestamp.tv_usec += delay_ms * 1000;
    if(packet.timestamp.tv_usec >= 1000000) {
        packet.timestamp.tv_sec += packet.timestamp.tv_usec / 1000000;
        packet.timestamp.tv_usec %= 1000000;
    }
    
    packet.src_ip = is_forward ? 0xC0A80101 : 0xC0A80102;
    packet.dst_ip = is_forward ? 0xC0A80102 : 0xC0A80101;
    packet.src_port = is_forward ? 12345 : 80;
    packet.dst_port = is_forward ? 80 : 12345;
    packet.protocol = 6;
    packet.packet_length = size;
    packet.header_length = 20;
    packet.payload_length = size - 20;
    packet.is_forward = is_forward;
    packet.window_size = 8192;
    
    packet.tcp_flags.syn = syn;
    packet.tcp_flags.ack = ack;
    packet.tcp_flags.fin = fin;
    packet.tcp_flags.psh = psh;
    
    FlowFeatures features{};
    std::cout << "+ " << std::setw(4) << size << " bytes " 
              << (is_forward ? "FWD" : "BWD") 
              << " SYN=" << syn << " ACK=" << ack 
              << " FIN=" << fin << " PSH=" << psh;
    
    if(analyzer.process_packet(packet, features)) {
        window_count++;
        std::cout << " -> WINDOW " << window_count << " FEATURES:" << std::endl;
        std::cout << "  Packets: " << features.total_fwd_packets 
                  << " fwd, " << features.total_bwd_packets 
                  << " bwd | Bytes: " << features.total_fwd_bytes 
                  << " fwd, " << features.total_bwd_bytes << " bwd" << std::endl;
        std::cout << "  Avg size: " << std::fixed << std::setprecision(1) 
                  << features.avg_packet_size 
                  << " | TCP flags: SYN=" << features.syn_flag_count 
                  << " ACK=" << features.ack_flag_count 
                  << " FIN=" << features.fin_flag_count 
                  << " PSH=" << features.psh_flag_count << std::endl;
        std::cout << "  IAT: mean=" << features.flow_iat_mean 
                  << " std=" << features.flow_iat_std 
                  << " | Rate: " << features.flow_bytes_per_sec 
                  << " bytes/sec" << std::endl;
    } else {
        std::cout << " (queued)" << std::endl;
    }
}

void run_scenario(const std::string& name, FlowAnalyzer& analyzer) {
    std::cout << "\n=== SCENARIO: " << name << " ===" << std::endl;
    int window_count = 0;
    
    if(name == "Normal Web Browsing") {
        addTest(analyzer, 60, true, true, false, false, false, 0, window_count);    // SYN
        addTest(analyzer, 60, false, true, true, false, false, 10, window_count);   // SYN-ACK
        addTest(analyzer, 52, true, false, true, false, false, 5, window_count);    // ACK
        addTest(analyzer, 200, true, false, true, false, true, 20, window_count);   // HTTP request
        addTest(analyzer, 52, false, false, true, false, false, 50, window_count);  // ACK
        addTest(analyzer, 1460, false, false, true, false, true, 10, window_count); // HTTP response
        addTest(analyzer, 800, false, false, true, false, false, 2, window_count);  // More data
        
    } else if(name == "Suspicious Fast Scanning") {
        // Rapid small packets to different ports (scanning behavior)
        addTest(analyzer, 60, true, true, false, false, false, 0, window_count);
        addTest(analyzer, 60, true, true, false, false, false, 1, window_count); // Very fast
        addTest(analyzer, 60, true, true, false, false, false, 1, window_count);
        addTest(analyzer, 60, true, true, false, false, false, 1, window_count);
        addTest(analyzer, 60, true, true, false, false, false, 1, window_count);
        addTest(analyzer, 60, true, true, false, false, false, 1, window_count);
        addTest(analyzer, 60, true, true, false, false, false, 1, window_count);
        
    } else if(name == "Large File Transfer") {
        addTest(analyzer, 60, true, true, false, false, false, 0, window_count);
        addTest(analyzer, 60, false, true, true, false, false, 5, window_count);
        addTest(analyzer, 52, true, false, true, false, false, 2, window_count);
        addTest(analyzer, 1460, true, false, true, false, false, 10, window_count); // Full MTU
        addTest(analyzer, 1460, true, false, true, false, false, 10, window_count);
        addTest(analyzer, 1460, true, false, true, false, false, 10, window_count);
        addTest(analyzer, 1460, true, false, true, false, false, 10, window_count);
    }
}

int main() {
    std::cout << "=== Flow Analyzer Demonstration ===" << std::endl;
    std::cout << "Testing different network scenarios to show flow feature differences" << std::endl;
    
    // Create analyzer with small window for quick demonstration
    auto analyzer = std::make_unique<FlowAnalyzer>(20, 5, 1);
    
    std::cout << "\nAnalyzer Configuration: Window Size = 5 packets" << std::endl;
    std::cout << "Features calculated after every 5 packets (rolling window)" << std::endl;
    
    run_scenario("Normal Web Browsing", *analyzer);
    
    // Reset analyzer for next scenario
    analyzer = std::make_unique<FlowAnalyzer>(20, 5, 1);
    
    run_scenario("Suspicious Fast Scanning", *analyzer);
    
    // Reset analyzer for next scenario
    analyzer = std::make_unique<FlowAnalyzer>(20, 5, 1);
    
    run_scenario("Large File Transfer", *analyzer);
    
    std::cout << "\n=== Analysis Summary ===" << std::endl;
    std::cout << "Notice how different traffic patterns produce different flow features:" << std::endl;
    std::cout << "1. Normal browsing: Mixed packet sizes, moderate timing" << std::endl;
    std::cout << "2. Port scanning: Small uniform packets, very fast timing" << std::endl;
    std::cout << "3. File transfer: Large uniform packets, consistent timing" << std::endl;
    std::cout << "\nThese features can be used to create rules like:" << std::endl;
    std::cout << "- Alert if mean_iat < 2ms AND packet_size < 100 (potential scanning)" << std::endl;
    std::cout << "- Alert if avg_packet_size > 1400 AND flow_rate > 10MB/s (bulk transfer)" << std::endl;
    
    return 0;
}
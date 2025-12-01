#include "flow_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <sys/time.h>
#include <memory>
#include <sstream>

void print_compact_features(const FlowFeatures& features) {
    std::cout << "\n--- Window Features ---" << std::endl;
    std::cout << "Packets: FWD=" << features.total_fwd_packets 
              << ", BWD=" << features.total_bwd_packets 
              << " | Bytes: FWD=" << features.total_fwd_bytes 
              << ", BWD=" << features.total_bwd_bytes << std::endl;
    std::cout << "Avg Size: " << std::fixed << std::setprecision(1) 
              << features.avg_packet_size 
              << " | Min=" << features.packet_length_min 
              << ", Max=" << features.packet_length_max << std::endl;
    std::cout << "IAT Stats: Mean=" << std::setprecision(2) 
              << features.flow_iat_mean << ", Std=" << features.flow_iat_std 
              << ", Min=" << features.flow_iat_min 
              << ", Max=" << features.flow_iat_max << std::endl;
    std::cout << "TCP Flags: SYN=" << features.syn_flag_count 
              << " ACK=" << features.ack_flag_count 
              << " FIN=" << features.fin_flag_count 
              << " RST=" << features.rst_flag_count 
              << " PSH=" << features.psh_flag_count << std::endl;
    std::cout << "Flow Rate: " << features.flow_bytes_per_sec 
              << " bytes/sec, " << features.flow_packets_per_sec 
              << " packets/sec" << std::endl;
    std::cout << "----------------------" << std::endl;
}

int main() {
    std::cout << "=== Interactive Flow Analyzer Test ===" << std::endl;
    std::cout << "Enter packet data to see flow features calculated in real-time" << std::endl << std::endl;
    
    int window_size, capacity;
    std::cout << "Enter window size (e.g., 5): ";
    std::cin >> window_size;
    std::cout << "Enter queue capacity (e.g., 20): ";
    std::cin >> capacity;
    
    auto analyzer = std::make_unique<FlowAnalyzer>(capacity, window_size, 1);
    
    std::cout << "\nAnalyzer created with window_size=" << window_size 
              << ", capacity=" << capacity << std::endl;
    std::cout << "Enter packets (format: size direction[f/b] syn ack fin psh) or 'q' to quit" << std::endl;
    std::cout << "Example: 100 f 1 0 0 0  (100-byte forward packet with SYN flag)" << std::endl << std::endl;
    
    int packet_count = 0;
    std::string input;
    FlowFeatures features{};
    
    // consume remaining newline from previous input
    std::cin.ignore();
    
    while(true) {
        std::cout << "Packet " << (packet_count + 1) << "> ";
        
        if(!std::getline(std::cin, input)) break;
        
        if(input.empty()) continue;
        if(input[0] == 'q' || input[0] == 'Q') break;
        
        std::istringstream iss(input);
        int size, syn, ack, fin, psh;
        char direction;
        
        if(!(iss >> size >> direction >> syn >> ack >> fin >> psh)) {
            std::cout << "Invalid format. Use: size direction[f/b] syn ack fin psh" << std::endl;
            continue;
        }
        
        if(size <= 0 || size > 9000) {
            std::cout << "Invalid packet size (1-9000)" << std::endl;
            continue;
        }
        
        bool is_forward = (direction == 'f' || direction == 'F');
        
        PacketInfo packet{};
        
        gettimeofday(&packet.timestamp, nullptr);
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
        
        packet.tcp_flags.syn = syn ? true : false;
        packet.tcp_flags.ack = ack ? true : false;
        packet.tcp_flags.fin = fin ? true : false;
        packet.tcp_flags.psh = psh ? true : false;
        
        std::cout << "Added: " << size << " bytes " 
                  << (is_forward ? "FWD" : "BWD") 
                  << " SYN=" << syn << " ACK=" << ack 
                  << " FIN=" << fin << " PSH=" << psh << std::endl;
        
        if(analyzer->process_packet(packet, features)) {
            std::cout << ">>> WINDOW COMPLETE - FEATURES CALCULATED <<<";
            print_compact_features(features);
        } else {
            std::cout << "Queued (packet in window)" << std::endl;
        }
        
        packet_count++;
    }
    
    std::cout << "\nTest completed. " << packet_count << " packets processed." << std::endl;
    return 0;
}
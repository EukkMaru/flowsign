#include "flow_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <sys/time.h>
#include <unistd.h>
#include <thread>
#include <chrono>

void print_flow_features(const FlowFeatures& features) {
    std::cout << "\n=== Flow Features ===" << std::endl;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Flow Duration: " << features.flow_duration << " microseconds" << std::endl;
    std::cout << "Total Forward Packets: " << features.total_fwd_packets << std::endl;
    std::cout << "Total Backward Packets: " << features.total_bwd_packets << std::endl;
    std::cout << "Total Forward Bytes: " << features.total_fwd_bytes << std::endl;
    std::cout << "Total Backward Bytes: " << features.total_bwd_bytes << std::endl;
    
    std::cout << "\nPacket Length Statistics:" << std::endl;
    std::cout << "  Min: " << features.packet_length_min 
              << ", Max: " << features.packet_length_max
              << ", Mean: " << features.packet_length_mean 
              << ", Std: " << features.packet_length_std << std::endl;
    
    std::cout << "\nForward Direction:" << std::endl;
    std::cout << "  Packet Length - Min: " << features.fwd_packet_length_min
              << ", Max: " << features.fwd_packet_length_max
              << ", Mean: " << features.fwd_packet_length_mean
              << ", Std: " << features.fwd_packet_length_std << std::endl;
    std::cout << "  IAT - Min: " << features.fwd_iat_min
              << ", Max: " << features.fwd_iat_max
              << ", Mean: " << features.fwd_iat_mean
              << ", Std: " << features.fwd_iat_std << std::endl;
    
    std::cout << "\nBackward Direction:" << std::endl;
    std::cout << "  Packet Length - Min: " << features.bwd_packet_length_min
              << ", Max: " << features.bwd_packet_length_max
              << ", Mean: " << features.bwd_packet_length_mean
              << ", Std: " << features.bwd_packet_length_std << std::endl;
    std::cout << "  IAT - Min: " << features.bwd_iat_min
              << ", Max: " << features.bwd_iat_max
              << ", Mean: " << features.bwd_iat_mean
              << ", Std: " << features.bwd_iat_std << std::endl;
    
    std::cout << "\nFlow Rates:" << std::endl;
    std::cout << "  Flow Bytes/sec: " << features.flow_bytes_per_sec << std::endl;
    std::cout << "  Flow Packets/sec: " << features.flow_packets_per_sec << std::endl;
    std::cout << "  Forward Packets/sec: " << features.fwd_packets_per_sec << std::endl;
    std::cout << "  Backward Packets/sec: " << features.bwd_packets_per_sec << std::endl;
    
    std::cout << "\nTCP Flags:" << std::endl;
    std::cout << "  SYN: " << features.syn_flag_count 
              << ", ACK: " << features.ack_flag_count
              << ", FIN: " << features.fin_flag_count 
              << ", RST: " << features.rst_flag_count
              << ", PSH: " << features.psh_flag_count 
              << ", URG: " << features.urg_flag_count << std::endl;
    
    std::cout << "\nOther Features:" << std::endl;
    std::cout << "  Down/Up Ratio: " << features.down_up_ratio << std::endl;
    std::cout << "  Average Packet Size: " << features.avg_packet_size << std::endl;
}

PacketInfo create_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, 
                        uint16_t dst_port, uint8_t protocol, uint16_t length, 
                        bool is_forward, bool syn = false, bool ack = false) {
    PacketInfo packet;
    packet.src_ip = src_ip;
    packet.dst_ip = dst_ip; 
    packet.src_port = src_port;
    packet.dst_port = dst_port;
    packet.protocol = protocol;
    packet.packet_length = length;
    packet.header_length = 20; // standard TCP header
    packet.payload_length = length - 20;
    packet.is_forward = is_forward;
    
    // get current time
    gettimeofday(&packet.timestamp, nullptr);
    
    // TCP flags
    std::memset(&packet.tcp_flags, 0, sizeof(packet.tcp_flags));
    packet.tcp_flags.syn = syn;
    packet.tcp_flags.ack = ack;
    
    packet.window_size = 65535;
    
    return packet;
}

int main() {
    std::cout << "Flow Analyzer Test Program" << std::endl;
    std::cout << "=========================" << std::endl;
    
    // create flow analyzer with window size 10, step size 5
    auto analyzer = std::make_unique<FlowAnalyzer>(100, 10, 5);
    
    std::cout << "\nGenerating test packets..." << std::endl;
    
    // simulate a bidirectional TCP flow
    struct {
        uint32_t src_ip = 0xC0A80101; // 192.168.1.1
        uint32_t dst_ip = 0xC0A80102; // 192.168.1.2
        uint16_t src_port = 12345;
        uint16_t dst_port = 80;
    } flow;
    
    FlowFeatures features;
    
    // send SYN packet
    PacketInfo syn_packet = create_packet(flow.src_ip, flow.dst_ip, flow.src_port, 
                                         flow.dst_port, 6, 64, true, true, false);
    std::cout << "Processing SYN packet..." << std::endl;
    analyzer->process_packet(syn_packet, features);
    
    // send SYN+ACK packet  
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    PacketInfo synack_packet = create_packet(flow.dst_ip, flow.src_ip, flow.dst_port,
                                            flow.src_port, 6, 64, false, true, true);
    std::cout << "Processing SYN+ACK packet..." << std::endl;
    analyzer->process_packet(synack_packet, features);
    
    // send ACK packet
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    PacketInfo ack_packet = create_packet(flow.src_ip, flow.dst_ip, flow.src_port,
                                         flow.dst_port, 6, 64, true, false, true);
    std::cout << "Processing ACK packet..." << std::endl;
    analyzer->process_packet(ack_packet, features);
    
    // send some data packets
    for(int i = 0; i < 8; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        // forward data packet
        PacketInfo fwd_data = create_packet(flow.src_ip, flow.dst_ip, flow.src_port,
                                           flow.dst_port, 6, 1500, true, false, true);
        analyzer->process_packet(fwd_data, features);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        
        // backward ACK packet
        PacketInfo bwd_ack = create_packet(flow.dst_ip, flow.src_ip, flow.dst_port,
                                          flow.src_port, 6, 64, false, false, true);
        bool result = analyzer->process_packet(bwd_ack, features);
        
        if(result) {
            std::cout << "\nFlow features generated after packet " << (i * 2 + 5) << std::endl;
            print_flow_features(features);
            break;
        }
    }
    
    std::cout << "\n=== Test completed successfully! ===" << std::endl;
    
    return 0;
}
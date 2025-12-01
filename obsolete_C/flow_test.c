#include "flow_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

void print_flow_features(const flow_features_t *features) {
    printf("\n=== Flow Features ===\n");
    printf("Flow Duration: %.2f microseconds\n", features->flow_duration);
    printf("Total Forward Packets: %u\n", features->total_fwd_packets);
    printf("Total Backward Packets: %u\n", features->total_bwd_packets);
    printf("Total Forward Bytes: %lu\n", features->total_fwd_bytes);
    printf("Total Backward Bytes: %lu\n", features->total_bwd_bytes);
    
    printf("\nPacket Length Statistics:\n");
    printf("  Min: %u, Max: %u, Mean: %.2f, Std: %.2f\n", 
           features->packet_length_min, features->packet_length_max,
           features->packet_length_mean, features->packet_length_std);
    
    printf("\nForward Direction:\n");
    printf("  Packet Length - Min: %u, Max: %u, Mean: %.2f, Std: %.2f\n",
           features->fwd_packet_length_min, features->fwd_packet_length_max,
           features->fwd_packet_length_mean, features->fwd_packet_length_std);
    printf("  IAT - Min: %.2f, Max: %.2f, Mean: %.2f, Std: %.2f\n",
           features->fwd_iat_min, features->fwd_iat_max,
           features->fwd_iat_mean, features->fwd_iat_std);
    
    printf("\nBackward Direction:\n");
    printf("  Packet Length - Min: %u, Max: %u, Mean: %.2f, Std: %.2f\n",
           features->bwd_packet_length_min, features->bwd_packet_length_max,
           features->bwd_packet_length_mean, features->bwd_packet_length_std);
    printf("  IAT - Min: %.2f, Max: %.2f, Mean: %.2f, Std: %.2f\n",
           features->bwd_iat_min, features->bwd_iat_max,
           features->bwd_iat_mean, features->bwd_iat_std);
    
    printf("\nFlow Rates:\n");
    printf("  Flow Bytes/sec: %.2f\n", features->flow_bytes_per_sec);
    printf("  Flow Packets/sec: %.2f\n", features->flow_packets_per_sec);
    printf("  Forward Packets/sec: %.2f\n", features->fwd_packets_per_sec);
    printf("  Backward Packets/sec: %.2f\n", features->bwd_packets_per_sec);
    
    printf("\nTCP Flags:\n");
    printf("  SYN: %u, ACK: %u, FIN: %u, RST: %u, PSH: %u, URG: %u\n",
           features->syn_flag_count, features->ack_flag_count,
           features->fin_flag_count, features->rst_flag_count,
           features->psh_flag_count, features->urg_flag_count);
    
    printf("\nOther Features:\n");
    printf("  Down/Up Ratio: %.2f\n", features->down_up_ratio);
    printf("  Average Packet Size: %.2f\n", features->avg_packet_size);
    printf("  Forward Init Window: %u\n", features->fwd_init_win_bytes);
    printf("  Backward Init Window: %u\n", features->bwd_init_win_bytes);
    printf("====================\n\n");
}

packet_info_t create_test_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, 
                                uint16_t dst_port, uint16_t length, bool is_forward,
                                bool syn, bool ack, bool fin, bool psh) {
    packet_info_t packet;
    memset(&packet, 0, sizeof(packet_info_t));
    
    gettimeofday(&packet.timestamp, NULL);
    packet.src_ip = src_ip;
    packet.dst_ip = dst_ip;
    packet.src_port = src_port;
    packet.dst_port = dst_port;
    packet.protocol = 6; // TCP
    packet.packet_length = length;
    packet.header_length = 20; // Basic TCP header
    packet.payload_length = length - 20;
    packet.is_forward = is_forward;
    packet.window_size = 8192;
    
    packet.tcp_flags.syn = syn;
    packet.tcp_flags.ack = ack;
    packet.tcp_flags.fin = fin;
    packet.tcp_flags.psh = psh;
    
    return packet;
}

int main() {
    printf("Flow Analyzer Test Program\n");
    printf("==========================\n");
    
    // Create flow analyzer with window size of 10 packets, capacity of 50, step size of 1
    flow_analyzer_t *analyzer = create_flow_analyzer(50, 10, 1);
    if (!analyzer) {
        printf("Failed to create flow analyzer\n");
        return 1;
    }
    
    // Simulate a TCP connection with some packets
    printf("Simulating TCP connection packets...\n");
    
    packet_info_t packets[15];
    flow_features_t features;
    
    // SYN packet (forward)
    packets[0] = create_test_packet(0xC0A80101, 0xC0A80102, 12345, 80, 60, true, true, false, false, false);
    
    // SYN-ACK packet (backward)  
    packets[1] = create_test_packet(0xC0A80102, 0xC0A80101, 80, 12345, 60, false, true, true, false, false);
    
    // ACK packet (forward)
    packets[2] = create_test_packet(0xC0A80101, 0xC0A80102, 12345, 80, 52, true, false, true, false, false);
    
    // Data packets (forward and backward)
    for (int i = 3; i < 12; i++) {
        bool is_fwd = (i % 2 == 1);
        uint16_t size = 500 + (i * 50); // Varying packet sizes
        bool push_flag = (i > 8); // PSH flag on later packets
        
        packets[i] = create_test_packet(
            is_fwd ? 0xC0A80101 : 0xC0A80102,
            is_fwd ? 0xC0A80102 : 0xC0A80101,
            is_fwd ? 12345 : 80,
            is_fwd ? 80 : 12345,
            size, is_fwd, false, true, false, push_flag
        );
    }
    
    // FIN packets
    packets[12] = create_test_packet(0xC0A80101, 0xC0A80102, 12345, 80, 52, true, false, true, true, false);
    packets[13] = create_test_packet(0xC0A80102, 0xC0A80101, 80, 12345, 52, false, false, true, true, false);
    packets[14] = create_test_packet(0xC0A80101, 0xC0A80102, 12345, 80, 52, true, false, true, false, false);
    
    // Process packets through the analyzer
    for (int i = 0; i < 15; i++) {
        printf("Processing packet %d (size: %u, direction: %s)\n", 
               i + 1, packets[i].packet_length, 
               packets[i].is_forward ? "forward" : "backward");
        
        if (process_packet(analyzer, &packets[i], &features)) {
            printf("Window %d completed - Flow features calculated:\n", i - analyzer->queue->window_size + 2);
            print_flow_features(&features);
        }
    }
    
    printf("Test completed. The rolling window approach generates flow features every time\n");
    printf("a new packet is processed (once the initial window is filled).\n");
    printf("This allows for real-time flow-based intrusion detection.\n");
    
    destroy_flow_analyzer(analyzer);
    return 0;
}
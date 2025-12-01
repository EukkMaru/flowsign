#include "flow_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

void print_compact_features(const flow_features_t *features) {
    printf("\n--- Window Features ---\n");
    printf("Packets: FWD=%u, BWD=%u | Bytes: FWD=%lu, BWD=%lu\n", 
           features->total_fwd_packets, features->total_bwd_packets,
           features->total_fwd_bytes, features->total_bwd_bytes);
    printf("Avg Size: %.1f | Min=%u, Max=%u\n", 
           features->avg_packet_size, features->packet_length_min, features->packet_length_max);
    printf("IAT Stats: Mean=%.2f, Std=%.2f, Min=%.2f, Max=%.2f\n",
           features->flow_iat_mean, features->flow_iat_std, 
           features->flow_iat_min, features->flow_iat_max);
    printf("TCP Flags: SYN=%u ACK=%u FIN=%u RST=%u PSH=%u\n",
           features->syn_flag_count, features->ack_flag_count,
           features->fin_flag_count, features->rst_flag_count, features->psh_flag_count);
    printf("Flow Rate: %.2f bytes/sec, %.2f packets/sec\n",
           features->flow_bytes_per_sec, features->flow_packets_per_sec);
    printf("----------------------\n");
}

int main() {
    printf("=== Interactive Flow Analyzer Test ===\n");
    printf("Enter packet data to see flow features calculated in real-time\n\n");
    
    int window_size, capacity;
    printf("Enter window size (e.g., 5): ");
    scanf("%d", &window_size);
    printf("Enter queue capacity (e.g., 20): ");
    scanf("%d", &capacity);
    
    flow_analyzer_t *analyzer = create_flow_analyzer(capacity, window_size, 1);
    if (!analyzer) {
        printf("Failed to create analyzer\n");
        return 1;
    }
    
    printf("\nAnalyzer created with window_size=%d, capacity=%d\n", window_size, capacity);
    printf("Enter packets (format: size direction[f/b] syn ack fin psh) or 'q' to quit\n");
    printf("Example: 100 f 1 0 0 0  (100-byte forward packet with SYN flag)\n\n");
    
    int packet_count = 0;
    char input[256];
    flow_features_t features;
    
    while (1) {
        printf("Packet %d> ", packet_count + 1);
        
        if (!fgets(input, sizeof(input), stdin)) break;
        
        if (input[0] == 'q' || input[0] == 'Q') break;
        
        int size, syn, ack, fin, psh;
        char direction;
        
        if (sscanf(input, "%d %c %d %d %d %d", &size, &direction, &syn, &ack, &fin, &psh) != 6) {
            if (strlen(input) > 1) {
                printf("Invalid format. Use: size direction[f/b] syn ack fin psh\n");
            }
            continue;
        }
        
        if (size <= 0 || size > 9000) {
            printf("Invalid packet size (1-9000)\n");
            continue;
        }
        
        bool is_forward = (direction == 'f' || direction == 'F');
        
        packet_info_t packet;
        memset(&packet, 0, sizeof(packet_info_t));
        
        gettimeofday(&packet.timestamp, NULL);
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
        
        packet.tcp_flags.syn = syn ? 1 : 0;
        packet.tcp_flags.ack = ack ? 1 : 0;
        packet.tcp_flags.fin = fin ? 1 : 0;
        packet.tcp_flags.psh = psh ? 1 : 0;
        
        printf("Added: %u bytes %s SYN=%d ACK=%d FIN=%d PSH=%d\n", 
               size, is_forward ? "FWD" : "BWD", syn, ack, fin, psh);
        
        if (process_packet(analyzer, &packet, &features)) {
            printf(">>> WINDOW COMPLETE - FEATURES CALCULATED <<<");
            print_compact_features(&features);
        } else {
            printf("Queued (%d/%d packets in window)\n", 
                   analyzer->queue->size, window_size);
        }
        
        packet_count++;
    }
    
    destroy_flow_analyzer(analyzer);
    printf("\nTest completed. %d packets processed.\n", packet_count);
    return 0;
}
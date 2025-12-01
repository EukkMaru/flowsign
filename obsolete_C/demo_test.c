#include "flow_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

void addTest(flow_analyzer_t *analyzer, int size, bool is_forward, 
                          bool syn, bool ack, bool fin, bool psh, 
                          int delay_ms, int *window_count) {
    packet_info_t packet;
    memset(&packet, 0, sizeof(packet_info_t));
    
    gettimeofday(&packet.timestamp, NULL);
    
    // Add artificial delay
    packet.timestamp.tv_usec += delay_ms * 1000;
    if (packet.timestamp.tv_usec >= 1000000) {
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
    
    flow_features_t features;
    printf("+ %4d bytes %s SYN=%d ACK=%d FIN=%d PSH=%d", 
           size, is_forward ? "FWD" : "BWD", syn, ack, fin, psh);
    
    if (process_packet(analyzer, &packet, &features)) {
        (*window_count)++;
        printf(" -> WINDOW %d FEATURES:\n", *window_count);
        printf("  Packets: %u fwd, %u bwd | Bytes: %lu fwd, %lu bwd\n",
               features.total_fwd_packets, features.total_bwd_packets,
               features.total_fwd_bytes, features.total_bwd_bytes);
        printf("  Avg size: %.1f | TCP flags: SYN=%u ACK=%u FIN=%u PSH=%u\n",
               features.avg_packet_size, features.syn_flag_count, 
               features.ack_flag_count, features.fin_flag_count, features.psh_flag_count);
        printf("  IAT: mean=%.1f std=%.1f | Rate: %.1f bytes/sec\n",
               features.flow_iat_mean, features.flow_iat_std, features.flow_bytes_per_sec);
    } else {
        printf(" (queued: %d/%d)\n", analyzer->queue->size, analyzer->queue->window_size);
    }
}

void run_scenario(const char *name, flow_analyzer_t *analyzer) {
    printf("\n=== SCENARIO: %s ===\n", name);
    int window_count = 0;
    
    if (strcmp(name, "Normal Web Browsing") == 0) {
        addTest(analyzer, 60, true, true, false, false, false, 0, &window_count);    // SYN
        addTest(analyzer, 60, false, true, true, false, false, 10, &window_count);   // SYN-ACK
        addTest(analyzer, 52, true, false, true, false, false, 5, &window_count);    // ACK
        addTest(analyzer, 200, true, false, true, false, true, 20, &window_count);   // HTTP request
        addTest(analyzer, 52, false, false, true, false, false, 50, &window_count);  // ACK
        addTest(analyzer, 1460, false, false, true, false, true, 10, &window_count); // HTTP response
        addTest(analyzer, 800, false, false, true, false, false, 2, &window_count);  // More data
        
    } else if (strcmp(name, "Suspicious Fast Scanning") == 0) {
        // Rapid small packets to different ports (scanning behavior)
        addTest(analyzer, 60, true, true, false, false, false, 0, &window_count);
        addTest(analyzer, 60, true, true, false, false, false, 1, &window_count); // Very fast
        addTest(analyzer, 60, true, true, false, false, false, 1, &window_count);
        addTest(analyzer, 60, true, true, false, false, false, 1, &window_count);
        addTest(analyzer, 60, true, true, false, false, false, 1, &window_count);
        addTest(analyzer, 60, true, true, false, false, false, 1, &window_count);
        addTest(analyzer, 60, true, true, false, false, false, 1, &window_count);
        
    } else if (strcmp(name, "Large File Transfer") == 0) {
        addTest(analyzer, 60, true, true, false, false, false, 0, &window_count);
        addTest(analyzer, 60, false, true, true, false, false, 5, &window_count);
        addTest(analyzer, 52, true, false, true, false, false, 2, &window_count);
        addTest(analyzer, 1460, true, false, true, false, false, 10, &window_count); // Full MTU
        addTest(analyzer, 1460, true, false, true, false, false, 10, &window_count);
        addTest(analyzer, 1460, true, false, true, false, false, 10, &window_count);
        addTest(analyzer, 1460, true, false, true, false, false, 10, &window_count);
    }
}

int main() {
    printf("=== Flow Analyzer Demonstration ===\n");
    printf("Testing different network scenarios to show flow feature differences\n");
    
    // Create analyzer with small window for quick demonstration
    flow_analyzer_t *analyzer = create_flow_analyzer(20, 5, 1);
    if (!analyzer) {
        printf("Failed to create analyzer\n");
        return 1;
    }
    
    printf("\nAnalyzer Configuration: Window Size = 5 packets\n");
    printf("Features calculated after every 5 packets (rolling window)\n");
    
    run_scenario("Normal Web Browsing", analyzer);
    
    // Reset analyzer for next scenario
    destroy_flow_analyzer(analyzer);
    analyzer = create_flow_analyzer(20, 5, 1);
    
    run_scenario("Suspicious Fast Scanning", analyzer);
    
    // Reset analyzer for next scenario
    destroy_flow_analyzer(analyzer);
    analyzer = create_flow_analyzer(20, 5, 1);
    
    run_scenario("Large File Transfer", analyzer);
    
    destroy_flow_analyzer(analyzer);
    
    printf("\n=== Analysis Summary ===\n");
    printf("Notice how different traffic patterns produce different flow features:\n");
    printf("1. Normal browsing: Mixed packet sizes, moderate timing\n");
    printf("2. Port scanning: Small uniform packets, very fast timing\n");
    printf("3. File transfer: Large uniform packets, consistent timing\n");
    printf("\nThese features can be used to create rules like:\n");
    printf("- Alert if mean_iat < 2ms AND packet_size < 100 (potential scanning)\n");
    printf("- Alert if avg_packet_size > 1400 AND flow_rate > 10MB/s (bulk transfer)\n");
    
    return 0;
}
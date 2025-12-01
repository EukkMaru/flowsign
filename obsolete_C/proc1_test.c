#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <string.h>
#include <arpa/inet.h>
#include "flow_analyzer.h"
#include "event_system.h"

static volatile bool running = true;
static event_system_t *event_sys = NULL;

void signal_handler(int sig) {
    (void)sig;
    printf("\n[PROC1] Shutting down...\n");
    running = false;
    
    if (event_sys) {
        send_shutdown_event(event_sys);
    }
}

void setup_test_packet(packet_info_t *packet, int seq, const char *src_ip, const char *dst_ip,
                      uint16_t src_port, uint16_t dst_port, uint16_t pkt_len, 
                      bool syn, bool ack, bool fin, bool psh) {
    gettimeofday(&packet->timestamp, NULL);
    
    // Add some microsecond offset based on sequence for realistic timing
    packet->timestamp.tv_usec += seq * 1000;
    if (packet->timestamp.tv_usec >= 1000000) {
        packet->timestamp.tv_sec++;
        packet->timestamp.tv_usec -= 1000000;
    }
    
    packet->src_ip = inet_addr(src_ip);
    packet->dst_ip = inet_addr(dst_ip);
    packet->src_port = src_port;
    packet->dst_port = dst_port;
    packet->protocol = 6; // TCP
    packet->packet_length = pkt_len;
    packet->header_length = 54; // TCP + IP headers
    packet->payload_length = pkt_len - 54; // Subtract headers
    packet->is_forward = (seq % 2 == 0);
    
    // Set TCP flags
    packet->tcp_flags.syn = syn;
    packet->tcp_flags.ack = ack;
    packet->tcp_flags.fin = fin;
    packet->tcp_flags.psh = psh;
    packet->tcp_flags.rst = false;
    packet->tcp_flags.urg = false;
    packet->tcp_flags.cwr = false;
    packet->tcp_flags.ece = false;
    
    packet->window_size = 8192;
}

int main() {
    printf("[PROC1] Flow Analyzer Process - Event Broadcasting Demo\n");
    printf("===============================================\n");
    
    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create flow analyzer
    flow_analyzer_t *analyzer = create_flow_analyzer(50, 5, 1);
    if (!analyzer) {
        fprintf(stderr, "[PROC1] Failed to create flow analyzer\n");
        return 1;
    }
    
    // Create event system (client)
    event_sys = create_event_system("/tmp/snortsharp_events", false);
    if (!event_sys) {
        fprintf(stderr, "[PROC1] Failed to create event system\n");
        destroy_flow_analyzer(analyzer);
        return 1;
    }
    
    // Connect to event server
    printf("[PROC1] Connecting to event server...\n");
    if (connect_event_client(event_sys) != 0) {
        fprintf(stderr, "[PROC1] Failed to connect to event server\n");
        destroy_event_system(event_sys);
        destroy_flow_analyzer(analyzer);
        return 1;
    }
    
    // Give some time for connection to establish
    usleep(100000); // 100ms
    
    // Simulate flow processing
    printf("[PROC1] Starting packet processing and event broadcasting...\n");
    printf("[PROC1] Window size: 5 packets, Broadcasting on each window completion\n\n");
    
    packet_info_t packet;
    flow_features_t features;
    uint32_t flow_id = 12345;
    int packet_count = 0;
    
    while (running && packet_count < 20) {
        // Create different types of packets to simulate realistic traffic
        if (packet_count < 3) {
            // TCP handshake
            if (packet_count == 0) {
                setup_test_packet(&packet, packet_count, "192.168.1.100", "10.0.0.50", 
                                12345, 80, 60, true, false, false, false); // SYN
            } else if (packet_count == 1) {
                setup_test_packet(&packet, packet_count, "10.0.0.50", "192.168.1.100", 
                                80, 12345, 60, true, true, false, false); // SYN-ACK
            } else {
                setup_test_packet(&packet, packet_count, "192.168.1.100", "10.0.0.50", 
                                12345, 80, 60, false, true, false, false); // ACK
            }
        } else if (packet_count < 15) {
            // Data exchange
            setup_test_packet(&packet, packet_count, "192.168.1.100", "10.0.0.50",
                            12345, 80, 1200 + (packet_count * 50), false, true, false, true); // PSH+ACK
        } else {
            // Connection teardown
            setup_test_packet(&packet, packet_count, "192.168.1.100", "10.0.0.50",
                            12345, 80, 60, false, false, true, false); // FIN
        }
        
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = packet.src_ip;
        dst_addr.s_addr = packet.dst_ip;
        
        uint8_t flags_byte = (packet.tcp_flags.syn ? 0x02 : 0) |
                            (packet.tcp_flags.ack ? 0x10 : 0) |
                            (packet.tcp_flags.fin ? 0x01 : 0) |
                            (packet.tcp_flags.psh ? 0x08 : 0);
        
        printf("[PROC1] Processing packet %d: %s:%d -> %s:%d (len=%d, flags=0x%02x)\n",
               packet_count + 1, inet_ntoa(src_addr), packet.src_port, 
               inet_ntoa(dst_addr), packet.dst_port, packet.packet_length, flags_byte);
        
        // Process packet through flow analyzer
        bool window_ready = process_packet(analyzer, &packet, &features);
        
        if (window_ready) {
            printf("[PROC1] *** WINDOW COMPLETED *** Broadcasting event to proc2\n");
            printf("[PROC1] Features: duration=%.2fms, total_packets=%d, total_bytes=%ld\n",
                   features.flow_duration / 1000.0, features.total_fwd_packets + features.total_bwd_packets, 
                   features.total_fwd_bytes + features.total_bwd_bytes);
            printf("[PROC1] Forward: packets=%d, bytes=%ld, avg_len=%.1f\n",
                   features.total_fwd_packets, features.total_fwd_bytes, features.fwd_packet_length_mean);
            printf("[PROC1] Backward: packets=%d, bytes=%ld, avg_len=%.1f\n",
                   features.total_bwd_packets, features.total_bwd_bytes, features.bwd_packet_length_mean);
            
            // Broadcast window event
            if (broadcast_window_event(event_sys, flow_id, &features, "proc1") != 0) {
                fprintf(stderr, "[PROC1] Failed to broadcast window event\n");
            } else {
                printf("[PROC1] Event broadcasted successfully!\n");
            }
            printf("\n");
        }
        
        packet_count++;
        
        // Simulate real-time packet arrival
        usleep(200000); // 200ms between packets
    }
    
    printf("[PROC1] Finished processing %d packets\n", packet_count);
    
    // Send shutdown event
    if (running) {
        printf("[PROC1] Sending shutdown event...\n");
        send_shutdown_event(event_sys);
        usleep(100000); // Give time for shutdown event to be sent
    }
    
    // Cleanup
    disconnect_event_client(event_sys);
    destroy_event_system(event_sys);
    destroy_flow_analyzer(analyzer);
    
    printf("[PROC1] Process 1 (Flow Analyzer) finished\n");
    return 0;
}
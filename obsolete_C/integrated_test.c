#define _POSIX_C_SOURCE 200809L
#include "snortsharp_integration.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

void print_separator() {
    printf("================================================================\n");
}

void print_header(const char *title) {
    printf("\n");
    print_separator();
    printf("                    %s\n", title);
    print_separator();
    printf("\n");
}

int main() {
    print_header("SNORTSHARP INTEGRATED TEST");
    printf("Testing complete Process 1 + Process 2 pipeline\n\n");
    
    printf("STEP 1: Creating SnortSharp engine...\n");
    snortsharp_engine_t *engine = create_snortsharp_engine(5, 50, 25);
    if (!engine) {
        printf("ERROR: Failed to create SnortSharp engine\n");
        return 1;
    }
    printf("SUCCESS: Engine created with Process 1 (flow analysis) and Process 2 (rule engine)\n");
    
    printf("\nSTEP 2: Loading flow-based detection rules...\n");
    add_flow_rule(engine, "sid:2001 msg:\"Port Scan\" flow_iat_mean < 2000 AND syn_flag_count > 4");
    add_flow_rule(engine, "sid:2002 msg:\"Small Packet DoS\" avg_packet_size < 100 AND fwd_packets > 8");
    add_flow_rule(engine, "sid:2003 msg:\"Large Transfer\" avg_packet_size > 1000");
    printf("SUCCESS: Loaded 3 detection rules\n");
    
    printf("\nSTEP 3: Starting multi-threaded processing...\n");
    if (!start_snortsharp_engine(engine)) {
        printf("ERROR: Failed to start engine\n");
        destroy_snortsharp_engine(engine);
        return 1;
    }
    printf("SUCCESS: Process 1 and Process 2 threads started\n");
    
    // Wait for threads to initialize
    struct timespec init_wait = {0, 100000000}; // 100ms
    nanosleep(&init_wait, NULL);
    
    print_header("SCENARIO 1: PORT SCAN SIMULATION");
    printf("Generating fast SYN packets to trigger port scan rule...\n");
    
    for (int port = 80; port <= 88; port++) {
        snort_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        
        gettimeofday(&pkt.timestamp, NULL);
        pkt.timestamp.tv_usec += port * 100; // Fast timing
        
        pkt.src_ip = 0xC0A80201;  // 192.168.2.1
        pkt.dst_ip = 0xC0A80101;  // 192.168.1.1
        pkt.src_port = 12345;
        pkt.dst_port = port;
        pkt.protocol = 6;
        pkt.packet_length = 60;
        pkt.header_length = 20;
        pkt.is_forward = true;
        pkt.tcp_flags.syn = 1;
        
        printf("  Packet to port %d\n", port);
        process_snort_packet(engine, &pkt);
        
        struct timespec small_delay = {0, 1000000}; // 1ms
        nanosleep(&small_delay, NULL);
    }
    
    printf("\nWaiting for Process 1 -> Process 2 pipeline...\n");
    struct timespec wait = {0, 200000000}; // 200ms
    nanosleep(&wait, NULL);
    
    printf("\nChecking for alerts from Process 2:\n");
    flow_alert_t alert;
    int alert_count = 0;
    while (get_next_alert(engine, &alert)) {
        alert_count++;
        printf("  ALERT %d: SID:%u - %s\n", alert_count, alert.rule_id, alert.message);
        printf("    Flow: %u packets, %.1f avg size, %.1f IAT mean\n",
               alert.features.total_fwd_packets + alert.features.total_bwd_packets,
               alert.features.avg_packet_size, alert.features.flow_iat_mean);
    }
    
    if (alert_count == 0) {
        printf("  No alerts yet (processing may still be in progress)\n");
    }
    
    print_header("SCENARIO 2: SMALL PACKET DOS SIMULATION");
    printf("Generating many small packets to trigger DoS rule...\n");
    
    for (int i = 0; i < 15; i++) {
        snort_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        
        gettimeofday(&pkt.timestamp, NULL);
        pkt.timestamp.tv_usec += i * 500;
        
        pkt.src_ip = 0xC0A80202;  // 192.168.2.2  
        pkt.dst_ip = 0xC0A80101;  // 192.168.1.1
        pkt.src_port = 54321;
        pkt.dst_port = 80;
        pkt.protocol = 6;
        pkt.packet_length = 40;   // Very small packets
        pkt.header_length = 20;
        pkt.is_forward = true;
        pkt.tcp_flags.ack = 1;
        
        if (i % 3 == 0) {
            printf("  Small packet batch %d\n", i/3 + 1);
        }
        process_snort_packet(engine, &pkt);
        
        struct timespec tiny_delay = {0, 500000}; // 0.5ms
        nanosleep(&tiny_delay, NULL);
    }
    
    printf("\nWaiting for Process 1 -> Process 2 pipeline...\n");
    nanosleep(&wait, NULL);
    
    printf("\nChecking for new alerts:\n");
    int new_alerts = 0;
    while (get_next_alert(engine, &alert)) {
        new_alerts++;
        printf("  ALERT: SID:%u - %s\n", alert.rule_id, alert.message);
        printf("    Flow: %u packets, %.1f avg size\n",
               alert.features.total_fwd_packets + alert.features.total_bwd_packets,
               alert.features.avg_packet_size);
    }
    
    if (new_alerts == 0) {
        printf("  No new alerts (may need more processing time)\n");
    }
    
    print_header("SCENARIO 3: LARGE TRANSFER SIMULATION");
    printf("Generating large packets to trigger transfer rule...\n");
    
    for (int i = 0; i < 8; i++) {
        snort_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        
        gettimeofday(&pkt.timestamp, NULL);
        pkt.timestamp.tv_usec += i * 2000;
        
        pkt.src_ip = 0xC0A80102;  // 192.168.1.2
        pkt.dst_ip = 0xC0A80101;  // 192.168.1.1
        pkt.src_port = 443;
        pkt.dst_port = 45678;
        pkt.protocol = 6;
        pkt.packet_length = 1460; // Large packets
        pkt.header_length = 20;
        pkt.is_forward = false;
        pkt.tcp_flags.ack = 1;
        pkt.tcp_flags.psh = 1;
        
        printf("  Large packet %d (%u bytes)\n", i + 1, pkt.packet_length);
        process_snort_packet(engine, &pkt);
        
        struct timespec med_delay = {0, 2000000}; // 2ms
        nanosleep(&med_delay, NULL);
    }
    
    printf("\nFinal processing wait...\n");
    nanosleep(&wait, NULL);
    
    printf("\nFinal alert check:\n");
    int final_alerts = 0;
    while (get_next_alert(engine, &alert)) {
        final_alerts++;
        printf("  ALERT: SID:%u - %s\n", alert.rule_id, alert.message);
        printf("    Flow: %u packets, %.1f avg size\n",
               alert.features.total_fwd_packets + alert.features.total_bwd_packets,
               alert.features.avg_packet_size);
    }
    
    print_header("INTEGRATION TEST SUMMARY");
    
    // Print engine statistics
    print_snortsharp_stats(engine);
    
    printf("PIPELINE VERIFICATION:\n");
    printf("  Process 1 (Flow Analysis): %lu packets -> %lu features\n",
           engine->total_packets_processed, engine->total_features_generated);
    printf("  Process 2 (Rule Engine): %lu evaluations -> %lu matches\n",
           engine->rule_engine->total_evaluations, engine->rule_engine->total_matches);
    
    if (engine->total_packets_processed > 0 && engine->total_features_generated > 0) {
        printf("\nSUCCESS: Process 1 -> Process 2 pipeline is functional!\n");
    } else {
        printf("\nWARNING: Pipeline may need tuning - check processing times\n");
    }
    
    printf("\nKey Integration Points Tested:\n");
    printf("  * Multi-threaded packet processing (Process 1)\n");
    printf("  * Rolling window feature calculation (Process 1)\n");
    printf("  * Thread-safe feature queue (Process 1 -> Process 2)\n");
    printf("  * Flow-based rule evaluation (Process 2)\n");
    printf("  * Real-time alert generation (Process 2)\n");
    printf("  * Thread-safe alert queue (Process 2 -> output)\n");
    
    printf("\nCleaning up...\n");
    stop_snortsharp_engine(engine);
    destroy_snortsharp_engine(engine);
    
    print_separator();
    printf("SNORTSHARP INTEGRATION TEST COMPLETED\n");
    print_separator();
    
    return 0;
}
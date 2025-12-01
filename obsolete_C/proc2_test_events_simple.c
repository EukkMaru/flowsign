#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include "flow_rules.h"
#include "event_system.h"

static volatile bool running = true;
static event_system_t *event_sys = NULL;
static flow_rule_engine_t *rule_engine = NULL;

void signal_handler(int sig) {
    (void)sig;
    printf("\n[PROC2] Shutting down...\n");
    running = false;
}

void process_window_event(window_event_t *event, void *user_data) {
    (void)user_data;
    
    if (event->type == EVENT_SHUTDOWN) {
        printf("[PROC2] Received shutdown event from %s\n", event->source_process);
        running = false;
        return;
    }
    
    if (event->type != EVENT_WINDOW_UPDATE) {
        return;
    }
    
    printf("\n[PROC2] *** RECEIVED WINDOW EVENT ***\n");
    printf("[PROC2] Flow ID: %u, Source: %s\n", event->flow_id, event->source_process);
    printf("[PROC2] Timestamp: %ld.%06ld\n", event->timestamp.tv_sec, event->timestamp.tv_usec);
    
    // Extract features from event
    flow_features_t *features = &event->features;
    
    printf("[PROC2] Flow Features:\n");
    printf("  - Duration: %.2f ms\n", features->flow_duration / 1000.0);
    printf("  - Total packets: %d, Total bytes: %ld\n", 
           features->total_fwd_packets + features->total_bwd_packets, 
           features->total_fwd_bytes + features->total_bwd_bytes);
    printf("  - Forward: packets=%d, bytes=%ld, avg_len=%.1f\n",
           features->total_fwd_packets, features->total_fwd_bytes, 
           features->fwd_packet_length_mean);
    printf("  - Backward: packets=%d, bytes=%ld, avg_len=%.1f\n",
           features->total_bwd_packets, features->total_bwd_bytes, 
           features->bwd_packet_length_mean);
    printf("  - IAT mean: %.1f us, IAT std: %.1f us\n",
           features->flow_iat_mean, features->flow_iat_std);
    printf("  - TCP flags: SYN=%d, ACK=%d, FIN=%d, PSH=%d\n",
           features->syn_flag_count, features->ack_flag_count,
           features->fin_flag_count, features->psh_flag_count);
    
    // Simple rule checking
    printf("[PROC2] Running rule analysis...\n");
    
    int alerts = 0;
    
    // Rule 1: Port scan detection (fast IAT + multiple SYN flags)
    if (features->flow_iat_mean < 1000 && features->syn_flag_count > 3) {
        printf("[PROC2] *** ALERT: SID 1001 - Port Scan Detected ***\n");
        alerts++;
    }
    
    // Rule 2: Large file transfer detection
    if (features->fwd_packet_length_mean > 1200 && features->flow_bytes_per_sec > 1000000) {
        printf("[PROC2] *** ALERT: SID 1002 - Large File Transfer ***\n");
        alerts++;
    }
    
    // Rule 3: DoS attack detection (many packets, low bytes per packet)
    if (features->total_fwd_packets > 10 && features->fwd_packet_length_mean < 100) {
        printf("[PROC2] *** ALERT: SID 1003 - Potential DoS Attack ***\n");
        alerts++;
    }
    
    // Rule 4: Suspicious flow timing
    if (features->flow_iat_std > 5000 || features->flow_iat_min < 100) {
        printf("[PROC2] *** ALERT: SID 1004 - Suspicious Flow Timing ***\n");
        alerts++;
    }
    
    // Rule 5: Asymmetric flow (potential data exfiltration)
    if (features->total_bwd_bytes > 0 && 
        (features->total_fwd_bytes / features->total_bwd_bytes) > 10) {
        printf("[PROC2] *** ALERT: SID 1005 - Asymmetric Flow Pattern ***\n");
        alerts++;
    }
    
    if (alerts == 0) {
        printf("[PROC2] No rule matches - traffic appears normal\n");
    } else {
        printf("[PROC2] Total alerts: %d\n", alerts);
    }
    
    printf("[PROC2] Event processing complete\n");
}

int main() {
    printf("[PROC2] Rule Engine Process - Event Listener Demo\n");
    printf("===============================================\n");
    
    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create rule engine (even though we're doing simple checking)
    rule_engine = create_flow_rule_engine(100);
    if (!rule_engine) {
        fprintf(stderr, "[PROC2] Failed to create rule engine\n");
        return 1;
    }
    
    printf("[PROC2] Created rule engine with simple built-in rules:\n");
    printf("  - SID 1001: Port Scan Detected\n");
    printf("  - SID 1002: Large File Transfer\n");
    printf("  - SID 1003: Potential DoS Attack\n");
    printf("  - SID 1004: Suspicious Flow Timing\n");
    printf("  - SID 1005: Asymmetric Flow Pattern\n");
    
    // Create event system (server)
    event_sys = create_event_system("/tmp/snortsharp_events", true);
    if (!event_sys) {
        fprintf(stderr, "[PROC2] Failed to create event system\n");
        destroy_flow_rule_engine(rule_engine);
        return 1;
    }
    
    // Start event server
    printf("[PROC2] Starting event server...\n");
    if (start_event_server(event_sys, process_window_event, NULL) != 0) {
        fprintf(stderr, "[PROC2] Failed to start event server\n");
        destroy_event_system(event_sys);
        destroy_flow_rule_engine(rule_engine);
        return 1;
    }
    
    printf("[PROC2] Event server started, waiting for window events from proc1...\n");
    printf("[PROC2] Press Ctrl+C to stop\n\n");
    
    // Main event loop - just wait for events
    while (running) {
        usleep(100000); // 100ms
    }
    
    printf("\n[PROC2] Shutting down...\n");
    
    // Cleanup
    stop_event_server(event_sys);
    destroy_event_system(event_sys);
    destroy_flow_rule_engine(rule_engine);
    
    printf("[PROC2] Process 2 (Rule Engine) finished\n");
    return 0;
}
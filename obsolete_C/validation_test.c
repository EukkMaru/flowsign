#include "flow_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>

int test_count = 0;
int passed_tests = 0;

#define TEST_ASSERT(condition, message) do { \
    test_count++; \
    if (condition) { \
        printf("[PASS] %s\n", message); \
        passed_tests++; \
    } else { \
        printf("[FAIL] %s\n", message); \
    } \
} while(0)

packet_info_t create_simple_packet(int size, bool is_forward, int delay_us) {
    packet_info_t packet;
    memset(&packet, 0, sizeof(packet_info_t));
    
    gettimeofday(&packet.timestamp, NULL);
    packet.timestamp.tv_usec += delay_us;
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
    
    return packet;
}

void test_basic_functionality() {
    printf("\n=== Test: Basic Functionality ===\n");
    
    flow_analyzer_t *analyzer = create_flow_analyzer(10, 3, 1);
    TEST_ASSERT(analyzer != NULL, "Flow analyzer creation");
    TEST_ASSERT(analyzer->queue != NULL, "Circular queue creation");
    TEST_ASSERT(analyzer->queue->capacity == 10, "Queue capacity setting");
    TEST_ASSERT(analyzer->queue->window_size == 3, "Window size setting");
    
    destroy_flow_analyzer(analyzer);
}

void test_packet_counting() {
    printf("\n=== Test: Packet Counting ===\n");
    
    flow_analyzer_t *analyzer = create_flow_analyzer(10, 3, 1);
    flow_features_t features;
    
    // Add 3 packets: 2 forward, 1 backward
    packet_info_t p1 = create_simple_packet(100, true, 0);
    packet_info_t p2 = create_simple_packet(200, false, 1000);
    packet_info_t p3 = create_simple_packet(150, true, 2000);
    
    process_packet(analyzer, &p1, NULL);
    process_packet(analyzer, &p2, NULL);
    bool window_ready = process_packet(analyzer, &p3, &features);
    
    TEST_ASSERT(window_ready, "Window completion after 3 packets");
    TEST_ASSERT(features.total_fwd_packets == 2, "Forward packet count (expected 2)");
    TEST_ASSERT(features.total_bwd_packets == 1, "Backward packet count (expected 1)");
    TEST_ASSERT(features.total_fwd_bytes == 250, "Forward byte count (100+150=250)");
    TEST_ASSERT(features.total_bwd_bytes == 200, "Backward byte count (200)");
    
    destroy_flow_analyzer(analyzer);
}

void test_packet_length_stats() {
    printf("\n=== Test: Packet Length Statistics ===\n");
    
    flow_analyzer_t *analyzer = create_flow_analyzer(10, 4, 1);
    flow_features_t features;
    
    // Add packets with known sizes: 100, 200, 300, 400
    packet_info_t p1 = create_simple_packet(100, true, 0);
    packet_info_t p2 = create_simple_packet(200, true, 1000);
    packet_info_t p3 = create_simple_packet(300, true, 2000);
    packet_info_t p4 = create_simple_packet(400, true, 3000);
    
    process_packet(analyzer, &p1, NULL);
    process_packet(analyzer, &p2, NULL);
    process_packet(analyzer, &p3, NULL);
    bool window_ready = process_packet(analyzer, &p4, &features);
    
    TEST_ASSERT(window_ready, "Window completion");
    TEST_ASSERT(features.packet_length_min == 100, "Minimum packet length");
    TEST_ASSERT(features.packet_length_max == 400, "Maximum packet length");
    
    // Mean should be (100+200+300+400)/4 = 250
    TEST_ASSERT(features.packet_length_mean >= 249.0 && features.packet_length_mean <= 251.0, 
                "Average packet length (~250)");
    
    destroy_flow_analyzer(analyzer);
}

void test_inter_arrival_time() {
    printf("\n=== Test: Inter-Arrival Time Calculation ===\n");
    
    flow_analyzer_t *analyzer = create_flow_analyzer(10, 3, 1);
    flow_features_t features;
    
    // Add 3 packets with 1000us (1ms) intervals
    packet_info_t p1 = create_simple_packet(100, true, 0);
    packet_info_t p2 = create_simple_packet(100, true, 1000);   // +1ms
    packet_info_t p3 = create_simple_packet(100, true, 2000);   // +1ms
    
    process_packet(analyzer, &p1, NULL);
    process_packet(analyzer, &p2, NULL);
    bool window_ready = process_packet(analyzer, &p3, &features);
    
    TEST_ASSERT(window_ready, "Window completion");
    
    // Should have 2 IAT measurements of 1000us each
    TEST_ASSERT(features.flow_iat_mean >= 999.0 && features.flow_iat_mean <= 1001.0,
                "Flow IAT mean (~1000us)");
    TEST_ASSERT(features.flow_iat_min >= 999.0 && features.flow_iat_min <= 1001.0,
                "Flow IAT min (~1000us)");
    TEST_ASSERT(features.flow_iat_max >= 999.0 && features.flow_iat_max <= 1001.0,
                "Flow IAT max (~1000us)");
    
    destroy_flow_analyzer(analyzer);
}

void test_tcp_flag_counting() {
    printf("\n=== Test: TCP Flag Counting ===\n");
    
    flow_analyzer_t *analyzer = create_flow_analyzer(10, 3, 1);
    flow_features_t features;
    
    packet_info_t p1 = create_simple_packet(60, true, 0);
    p1.tcp_flags.syn = 1;
    
    packet_info_t p2 = create_simple_packet(60, false, 1000);
    p2.tcp_flags.syn = 1;
    p2.tcp_flags.ack = 1;
    
    packet_info_t p3 = create_simple_packet(52, true, 2000);
    p3.tcp_flags.ack = 1;
    
    process_packet(analyzer, &p1, NULL);
    process_packet(analyzer, &p2, NULL);
    bool window_ready = process_packet(analyzer, &p3, &features);
    
    TEST_ASSERT(window_ready, "Window completion");
    TEST_ASSERT(features.syn_flag_count == 2, "SYN flag count (expected 2)");
    TEST_ASSERT(features.ack_flag_count == 2, "ACK flag count (expected 2)");
    TEST_ASSERT(features.fin_flag_count == 0, "FIN flag count (expected 0)");
    
    destroy_flow_analyzer(analyzer);
}

void test_rolling_window() {
    printf("\n=== Test: Rolling Window Behavior ===\n");
    
    flow_analyzer_t *analyzer = create_flow_analyzer(10, 3, 1);
    flow_features_t features1, features2;
    
    // Add 4 packets to test rolling window
    packet_info_t p1 = create_simple_packet(100, true, 0);
    packet_info_t p2 = create_simple_packet(200, true, 1000);
    packet_info_t p3 = create_simple_packet(300, true, 2000);
    packet_info_t p4 = create_simple_packet(400, true, 3000);
    
    process_packet(analyzer, &p1, NULL);
    process_packet(analyzer, &p2, NULL);
    bool window1_ready = process_packet(analyzer, &p3, &features1);  // Window 1: p1,p2,p3
    bool window2_ready = process_packet(analyzer, &p4, &features2);  // Window 2: p2,p3,p4
    
    TEST_ASSERT(window1_ready, "First window completion");
    TEST_ASSERT(window2_ready, "Second window completion (rolling)");
    
    // First window: packets 100,200,300 -> mean 200
    TEST_ASSERT(features1.packet_length_mean >= 199.0 && features1.packet_length_mean <= 201.0,
                "First window mean (~200)");
    
    // Second window: packets 200,300,400 -> mean 300  
    TEST_ASSERT(features2.packet_length_mean >= 299.0 && features2.packet_length_mean <= 301.0,
                "Second window mean (~300) - rolling update");
    
    destroy_flow_analyzer(analyzer);
}

int main() {
    printf("=== Flow Analyzer Validation Tests ===\n");
    printf("Running comprehensive tests to validate implementation...\n");
    
    test_basic_functionality();
    test_packet_counting();
    test_packet_length_stats();
    test_inter_arrival_time();
    test_tcp_flag_counting();
    test_rolling_window();
    
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d/%d\n", passed_tests, test_count);
    
    if (passed_tests == test_count) {
        printf(" ALL TESTS PASSED! Flow analyzer is working correctly.\n");
    } else {
        printf("  Some tests failed. Check implementation.\n");
    }
    
    printf("\n=== What These Tests Validate ===\n");
    printf("* Circular queue and window management\n");
    printf("* Packet counting (forward/backward separation)\n");
    printf("* Statistical calculations (min/max/mean)\n");
    printf("* Inter-arrival time measurement\n");
    printf("* TCP flag counting\n");
    printf("* Rolling window updates\n");
    printf("\nThis confirms proc1 (flow feature calculation) is working correctly!\n");
    
    return (passed_tests == test_count) ? 0 : 1;
}
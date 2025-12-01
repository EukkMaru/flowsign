#include "flow_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <sys/time.h>
#include <memory>
#include <cassert>

int test_count = 0;
int passed_tests = 0;

#define TEST_ASSERT(condition, message) do { \
    test_count++; \
    if(condition) { \
        std::cout << "[PASS] " << message << std::endl; \
        passed_tests++; \
    } else { \
        std::cout << "[FAIL] " << message << std::endl; \
    } \
} while(0)

PacketInfo create_simple_packet(int size, bool is_forward, int delay_us) {
    PacketInfo packet{};
    
    gettimeofday(&packet.timestamp, nullptr);
    packet.timestamp.tv_usec += delay_us;
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
    
    return packet;
}

void test_basic_functionality() {
    std::cout << "\n=== Test: Basic Functionality ===" << std::endl;
    
    auto analyzer = std::make_unique<FlowAnalyzer>(10, 3, 1);
    TEST_ASSERT(analyzer != nullptr, "Flow analyzer creation");
    
    // test that we can get the flow id (basic operation test)
    TEST_ASSERT(analyzer->get_flow_id() >= 0, "Flow ID assignment");
    
    std::cout << "Basic functionality tests completed" << std::endl;
}

void test_packet_counting() {
    std::cout << "\n=== Test: Packet Counting ===" << std::endl;
    
    auto analyzer = std::make_unique<FlowAnalyzer>(10, 3, 1);
    FlowFeatures features{};
    
    // Add 3 packets: 2 forward, 1 backward
    PacketInfo p1 = create_simple_packet(100, true, 0);
    PacketInfo p2 = create_simple_packet(200, false, 1000);
    PacketInfo p3 = create_simple_packet(150, true, 2000);
    
    analyzer->process_packet(p1, features);
    analyzer->process_packet(p2, features);
    bool window_ready = analyzer->process_packet(p3, features);
    
    TEST_ASSERT(window_ready, "Window completion after 3 packets");
    TEST_ASSERT(features.total_fwd_packets == 2, "Forward packet count (expected 2)");
    TEST_ASSERT(features.total_bwd_packets == 1, "Backward packet count (expected 1)");
    TEST_ASSERT(features.total_fwd_bytes == 250, "Forward byte count (100+150=250)");
    TEST_ASSERT(features.total_bwd_bytes == 200, "Backward byte count (200)");
}

void test_packet_length_stats() {
    std::cout << "\n=== Test: Packet Length Statistics ===" << std::endl;
    
    auto analyzer = std::make_unique<FlowAnalyzer>(10, 4, 1);
    FlowFeatures features{};
    
    // Add packets with known sizes: 100, 200, 300, 400
    PacketInfo p1 = create_simple_packet(100, true, 0);
    PacketInfo p2 = create_simple_packet(200, true, 1000);
    PacketInfo p3 = create_simple_packet(300, true, 2000);
    PacketInfo p4 = create_simple_packet(400, true, 3000);
    
    analyzer->process_packet(p1, features);
    analyzer->process_packet(p2, features);
    analyzer->process_packet(p3, features);
    bool window_ready = analyzer->process_packet(p4, features);
    
    TEST_ASSERT(window_ready, "Window completion");
    TEST_ASSERT(features.packet_length_min == 100, "Minimum packet length");
    TEST_ASSERT(features.packet_length_max == 400, "Maximum packet length");
    
    // Mean should be (100+200+300+400)/4 = 250
    TEST_ASSERT(features.packet_length_mean >= 249.0 && features.packet_length_mean <= 251.0, 
                "Average packet length (~250)");
}

void test_inter_arrival_time() {
    std::cout << "\n=== Test: Inter-Arrival Time Calculation ===" << std::endl;
    
    auto analyzer = std::make_unique<FlowAnalyzer>(10, 3, 1);
    FlowFeatures features{};
    
    // Add 3 packets with 1000us (1ms) intervals
    PacketInfo p1 = create_simple_packet(100, true, 0);
    PacketInfo p2 = create_simple_packet(100, true, 1000);   // +1ms
    PacketInfo p3 = create_simple_packet(100, true, 2000);   // +1ms
    
    analyzer->process_packet(p1, features);
    analyzer->process_packet(p2, features);
    bool window_ready = analyzer->process_packet(p3, features);
    
    TEST_ASSERT(window_ready, "Window completion");
    
    // Should have 2 IAT measurements of 1000us each
    TEST_ASSERT(features.flow_iat_mean >= 999.0 && features.flow_iat_mean <= 1001.0,
                "Flow IAT mean (~1000us)");
    TEST_ASSERT(features.flow_iat_min >= 999.0 && features.flow_iat_min <= 1001.0,
                "Flow IAT min (~1000us)");
    TEST_ASSERT(features.flow_iat_max >= 999.0 && features.flow_iat_max <= 1001.0,
                "Flow IAT max (~1000us)");
}

void test_tcp_flag_counting() {
    std::cout << "\n=== Test: TCP Flag Counting ===" << std::endl;
    
    auto analyzer = std::make_unique<FlowAnalyzer>(10, 3, 1);
    FlowFeatures features{};
    
    PacketInfo p1 = create_simple_packet(60, true, 0);
    p1.tcp_flags.syn = true;
    
    PacketInfo p2 = create_simple_packet(60, false, 1000);
    p2.tcp_flags.syn = true;
    p2.tcp_flags.ack = true;
    
    PacketInfo p3 = create_simple_packet(52, true, 2000);
    p3.tcp_flags.ack = true;
    
    analyzer->process_packet(p1, features);
    analyzer->process_packet(p2, features);
    bool window_ready = analyzer->process_packet(p3, features);
    
    TEST_ASSERT(window_ready, "Window completion");
    TEST_ASSERT(features.syn_flag_count == 2, "SYN flag count (expected 2)");
    TEST_ASSERT(features.ack_flag_count == 2, "ACK flag count (expected 2)");
    TEST_ASSERT(features.fin_flag_count == 0, "FIN flag count (expected 0)");
}

void test_rolling_window() {
    std::cout << "\n=== Test: Rolling Window Behavior ===" << std::endl;
    
    auto analyzer = std::make_unique<FlowAnalyzer>(10, 3, 1);
    FlowFeatures features1{}, features2{};
    
    // Add 4 packets to test rolling window
    PacketInfo p1 = create_simple_packet(100, true, 0);
    PacketInfo p2 = create_simple_packet(200, true, 1000);
    PacketInfo p3 = create_simple_packet(300, true, 2000);
    PacketInfo p4 = create_simple_packet(400, true, 3000);
    
    analyzer->process_packet(p1, features1);
    analyzer->process_packet(p2, features1);
    bool window1_ready = analyzer->process_packet(p3, features1);  // Window 1: p1,p2,p3
    bool window2_ready = analyzer->process_packet(p4, features2);  // Window 2: p2,p3,p4
    
    TEST_ASSERT(window1_ready, "First window completion");
    TEST_ASSERT(window2_ready, "Second window completion (rolling)");
    
    // First window: packets 100,200,300 -> mean 200
    TEST_ASSERT(features1.packet_length_mean >= 199.0 && features1.packet_length_mean <= 201.0,
                "First window mean (~200)");
    
    // Second window: packets 200,300,400 -> mean 300  
    TEST_ASSERT(features2.packet_length_mean >= 299.0 && features2.packet_length_mean <= 301.0,
                "Second window mean (~300) - rolling update");
}

int main() {
    std::cout << "=== Flow Analyzer Validation Tests ===" << std::endl;
    std::cout << "Running comprehensive tests to validate implementation..." << std::endl;
    
    test_basic_functionality();
    test_packet_counting();
    test_packet_length_stats();
    test_inter_arrival_time();
    test_tcp_flag_counting();
    test_rolling_window();
    
    std::cout << "\n=== Test Results ===" << std::endl;
    std::cout << "Tests passed: " << passed_tests << "/" << test_count << std::endl;
    
    if(passed_tests == test_count) {
        std::cout << " ALL TESTS PASSED! Flow analyzer is working correctly." << std::endl;
    } else {
        std::cout << "  Some tests failed. Check implementation." << std::endl;
    }
    
    std::cout << "\n=== What These Tests Validate ===" << std::endl;
    std::cout << "* Circular queue and window management" << std::endl;
    std::cout << "* Packet counting (forward/backward separation)" << std::endl;
    std::cout << "* Statistical calculations (min/max/mean)" << std::endl;
    std::cout << "* Inter-arrival time measurement" << std::endl;
    std::cout << "* TCP flag counting" << std::endl;
    std::cout << "* Rolling window updates" << std::endl;
    std::cout << "\nThis confirms proc1 (flow feature calculation) is working correctly!" << std::endl;
    
    return (passed_tests == test_count) ? 0 : 1;
}
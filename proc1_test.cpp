#include <iostream>
#include <memory>
#include <csignal>
#include <unistd.h>
#include <sys/time.h>
#include <cstring>
#include <arpa/inet.h>
#include <atomic>
#include "flow_analyzer.hpp"
#include "event_system.hpp"

static std::atomic<bool> running{true};
static EventSystem* event_sys = nullptr;

void signal_handler(int sig) {
    (void)sig;
    std::cout << "\n[PROC1] Shutting down..." << std::endl;
    running = false;
    
    if(event_sys) {
        event_sys->send_shutdown_event();
    }
}

void setup_test_packet(PacketInfo& packet, int seq, const char* src_ip, const char* dst_ip,
                      uint16_t src_port, uint16_t dst_port, uint16_t pkt_len, 
                      bool syn, bool ack, bool fin, bool psh) {
    gettimeofday(&packet.timestamp, nullptr);
    
    // Add some microsecond offset based on sequence for realistic timing
    packet.timestamp.tv_usec += seq * 1000;
    if(packet.timestamp.tv_usec >= 1000000) {
        packet.timestamp.tv_sec++;
        packet.timestamp.tv_usec -= 1000000;
    }
    
    packet.src_ip = inet_addr(src_ip);
    packet.dst_ip = inet_addr(dst_ip);
    packet.src_port = src_port;
    packet.dst_port = dst_port;
    packet.protocol = 6; // TCP
    packet.packet_length = pkt_len;
    packet.header_length = 54; // TCP + IP headers
    packet.payload_length = pkt_len - 54; // Subtract headers
    packet.is_forward = (seq % 2 == 0);
    
    // Set TCP flags
    packet.tcp_flags.syn = syn;
    packet.tcp_flags.ack = ack;
    packet.tcp_flags.fin = fin;
    packet.tcp_flags.psh = psh;
    packet.tcp_flags.rst = false;
    packet.tcp_flags.urg = false;
    packet.tcp_flags.cwr = false;
    packet.tcp_flags.ece = false;
    
    packet.window_size = 8192;
}

int main() {
    std::cout << "[PROC1] Flow Analyzer Process - Event Broadcasting Demo" << std::endl;
    std::cout << "===============================================" << std::endl;
    
    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create flow analyzer
    auto analyzer = std::make_unique<FlowAnalyzer>(50, 5, 1);
    
    // Create event system (client)
    auto event_system = std::make_unique<EventSystem>("/tmp/snortsharp_events", false);
    event_sys = event_system.get();
    
    // Connect to event server
    std::cout << "[PROC1] Connecting to event server..." << std::endl;
    if(event_system->connect_event_client() != 0) {
        std::cerr << "[PROC1] Failed to connect to event server" << std::endl;
        return 1;
    }
    
    // Give some time for connection to establish
    usleep(100000); // 100ms
    
    // Simulate flow processing
    std::cout << "[PROC1] Starting packet processing and event broadcasting..." << std::endl;
    std::cout << "[PROC1] Window size: 5 packets, Broadcasting on each window completion" << std::endl << std::endl;
    
    PacketInfo packet{};
    FlowFeatures features{};
    uint32_t flow_id = 12345;
    int packet_count = 0;
    
    while(running && packet_count < 20) {
        // Create different types of packets to simulate realistic traffic
        if(packet_count < 3) {
            // TCP handshake
            if(packet_count == 0) {
                setup_test_packet(packet, packet_count, "192.168.1.100", "10.0.0.50", 
                                12345, 80, 60, true, false, false, false); // SYN
            } else if(packet_count == 1) {
                setup_test_packet(packet, packet_count, "10.0.0.50", "192.168.1.100", 
                                80, 12345, 60, true, true, false, false); // SYN-ACK
            } else {
                setup_test_packet(packet, packet_count, "192.168.1.100", "10.0.0.50", 
                                12345, 80, 60, false, true, false, false); // ACK
            }
        } else if(packet_count < 15) {
            // Data exchange
            setup_test_packet(packet, packet_count, "192.168.1.100", "10.0.0.50",
                            12345, 80, 1200 + (packet_count * 50), false, true, false, true); // PSH+ACK
        } else {
            // Connection teardown
            setup_test_packet(packet, packet_count, "192.168.1.100", "10.0.0.50",
                            12345, 80, 60, false, false, true, false); // FIN
        }
        
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = packet.src_ip;
        dst_addr.s_addr = packet.dst_ip;
        
        uint8_t flags_byte = (packet.tcp_flags.syn ? 0x02 : 0) |
                            (packet.tcp_flags.ack ? 0x10 : 0) |
                            (packet.tcp_flags.fin ? 0x01 : 0) |
                            (packet.tcp_flags.psh ? 0x08 : 0);
        
        std::cout << "[PROC1] Processing packet " << (packet_count + 1) 
                  << ": " << inet_ntoa(src_addr) << ":" << packet.src_port 
                  << " -> " << inet_ntoa(dst_addr) << ":" << packet.dst_port 
                  << " (len=" << packet.packet_length 
                  << ", flags=0x" << std::hex << static_cast<int>(flags_byte) 
                  << std::dec << ")" << std::endl;
        
        // Process packet through flow analyzer
        bool window_ready = analyzer->process_packet(packet, features);
        
        if(window_ready) {
            std::cout << "[PROC1] *** WINDOW COMPLETED *** Broadcasting event to proc2" << std::endl;
            std::cout << "[PROC1] Features: duration=" << (features.flow_duration / 1000.0) 
                      << "ms, total_packets=" << (features.total_fwd_packets + features.total_bwd_packets) 
                      << ", total_bytes=" << (features.total_fwd_bytes + features.total_bwd_bytes) << std::endl;
            std::cout << "[PROC1] Forward: packets=" << features.total_fwd_packets 
                      << ", bytes=" << features.total_fwd_bytes 
                      << ", avg_len=" << features.fwd_packet_length_mean << std::endl;
            std::cout << "[PROC1] Backward: packets=" << features.total_bwd_packets 
                      << ", bytes=" << features.total_bwd_bytes 
                      << ", avg_len=" << features.bwd_packet_length_mean << std::endl;
            
            // Broadcast window event
            if(event_system->broadcast_window_event(flow_id, features, "proc1") != 0) {
                std::cerr << "[PROC1] Failed to broadcast window event" << std::endl;
            } else {
                std::cout << "[PROC1] Event broadcasted successfully!" << std::endl;
            }
            std::cout << std::endl;
        }
        
        packet_count++;
        
        // Simulate real-time packet arrival
        usleep(200000); // 200ms between packets
    }
    
    std::cout << "[PROC1] Finished processing " << packet_count << " packets" << std::endl;
    
    // Send shutdown event
    if(running) {
        std::cout << "[PROC1] Sending shutdown event..." << std::endl;
        event_system->send_shutdown_event();
        usleep(100000); // Give time for shutdown event to be sent
    }
    
    // Cleanup
    event_system->disconnect_event_client();
    
    std::cout << "[PROC1] Process 1 (Flow Analyzer) finished" << std::endl;
    return 0;
}
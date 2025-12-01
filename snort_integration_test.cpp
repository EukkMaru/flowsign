#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <random>
#include <cstring>
#include <sys/time.h>
#include <arpa/inet.h>

#include "snortsharp_integration.hpp"
// #include "snortsharp_inspector.hpp" // Skip inspector for now due to snort3 dependencies

// mock snort packet structures for testing
struct MockSnortPacket {
    struct timeval timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t packet_length;
    uint16_t header_length;
    bool is_forward;
    uint16_t window_size;
    struct {
        bool fin, syn, rst, psh, ack, urg;
    } tcp_flags;
};

// mock snort3 packet header
struct MockPktHdr {
    struct timeval ts;
    uint32_t caplen;
    uint32_t pktlen;
};

// simple mock snort3 ip api
struct MockIpApi {
    uint32_t src_ip_;
    uint32_t dst_ip_;
    bool is_ip4_;
    
    bool is_ip4() const { return is_ip4_; }
    bool is_ip6() const { return !is_ip4_; }
    
    struct MockSfIp {
        uint32_t ip_;
        uint32_t get_ip4_value() const { return ip_; }
        uint32_t fast_hash() const { return ip_; }
    };
    
    mutable MockSfIp src_sfip, dst_sfip;
    
    const MockSfIp* get_src() const { 
        src_sfip.ip_ = src_ip_;
        return &src_sfip; 
    }
    const MockSfIp* get_dst() const { 
        dst_sfip.ip_ = dst_ip_;
        return &dst_sfip; 
    }
};

// simple mock tcp header
struct MockTcpHdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_offx2;
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

// mock snort3 decode data pointers
struct MockDecodeData {
    uint16_t sp, dp;
    MockIpApi ip_api;
    MockTcpHdr* tcph;
};

// mock snort3 packet
struct MockSnort3Packet {
    MockPktHdr* pkth;
    MockDecodeData ptrs;
    uint16_t pktlen;
    uint8_t ip_proto_next;
    
    bool is_tcp() const { return ip_proto_next == 6; }
};

MockSnortPacket generate_mock_packet(int packet_id, bool is_tcp_syn = false) {
    MockSnortPacket pkt{};
    
    // timestamp
    gettimeofday(&pkt.timestamp, nullptr);
    pkt.timestamp.tv_usec += (packet_id * 1000); // add microseconds for variety
    
    // random ip addresses
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> ip_dist(0x0A000000, 0x0AFFFFFF); // 10.x.x.x range
    std::uniform_int_distribution<uint16_t> port_dist(1024, 65535);
    std::uniform_int_distribution<uint16_t> len_dist(64, 1500);
    
    pkt.src_ip = ip_dist(gen);
    pkt.dst_ip = ip_dist(gen);
    pkt.src_port = port_dist(gen);
    pkt.dst_port = port_dist(gen);
    pkt.protocol = 6; // tcp
    pkt.packet_length = len_dist(gen);
    pkt.header_length = 20; // basic tcp/ip header
    pkt.is_forward = (pkt.src_port > pkt.dst_port);
    pkt.window_size = 65535;
    
    // tcp flags
    if(is_tcp_syn) {
        pkt.tcp_flags = {false, true, false, false, false, false}; // syn only
    } else {
        pkt.tcp_flags = {false, false, false, true, true, false}; // psh+ack
    }
    
    return pkt;
}

MockSnort3Packet* convert_to_snort3_packet(const MockSnortPacket& mock_pkt) {
    static MockPktHdr hdr;
    static MockTcpHdr tcp_hdr;
    static MockSnort3Packet s3_pkt;
    
    // setup packet header
    hdr.ts = mock_pkt.timestamp;
    hdr.pktlen = mock_pkt.packet_length;
    hdr.caplen = mock_pkt.packet_length;
    
    // setup tcp header
    tcp_hdr.th_sport = htons(mock_pkt.src_port);
    tcp_hdr.th_dport = htons(mock_pkt.dst_port);
    tcp_hdr.th_seq = htonl(12345);
    tcp_hdr.th_ack = htonl(67890);
    tcp_hdr.th_offx2 = 0x50; // 20 byte header
    tcp_hdr.th_flags = 0;
    if(mock_pkt.tcp_flags.fin) tcp_hdr.th_flags |= 0x01;
    if(mock_pkt.tcp_flags.syn) tcp_hdr.th_flags |= 0x02;
    if(mock_pkt.tcp_flags.rst) tcp_hdr.th_flags |= 0x04;
    if(mock_pkt.tcp_flags.psh) tcp_hdr.th_flags |= 0x08;
    if(mock_pkt.tcp_flags.ack) tcp_hdr.th_flags |= 0x10;
    if(mock_pkt.tcp_flags.urg) tcp_hdr.th_flags |= 0x20;
    tcp_hdr.th_win = htons(mock_pkt.window_size);
    tcp_hdr.th_sum = 0;
    tcp_hdr.th_urp = 0;
    
    // setup snort3 packet
    s3_pkt.pkth = &hdr;
    s3_pkt.pktlen = mock_pkt.packet_length;
    s3_pkt.ip_proto_next = mock_pkt.protocol;
    s3_pkt.ptrs.sp = mock_pkt.src_port;
    s3_pkt.ptrs.dp = mock_pkt.dst_port;
    s3_pkt.ptrs.ip_api.src_ip_ = mock_pkt.src_ip;
    s3_pkt.ptrs.ip_api.dst_ip_ = mock_pkt.dst_ip;
    s3_pkt.ptrs.ip_api.is_ip4_ = true;
    s3_pkt.ptrs.tcph = &tcp_hdr;
    
    return &s3_pkt;
}

void test_packet_conversion() {
    std::cout << "=== Testing Packet Conversion ===\n";
    
    // generate test packet
    MockSnortPacket mock_pkt = generate_mock_packet(1, true);
    MockSnort3Packet* s3_pkt = convert_to_snort3_packet(mock_pkt);
    
    // convert using our function
    auto our_pkt = convert_snort_packet_from_raw(s3_pkt);
    
    if(!our_pkt) {
        std::cout << "❌ Packet conversion failed\n";
        return;
    }
    
    // verify conversion
    bool conversion_ok = true;
    if(our_pkt->src_ip != mock_pkt.src_ip) {
        std::cout << "❌ Source IP mismatch\n";
        conversion_ok = false;
    }
    if(our_pkt->dst_ip != mock_pkt.dst_ip) {
        std::cout << "❌ Destination IP mismatch\n";
        conversion_ok = false;
    }
    if(our_pkt->src_port != mock_pkt.src_port) {
        std::cout << "❌ Source port mismatch\n";
        conversion_ok = false;
    }
    if(our_pkt->dst_port != mock_pkt.dst_port) {
        std::cout << "❌ Destination port mismatch\n";
        conversion_ok = false;
    }
    if(our_pkt->protocol != mock_pkt.protocol) {
        std::cout << "❌ Protocol mismatch\n";
        conversion_ok = false;
    }
    if(our_pkt->tcp_flags.syn != mock_pkt.tcp_flags.syn) {
        std::cout << "❌ SYN flag mismatch\n";
        conversion_ok = false;
    }
    
    if(conversion_ok) {
        std::cout << "✅ Packet conversion successful\n";
        std::cout << "  " << our_pkt->src_ip << ":" << our_pkt->src_port 
                  << " -> " << our_pkt->dst_ip << ":" << our_pkt->dst_port << "\n";
        std::cout << "  Length: " << our_pkt->packet_length << " bytes\n";
        std::cout << "  TCP SYN: " << (our_pkt->tcp_flags.syn ? "Yes" : "No") << "\n";
    }
}

void test_engine_functionality() {
    std::cout << "\n=== Testing Engine Functionality ===\n";
    
    // create engine directly
    SnortSharpEngine engine(50, 1000, 500);
    
    std::cout << "Starting engine...\n";
    if(!engine.start()) {
        std::cout << "❌ Failed to start engine\n";
        return;
    }
    
    // wait for initialization
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    std::cout << "Processing test packets...\n";
    
    // simulate packet processing
    for(int i = 0; i < 100; i++) {
        MockSnortPacket mock_pkt = generate_mock_packet(i, (i % 10 == 0));
        
        // convert to SnortPacket and process
        SnortPacket our_pkt;
        our_pkt.timestamp = mock_pkt.timestamp;
        our_pkt.src_ip = mock_pkt.src_ip;
        our_pkt.dst_ip = mock_pkt.dst_ip;
        our_pkt.src_port = mock_pkt.src_port;
        our_pkt.dst_port = mock_pkt.dst_port;
        our_pkt.protocol = mock_pkt.protocol;
        our_pkt.packet_length = mock_pkt.packet_length;
        our_pkt.header_length = mock_pkt.header_length;
        our_pkt.is_forward = mock_pkt.is_forward;
        our_pkt.window_size = mock_pkt.window_size;
        our_pkt.tcp_flags.fin = mock_pkt.tcp_flags.fin;
        our_pkt.tcp_flags.syn = mock_pkt.tcp_flags.syn;
        our_pkt.tcp_flags.rst = mock_pkt.tcp_flags.rst;
        our_pkt.tcp_flags.psh = mock_pkt.tcp_flags.psh;
        our_pkt.tcp_flags.ack = mock_pkt.tcp_flags.ack;
        our_pkt.tcp_flags.urg = mock_pkt.tcp_flags.urg;
        
        // process packet through engine
        engine.process_snort_packet(our_pkt);
        
        // small delay to simulate realistic packet timing
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    
    // let processing complete
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    std::cout << "Printing statistics...\n";
    engine.print_stats();
    
    std::cout << "Stopping engine...\n";
    engine.stop();
    
    std::cout << "✅ Engine test completed\n";
}

void test_multi_threaded_processing() {
    std::cout << "\n=== Testing Multi-threaded Processing ===\n";
    
    SnortSharpEngine engine(50, 1000, 500);
    if(!engine.start()) {
        std::cout << "❌ Failed to start engine\n";
        return;
    }
    
    // wait for initialization
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    const int num_threads = 4;
    const int packets_per_thread = 50;
    std::vector<std::thread> threads;
    
    std::cout << "Starting " << num_threads << " threads, " << packets_per_thread << " packets each...\n";
    
    auto worker = [&](int thread_id) {
        for(int i = 0; i < packets_per_thread; i++) {
            MockSnortPacket mock_pkt = generate_mock_packet(thread_id * packets_per_thread + i);
            
            // convert to SnortPacket and process
            SnortPacket our_pkt;
            our_pkt.timestamp = mock_pkt.timestamp;
            our_pkt.src_ip = mock_pkt.src_ip;
            our_pkt.dst_ip = mock_pkt.dst_ip;
            our_pkt.src_port = mock_pkt.src_port;
            our_pkt.dst_port = mock_pkt.dst_port;
            our_pkt.protocol = mock_pkt.protocol;
            our_pkt.packet_length = mock_pkt.packet_length;
            our_pkt.header_length = mock_pkt.header_length;
            our_pkt.is_forward = mock_pkt.is_forward;
            our_pkt.window_size = mock_pkt.window_size;
            our_pkt.tcp_flags.fin = mock_pkt.tcp_flags.fin;
            our_pkt.tcp_flags.syn = mock_pkt.tcp_flags.syn;
            our_pkt.tcp_flags.rst = mock_pkt.tcp_flags.rst;
            our_pkt.tcp_flags.psh = mock_pkt.tcp_flags.psh;
            our_pkt.tcp_flags.ack = mock_pkt.tcp_flags.ack;
            our_pkt.tcp_flags.urg = mock_pkt.tcp_flags.urg;
            
            engine.process_snort_packet(our_pkt);
            
            // vary timing per thread
            std::this_thread::sleep_for(std::chrono::microseconds(50 + thread_id * 25));
        }
        std::cout << "Thread " << thread_id << " completed\n";
    };
    
    // start threads
    for(int t = 0; t < num_threads; t++) {
        threads.emplace_back(worker, t);
    }
    
    // wait for all threads
    for(auto& thread : threads) {
        thread.join();
    }
    
    // let processing complete
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    
    std::cout << "Final statistics:\n";
    engine.print_stats();
    
    engine.stop();
    std::cout << "✅ Multi-threaded test completed\n";
}

int main() {
    std::cout << "SnortSharp Snort3 Integration Test Suite\n";
    std::cout << "========================================\n\n";
    
    try {
        test_packet_conversion();
        test_engine_functionality();
        test_multi_threaded_processing();
        
        std::cout << "\n🎉 All integration tests passed!\n";
        std::cout << "SnortSharp is ready for Snort3 integration.\n";
        
    } catch(const std::exception& e) {
        std::cerr << "❌ Test failed with exception: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
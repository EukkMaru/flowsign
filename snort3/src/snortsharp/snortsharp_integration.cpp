#include "snortsharp_integration.hpp"
#include <iostream>
#include <chrono>
#include <cstring>
#include <sys/time.h>
#include <arpa/inet.h>

// Snort3 includes for packet conversion
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "framework/decode_data.h"
#include "protocols/ip.h"

// TCP flag constants from Snort3 are #defines, not namespace members
// TH_FIN, TH_SYN, etc. are already available as #defines from snort3/src/protocols/tcp.h

// constructor - without event system
SnortSharpEngine::SnortSharpEngine(int window_size, int queue_capacity, int alert_capacity) 
    : use_events_(false), running_(false), threads_created_(false) {
    
    // create process 1: flow analyzer
    flow_analyzer_ = std::make_unique<FlowAnalyzer>(queue_capacity * 2, window_size, 1);
    
    // create process 2: rule engine
    rule_engine_ = std::make_unique<FlowRuleEngine>(alert_capacity);
    
    // create communication queue
    feature_queue_ = std::make_unique<FeatureQueue<FlowFeatures>>(queue_capacity);
    
    // event system not used
    event_system_ = nullptr;
    
    std::cout << "[SnortSharp] Engine created (traditional queue mode)\n";
}

// constructor - with event system
SnortSharpEngine::SnortSharpEngine(int window_size, int queue_capacity, int alert_capacity, const std::string& event_pipe)
    : use_events_(true), running_(false), threads_created_(false) {
    
    // create process 1: flow analyzer
    flow_analyzer_ = std::make_unique<FlowAnalyzer>(queue_capacity * 2, window_size, 1);
    
    // create process 2: rule engine
    rule_engine_ = std::make_unique<FlowRuleEngine>(alert_capacity);
    
    // create communication queue (fallback)
    feature_queue_ = std::make_unique<FeatureQueue<FlowFeatures>>(queue_capacity);
    
    // create event system for inter-process communication
    event_system_ = std::make_unique<EventSystem>(event_pipe, false); // client mode for proc1
    
    std::cout << "[SnortSharp] Engine created with libuv event system: " << event_pipe << "\n";
}

SnortSharpEngine::~SnortSharpEngine() {
    if(threads_created_ && running_.load()) {
        stop();
    }
}

bool SnortSharpEngine::start() {
    if(threads_created_) return false;
    
    running_ = true;
    
    // if using events, connect to event system
    if(use_events_ && event_system_) {
        if(event_system_->connect_event_client() != 0) {
            std::cout << "[SnortSharp] Failed to connect to event system\n";
            running_ = false;
            return false;
        }
        std::cout << "[SnortSharp] Connected to event system\n";
    }
    
    try {
        // start process 1 thread (flow analysis)
        process1_thread_ = std::thread(&SnortSharpEngine::process1_thread_func, this);
        
        // start process 2 thread (rule evaluation)
        process2_thread_ = std::thread(&SnortSharpEngine::process2_thread_func, this);
        
        threads_created_ = true;
        
        std::cout << "[SnortSharp] Engine started with " << rule_engine_->get_ruleset()->get_rule_count() 
                 << " flow rules\n";
        
        return true;
    } catch(const std::exception& e) {
        std::cout << "[SnortSharp] Failed to start threads: " << e.what() << "\n";
        running_ = false;
        return false;
    }
}

void SnortSharpEngine::stop() {
    if(!threads_created_) return;
    
    std::cout << "[SnortSharp] Stopping engine...\n";
    
    running_ = false;
    
    // send shutdown event if using event system
    if(use_events_ && event_system_) {
        event_system_->send_shutdown_event();
        event_system_->disconnect_event_client();
    }
    
    // wake up process 2 thread if it's waiting on the queue
    // we do this by enqueueing a dummy feature set
    if(feature_queue_) {
        FlowFeatures dummy_features{};
        feature_queue_->enqueue(dummy_features);
    }
    
    // join threads
    if(process1_thread_.joinable()) {
        process1_thread_.join();
    }
    if(process2_thread_.joinable()) {
        process2_thread_.join();
    }
    
    threads_created_ = false;
    
    std::cout << "[SnortSharp] Engine stopped\n";
}

void SnortSharpEngine::process1_thread_func() {
    std::cout << "[Process 1] Flow analysis thread started\n";
    
    while(running_.load()) {
        // in a real implementation, this would receive packets from snort
        // for now, we'll just maintain the thread
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    std::cout << "[Process 1] Flow analysis thread stopped\n";
}

void SnortSharpEngine::process2_thread_func() {
    std::cout << "[Process 2] Rule evaluation thread started\n";
    
    while(running_.load()) {
        FlowFeatures features;
        
        // dequeue features from process 1 (blocking call)
        if(feature_queue_->dequeue(features)) {
            if(!running_.load()) break; // check if we should stop
            
            // process features through rule engine
            rule_engine_->process_flow_features(features);
            total_alerts_generated_ = rule_engine_->get_total_matches();
        }
    }
    
    std::cout << "[Process 2] Rule evaluation thread stopped\n";
}

PacketInfo SnortSharpEngine::convert_snort_packet(const SnortPacket& snort_packet) {
    PacketInfo pkt{};
    
    pkt.timestamp = snort_packet.timestamp;
    pkt.src_ip = snort_packet.src_ip;
    pkt.dst_ip = snort_packet.dst_ip;
    pkt.src_port = snort_packet.src_port;
    pkt.dst_port = snort_packet.dst_port;
    pkt.protocol = snort_packet.protocol;
    pkt.packet_length = snort_packet.packet_length;
    pkt.header_length = snort_packet.header_length;
    pkt.payload_length = snort_packet.packet_length - snort_packet.header_length;
    pkt.is_forward = snort_packet.is_forward;
    pkt.window_size = snort_packet.window_size;
    
    pkt.tcp_flags.fin = snort_packet.tcp_flags.fin;
    pkt.tcp_flags.syn = snort_packet.tcp_flags.syn;
    pkt.tcp_flags.rst = snort_packet.tcp_flags.rst;
    pkt.tcp_flags.psh = snort_packet.tcp_flags.psh;
    pkt.tcp_flags.ack = snort_packet.tcp_flags.ack;
    pkt.tcp_flags.urg = snort_packet.tcp_flags.urg;
    pkt.tcp_flags.cwr = false; // not in snort packet struct
    pkt.tcp_flags.ece = false; // not in snort packet struct
    
    return pkt;
}

bool SnortSharpEngine::process_snort_packet(const SnortPacket& snort_packet) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // convert snort packet to our format
    PacketInfo pkt = convert_snort_packet(snort_packet);
    
    // process through flow analyzer (process 1)
    FlowFeatures features;
    if(flow_analyzer_->process_packet(pkt, features)) {
        // features generated, send to process 2
        if(use_events_ && event_system_) {
            // broadcast event via libuv
            if(event_system_->broadcast_window_event(flow_analyzer_->get_flow_id(), 
                                                   features, "proc1") == 0) {
                total_features_generated_++;
            } else {
                stats_.features_dropped++;
            }
        } else {
            // use traditional queue
            if(feature_queue_->enqueue(features)) {
                total_features_generated_++;
            } else {
                stats_.features_dropped++;
            }
        }
    }
    
    total_packets_processed_++;
    
    // update timing statistics
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    double processing_time = duration.count();
    
    if(total_packets_processed_.load() == 1) {
        stats_.avg_processing_time_us = processing_time;
    } else {
        // exponential moving average
        double current_avg = stats_.avg_processing_time_us.load();
        stats_.avg_processing_time_us = (current_avg * 0.9) + (processing_time * 0.1);
    }
    
    return true;
}

bool SnortSharpEngine::get_next_alert(FlowAlert& alert) {
    return rule_engine_->get_next_alert(alert);
}

bool SnortSharpEngine::add_flow_rule(const std::string& rule_string) {
    return rule_engine_->get_ruleset()->add_rule_from_string(rule_string);
}

bool SnortSharpEngine::load_flow_rules(const std::string& rules_file) {
    return rule_engine_->get_ruleset()->load_rules_from_file(rules_file);
}

void SnortSharpEngine::print_stats() const {
    std::cout << "\n=== SnortSharp Engine Statistics ===\n";
    std::cout << "Packets Processed: " << total_packets_processed_.load() << "\n";
    std::cout << "Features Generated: " << total_features_generated_.load() << "\n";
    std::cout << "Alerts Generated: " << total_alerts_generated_.load() << "\n";
    std::cout << "Features Dropped: " << stats_.features_dropped.load() << "\n";
    std::cout << "Processing Errors: " << stats_.processing_errors.load() << "\n";
    std::cout << "Avg Processing Time: " << stats_.avg_processing_time_us.load() << " us\n";
    
    std::cout << "\nRule Engine Stats:\n";
    std::cout << "  Total Evaluations: " << rule_engine_->get_total_evaluations() << "\n";
    std::cout << "  Total Matches: " << rule_engine_->get_total_matches() << "\n";
    std::cout << "  Features Processed: " << rule_engine_->get_total_features_processed() << "\n";
    
    if(rule_engine_->get_total_evaluations() > 0) {
        double match_rate = (rule_engine_->get_total_matches() * 100.0) / rule_engine_->get_total_evaluations();
        std::cout << "  Match Rate: " << match_rate << "%\n";
    }
    
    std::cout << "\nFeature Queue Stats:\n";
    std::cout << "  Current Count: " << feature_queue_->size() << "\n";
    
    std::cout << "=====================================\n\n";
}

void SnortSharpEngine::reset_stats() {
    total_packets_processed_ = 0;
    total_features_generated_ = 0;
    total_alerts_generated_ = 0;
    stats_.features_dropped = 0;
    stats_.processing_errors = 0;
    stats_.avg_processing_time_us = 0.0;
}

// utility functions
std::unique_ptr<SnortPacket> convert_snort_packet_from_raw(const void* snort_internal_packet) {
    if(!snort_internal_packet) {
        return nullptr;
    }
    
    // Cast to Snort3 Packet structure
    const snort::Packet* snort_packet = static_cast<const snort::Packet*>(snort_internal_packet);
    
    // Create our packet with safe memory copying
    auto our_packet = std::make_unique<SnortPacket>();
    
    // Extract IP addresses - must handle IPv4 and IPv6
    if(snort_packet->ptrs.ip_api.is_ip4()) {
        // IPv4 addresses  
        const auto* src_ip = snort_packet->ptrs.ip_api.get_src();
        const auto* dst_ip = snort_packet->ptrs.ip_api.get_dst();
        if(src_ip && dst_ip) {
            // Convert from host byte order to network byte order (big-endian)
            our_packet->src_ip = htonl(src_ip->get_ip4_value()); // Copy value, not reference
            our_packet->dst_ip = htonl(dst_ip->get_ip4_value()); // Copy value, not reference
        }
    } else if(snort_packet->ptrs.ip_api.is_ip6()) {
        // IPv6 - for now, hash to 32-bit for compatibility
        // TODO: Extend SnortPacket to handle IPv6 properly
        const auto* src_ip = snort_packet->ptrs.ip_api.get_src();  
        const auto* dst_ip = snort_packet->ptrs.ip_api.get_dst();
        if(src_ip && dst_ip) {
            // For IPv6, use the first 32 bits (simple approach for now)
            const uint32_t* src_ptr = src_ip->get_ip6_ptr();
            const uint32_t* dst_ptr = dst_ip->get_ip6_ptr();
            our_packet->src_ip = src_ptr ? *src_ptr : 0;
            our_packet->dst_ip = dst_ptr ? *dst_ptr : 0;
        }
    }
    
    // Extract port information (copy values, not references)
    our_packet->src_port = snort_packet->ptrs.sp;  // uint16_t value copy
    our_packet->dst_port = snort_packet->ptrs.dp;  // uint16_t value copy
    
    // Extract protocol
    our_packet->protocol = static_cast<uint8_t>(snort_packet->ip_proto_next);
    
    // Extract packet lengths (copy values safely)
    our_packet->packet_length = static_cast<uint16_t>(snort_packet->pktlen);
    our_packet->header_length = 20; // Default IP header, could be refined
    
    // Note: SnortPacket doesn't have payload_length field
    // Payload length can be calculated as: packet_length - header_length
    
    // Extract timestamp (copy struct content, not pointer)
    if(snort_packet->pkth) {
        our_packet->timestamp.tv_sec = snort_packet->pkth->ts.tv_sec;
        our_packet->timestamp.tv_usec = snort_packet->pkth->ts.tv_usec;
    } else {
        // Fallback to current time if no timestamp available
        gettimeofday(&our_packet->timestamp, nullptr);
    }
    
    // Determine flow direction (simplified heuristic)
    // Higher port number typically indicates client->server (forward)
    our_packet->is_forward = (our_packet->src_port > our_packet->dst_port);
    
    // Extract TCP flags if this is a TCP packet
    std::memset(&our_packet->tcp_flags, 0, sizeof(our_packet->tcp_flags));
    if(snort_packet->is_tcp() && snort_packet->ptrs.tcph) {
        const auto* tcp_hdr = snort_packet->ptrs.tcph;
        uint8_t flags = tcp_hdr->th_flags; // Copy flags value
        
        // Map Snort TCP flags to our structure (safe bit extraction)
        our_packet->tcp_flags.fin = (flags & TH_FIN) != 0;
        our_packet->tcp_flags.syn = (flags & TH_SYN) != 0;
        our_packet->tcp_flags.rst = (flags & TH_RST) != 0;
        our_packet->tcp_flags.psh = (flags & TH_PUSH) != 0;
        our_packet->tcp_flags.ack = (flags & TH_ACK) != 0;
        our_packet->tcp_flags.urg = (flags & TH_URG) != 0;
        
        // Copy window size
        our_packet->window_size = ntohs(tcp_hdr->th_win); // Network to host byte order
        
        // Refine header length for TCP
        our_packet->header_length = ((tcp_hdr->th_offx2 & 0xf0) >> 2); // TCP header length
        if(our_packet->header_length < 20) our_packet->header_length = 20; // Minimum TCP header
    } else {
        our_packet->window_size = 0;
    }
    
    return our_packet; // Return owned copy, all data safely copied
}

void print_flow_alert(const FlowAlert& alert) {
    std::cout << "[FLOW ALERT] SID:" << alert.rule_id << " - " << alert.message << "\n";
    std::cout << "  Timestamp: " << alert.timestamp.tv_sec << "." << alert.timestamp.tv_usec << "\n";
    std::cout << "  Flow Stats: " 
              << (alert.features.total_fwd_packets + alert.features.total_bwd_packets) << " packets, "
              << (alert.features.total_fwd_bytes + alert.features.total_bwd_bytes) << " bytes, "
              << alert.features.flow_iat_mean << " IAT mean\n";
}
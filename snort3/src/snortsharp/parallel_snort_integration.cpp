#include "parallel_snort_integration.hpp"
#include <iostream>
#include <chrono>
#include <algorithm>
#include <cstring>

// Snort3 includes for packet access
#include "framework/inspector.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/ip.h"

// Enable verbose debugging (set to false for clean alert output)
static const bool ENABLE_VERBOSE_DEBUG = false;

ParallelSnortSharpEngine::ParallelSnortSharpEngine(int window_size, int queue_capacity, const std::string& rules_file)
    : window_size_(window_size)
    , queue_capacity_(queue_capacity) 
    , rules_file_(rules_file) {
    
    snort_to_flow_queue_ = std::make_unique<ParallelPacketQueue>(queue_capacity);
    flow_to_snort_queue_ = std::make_unique<ParallelPacketQueue>(queue_capacity / 2);
}

ParallelSnortSharpEngine::~ParallelSnortSharpEngine() {
    shutdown();
}

bool ParallelSnortSharpEngine::initialize() {
    if(initialized_.load()) {
        return true;
    }
    
    std::cout << "[Parallel Engine] Initializing with dual-thread architecture...\n";
    std::cout << "  Window Size: " << window_size_ << "\n";
    std::cout << "  Queue Capacity: " << queue_capacity_ << "\n";
    std::cout << "  Rules File: " << rules_file_ << "\n";
    
    // initialize flow analyzer with circular queue
    flow_analyzer_ = std::make_unique<FlowAnalyzer>(queue_capacity_, window_size_, 1);
    if(!flow_analyzer_) {
        std::cerr << "[Parallel Engine] Failed to create flow analyzer\n";
        return false;
    }
    
    // initialize rule engine
    rule_engine_ = std::make_unique<FlowRuleEngine>(500);
    if(!rule_engine_) {
        std::cerr << "[Parallel Engine] Failed to create rule engine\n";
        return false;
    }
    
    // load flow rules
    if(!rules_file_.empty()) {
        if(!rule_engine_->get_ruleset()->load_rules_from_file(rules_file_)) {
            std::cerr << "[Parallel Engine] Failed to load rules from: " << rules_file_ << "\n";
            return false;
        }
        std::cout << "[Parallel Engine] Loaded " << rule_engine_->get_ruleset()->get_rule_count() << " flow rules\n";
    }
    
    // start processing threads
    running_ = true;
    flow_processing_thread_ = std::thread(&ParallelSnortSharpEngine::flow_processing_thread_func, this);
    communication_thread_ = std::thread(&ParallelSnortSharpEngine::communication_thread_func, this);
    
    initialized_ = true;
    std::cout << "[Parallel Engine] Initialization complete - parallel processing ready\n";
    return true;
}

void ParallelSnortSharpEngine::shutdown() {
    if(!initialized_.load()) {
        return;
    }
    
    std::cout << "[Parallel Engine] Shutting down parallel processing...\n";
    running_ = false;
    
    // wait for threads to complete
    if(flow_processing_thread_.joinable()) {
        flow_processing_thread_.join();
        std::cout << "[Parallel Engine] Flow processing thread stopped\n";
    }
    
    if(communication_thread_.joinable()) {
        communication_thread_.join();
        std::cout << "[Parallel Engine] Communication thread stopped\n";
    }
    
    initialized_ = false;
    std::cout << "[Parallel Engine] Shutdown complete\n";
}

// NEW: Direct enqueue for already-copied packets (from bridge)
bool ParallelSnortSharpEngine::enqueue_copied_packet(std::shared_ptr<ParallelPacket> copied_packet) {
    if(!initialized_.load() || !running_.load()) {
        std::cerr << "[Parallel Engine] Not initialized or not running\n";
        return false;
    }

    if(!copied_packet) {
        std::cerr << "[Parallel Engine] Received null copied packet\n";
        return false;
    }

    if (ENABLE_VERBOSE_DEBUG) {
        std::cout << "[Parallel Engine] Received pre-copied packet from bridge\n";
    }

    // packet is already deep-copied by bridge, just enqueue it
    if(!snort_to_flow_queue_->enqueue(copied_packet)) {
        std::cerr << "[Parallel Engine] Failed to enqueue copied packet for flow processing\n";
        return false;
    }

    total_packets_processed_++;
    if (ENABLE_VERBOSE_DEBUG) {
        std::cout << "[Parallel Engine] Enqueued packet #" << total_packets_processed_.load() << "\n";
    }
    return true;
}

bool ParallelSnortSharpEngine::process_snort_packet_parallel(const void* snort_packet) {
    if(!initialized_.load() || !running_.load()) {
        return false;
    }
    
    // create deep copy of packet for thread safety
    auto parallel_packet = convert_snort_packet_deep_copy(snort_packet);
    if(!parallel_packet) {
        return false;
    }
    
    // simulate snort3 processing time and results
    // in real implementation, this would come from snort3's actual processing
    auto snort_start = std::chrono::high_resolution_clock::now();
    
    // mock snort3 processing - replace with actual snort3 results
    parallel_packet->snort_results.processed = true;
    parallel_packet->snort_results.priority = 2;
    parallel_packet->snort_results.classification = "attempted-dos";
    
    // add mock snort alerts based on packet characteristics
    if(parallel_packet->protocol == 6) { // TCP
        if(parallel_packet->tcp_flags.syn && !parallel_packet->tcp_flags.ack) {
            parallel_packet->snort_results.snort_alerts.push_back("SYN flood detected");
        }
        if(parallel_packet->payload_length > 1400) {
            parallel_packet->snort_results.snort_alerts.push_back("Large payload detected");
        }
    }
    
    auto snort_end = std::chrono::high_resolution_clock::now();
    auto snort_processing_time = std::chrono::duration<double, std::micro>(snort_end - snort_start).count();
    
    // update snort processing statistics
    snort_alerts_generated_ += parallel_packet->snort_results.snort_alerts.size();
    avg_snort_processing_us_ = snort_processing_time; // simplified averaging
    
    // enqueue packet for flow processing
    if(!snort_to_flow_queue_->enqueue(parallel_packet)) {
        std::cerr << "[Parallel Engine] Failed to enqueue packet for flow processing\n";
        return false;
    }
    
    total_packets_processed_++;
    return true;
}

void ParallelSnortSharpEngine::flow_processing_thread_func() {
    if (ENABLE_VERBOSE_DEBUG) {
        std::cout << "[Flow Thread] Starting flow processing thread...\n";
    }
    
    while(running_.load()) {
        // dequeue packet from snort processing
        auto packet = snort_to_flow_queue_->dequeue(std::chrono::milliseconds(100));
        if(!packet) {
            continue; // timeout, check running flag
        }
        
        // process through flow engine
        process_packet_through_flow_engine(packet);
        
        // enqueue for communication back to snort
        flow_to_snort_queue_->enqueue(packet);
    }
    
    if (ENABLE_VERBOSE_DEBUG) {
        std::cout << "[Flow Thread] Flow processing thread stopped\n";
    }
}

void ParallelSnortSharpEngine::communication_thread_func() {
    if (ENABLE_VERBOSE_DEBUG) {
        std::cout << "[Communication Thread] Starting communication thread...\n";
    }
    
    while(running_.load()) {
        // get processed packets with both snort and flow results
        auto packet = flow_to_snort_queue_->dequeue(std::chrono::milliseconds(100));
        if(!packet) {
            continue; // timeout, check running flag
        }
        
        // correlate alerts from both engines
        correlate_alerts(packet);
    }
    
    if (ENABLE_VERBOSE_DEBUG) {
        std::cout << "[Communication Thread] Communication thread stopped\n";
    }
}

std::shared_ptr<ParallelPacket> ParallelSnortSharpEngine::convert_snort_packet_deep_copy(const void* snort_packet) {
    if(!snort_packet) {
        return nullptr;
    }
    
    // cast to snort3 packet
    const snort::Packet* pkt = static_cast<const snort::Packet*>(snort_packet);
    
    // create our packet with deep copy
    auto parallel_pkt = std::make_shared<ParallelPacket>();
    
    // copy timestamp
    gettimeofday(&parallel_pkt->timestamp, nullptr);
    
    // extract and copy IP addresses safely
    if(pkt->ptrs.ip_api.is_ip4()) {
        const auto* src_ip = pkt->ptrs.ip_api.get_src();
        const auto* dst_ip = pkt->ptrs.ip_api.get_dst();
        if(src_ip && dst_ip) {
            // Convert from host byte order to network byte order (big-endian)
            parallel_pkt->src_ip = htonl(src_ip->get_ip4_value());
            parallel_pkt->dst_ip = htonl(dst_ip->get_ip4_value());
        }
    } else {
        // handle IPv6 or unknown - use default values
        parallel_pkt->src_ip = 0;
        parallel_pkt->dst_ip = 0;
    }
    
    // extract port information
    if(pkt->ptrs.tcph) {
        parallel_pkt->src_port = pkt->ptrs.tcph->src_port();
        parallel_pkt->dst_port = pkt->ptrs.tcph->dst_port();
        parallel_pkt->window_size = pkt->ptrs.tcph->win();
        
        // copy TCP flags with deep copy
        parallel_pkt->tcp_flags.fin = pkt->ptrs.tcph->is_fin();
        parallel_pkt->tcp_flags.syn = pkt->ptrs.tcph->is_syn();
        parallel_pkt->tcp_flags.rst = pkt->ptrs.tcph->is_rst();
        parallel_pkt->tcp_flags.psh = pkt->ptrs.tcph->is_psh();
        parallel_pkt->tcp_flags.ack = pkt->ptrs.tcph->is_ack();
        parallel_pkt->tcp_flags.urg = ((pkt->ptrs.tcph->th_flags & TH_URG) != 0);
        parallel_pkt->tcp_flags.cwr = ((pkt->ptrs.tcph->th_flags & TH_CWR) != 0);
        parallel_pkt->tcp_flags.ece = ((pkt->ptrs.tcph->th_flags & TH_ECE) != 0);
    } else {
        parallel_pkt->src_port = 0;
        parallel_pkt->dst_port = 0;
        parallel_pkt->window_size = 0;
    }
    
    // copy packet length information - simplified for compatibility
    parallel_pkt->packet_length = pkt->dsize + 40; // estimate header size
    parallel_pkt->header_length = 40; // standard IP + TCP header estimate
    parallel_pkt->payload_length = pkt->dsize;
    parallel_pkt->protocol = static_cast<uint8_t>(pkt->get_ip_proto_next());
    parallel_pkt->is_forward = true; // simplified for now
    
    // deep copy payload data for thread safety
    if(pkt->data && pkt->dsize > 0) {
        parallel_pkt->payload_data.resize(pkt->dsize);
        std::memcpy(parallel_pkt->payload_data.data(), pkt->data, pkt->dsize);
    }
    
    return parallel_pkt;
}

void ParallelSnortSharpEngine::process_packet_through_flow_engine(std::shared_ptr<ParallelPacket> packet) {
    auto flow_start = std::chrono::high_resolution_clock::now();
    
    // convert to our flow analyzer packet format
    PacketInfo flow_pkt{};
    flow_pkt.timestamp = packet->timestamp;
    flow_pkt.src_ip = packet->src_ip;
    flow_pkt.dst_ip = packet->dst_ip;
    flow_pkt.src_port = packet->src_port;
    flow_pkt.dst_port = packet->dst_port;
    flow_pkt.protocol = packet->protocol;
    flow_pkt.packet_length = packet->packet_length;
    flow_pkt.header_length = packet->header_length;
    flow_pkt.payload_length = packet->payload_length;
    flow_pkt.is_forward = packet->is_forward;
    flow_pkt.window_size = packet->window_size;
    
    // copy TCP flags individually
    flow_pkt.tcp_flags.fin = packet->tcp_flags.fin;
    flow_pkt.tcp_flags.syn = packet->tcp_flags.syn;
    flow_pkt.tcp_flags.rst = packet->tcp_flags.rst;
    flow_pkt.tcp_flags.psh = packet->tcp_flags.psh;
    flow_pkt.tcp_flags.ack = packet->tcp_flags.ack;
    flow_pkt.tcp_flags.urg = packet->tcp_flags.urg;
    flow_pkt.tcp_flags.cwr = packet->tcp_flags.cwr;
    flow_pkt.tcp_flags.ece = packet->tcp_flags.ece;
    
    // process through flow analyzer
    FlowFeatures features;
    bool flow_ready = flow_analyzer_->process_packet(flow_pkt, features);
    
    if(flow_ready) {
        // store flow features in packet
        packet->flow_results.features = features;
        packet->flow_results.processed = true;
        
        // evaluate flow rules
        rule_engine_->process_flow_features(features);
        
        // collect flow alerts
        FlowAlert alert;
        while(rule_engine_->get_next_alert(alert)) {
            packet->flow_results.flow_alerts.push_back(alert);
        }
        
        flow_alerts_generated_ += packet->flow_results.flow_alerts.size();
    }
    
    auto flow_end = std::chrono::high_resolution_clock::now();
    auto flow_processing_time = std::chrono::duration<double, std::micro>(flow_end - flow_start).count();
    avg_flow_processing_us_ = flow_processing_time; // simplified averaging
}

void ParallelSnortSharpEngine::correlate_alerts(std::shared_ptr<ParallelPacket> packet) {
    // correlate snort alerts with flow alerts
    size_t total_alerts = packet->snort_results.snort_alerts.size() + 
                         packet->flow_results.flow_alerts.size();
    
    if(total_alerts > 0) {
        combined_alerts_++;

        // print combined alert information
        if (ENABLE_VERBOSE_DEBUG) {
            std::cout << "[Alert Correlation] Packet alerts combined:\n";
        }

        // print snort alerts
        for(const auto& snort_alert : packet->snort_results.snort_alerts) {
            std::cout << "  [SNORT] " << snort_alert << "\n";
        }
        
        // print flow alerts with flow 5-tuple
        for(const auto& flow_alert : packet->flow_results.flow_alerts) {
            // Format IP addresses from alert features (not packet)
            uint32_t src = flow_alert.features.src_ip;
            uint32_t dst = flow_alert.features.dst_ip;
            char src_ip_str[16], dst_ip_str[16];
            snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
                    (src >> 24) & 0xFF, (src >> 16) & 0xFF,
                    (src >> 8) & 0xFF, src & 0xFF);
            snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
                    (dst >> 24) & 0xFF, (dst >> 16) & 0xFF,
                    (dst >> 8) & 0xFF, dst & 0xFF);

            // Protocol name
            const char* proto = "UNKNOWN";
            if(flow_alert.features.protocol == 6) proto = "TCP";
            else if(flow_alert.features.protocol == 17) proto = "UDP";
            else if(flow_alert.features.protocol == 1) proto = "ICMP";

            std::cout << "  [FLOW] SID:" << flow_alert.rule_id << " - " << flow_alert.message
                      << " Flow:" << src_ip_str << ":" << flow_alert.features.src_port
                      << "->" << dst_ip_str << ":" << flow_alert.features.dst_port
                      << " Proto:" << proto << "\n";
        }
        
        // enhanced correlation logic could go here
        // for now, we just combine the alerts
    }
}

bool ParallelSnortSharpEngine::get_next_combined_alert(FlowAlert& alert) {
    return rule_engine_->get_next_alert(alert);
}

std::vector<FlowAlert> ParallelSnortSharpEngine::get_all_pending_alerts() {
    std::vector<FlowAlert> alerts;
    FlowAlert alert;
    while(rule_engine_->get_next_alert(alert)) {
        alerts.push_back(alert);
    }
    return alerts;
}

bool ParallelSnortSharpEngine::load_flow_rules(const std::string& rules_file) {
    if(!rule_engine_) {
        return false;
    }
    return rule_engine_->get_ruleset()->load_rules_from_file(rules_file);
}

bool ParallelSnortSharpEngine::add_flow_rule(const std::string& rule_string) {
    if(!rule_engine_) {
        return false;
    }
    return rule_engine_->get_ruleset()->add_rule_from_string(rule_string);
}

void ParallelSnortSharpEngine::print_parallel_stats() const {
    std::cout << "\n======== PARALLEL ENGINE STATISTICS ========\n";
    std::cout << "Total Packets Processed: " << total_packets_processed_.load() << "\n";
    std::cout << "Snort Alerts Generated: " << snort_alerts_generated_.load() << "\n";
    std::cout << "Flow Alerts Generated: " << flow_alerts_generated_.load() << "\n";
    std::cout << "Combined Alerts: " << combined_alerts_.load() << "\n";
    std::cout << "Avg Snort Processing: " << avg_snort_processing_us_.load() << " us\n";
    std::cout << "Avg Flow Processing: " << avg_flow_processing_us_.load() << " us\n";
    
    std::cout << "\nQueue Statistics:\n";
    std::cout << "  Snort->Flow Queue: " << snort_to_flow_queue_->size() << " packets\n";
    std::cout << "  Flow->Snort Queue: " << flow_to_snort_queue_->size() << " packets\n";
    std::cout << "  Dropped Packets: " << snort_to_flow_queue_->get_dropped_count() << "\n";
    
    if(rule_engine_) {
        std::cout << "\nRule Engine Statistics:\n";
        std::cout << "  Total Evaluations: " << rule_engine_->get_total_evaluations() << "\n";
        std::cout << "  Total Matches: " << rule_engine_->get_total_matches() << "\n";
        std::cout << "  Features Processed: " << rule_engine_->get_total_features_processed() << "\n";
    }
    
    std::cout << "============================================\n\n";
}

void ParallelSnortSharpEngine::reset_stats() {
    total_packets_processed_ = 0;
    snort_alerts_generated_ = 0;
    flow_alerts_generated_ = 0;
    combined_alerts_ = 0;
    avg_snort_processing_us_ = 0.0;
    avg_flow_processing_us_ = 0.0;
    snort_to_flow_queue_->reset_dropped_count();
}

// ParallelSnortSharpInspector implementation
ParallelSnortSharpInspector::ParallelSnortSharpInspector() {}

ParallelSnortSharpInspector::~ParallelSnortSharpInspector() {
    if(parallel_engine_) {
        parallel_engine_->shutdown();
    }
}

bool ParallelSnortSharpInspector::configure(snort::SnortConfig* /* config */) {
    if (ENABLE_VERBOSE_DEBUG) {
        std::cout << "[Parallel Inspector] Configuring with parallel architecture:\n";
        std::cout << "  Window Size: " << window_size_ << "\n";
        std::cout << "  Queue Capacity: " << queue_capacity_ << "\n";
        std::cout << "  Rules File: " << rules_file_ << "\n";
    }

    initialize_parallel_engine();
    return initialized_.load();
}

void ParallelSnortSharpInspector::show(const snort::SnortConfig* /* config */) const {
    std::cout << "\n=== PARALLEL SNORTSHARP INSPECTOR ===\n";
    std::cout << "Window Size: " << window_size_ << "\n";
    std::cout << "Queue Capacity: " << queue_capacity_ << "\n";
    std::cout << "Rules File: " << rules_file_ << "\n";
    std::cout << "Initialized: " << (initialized_.load() ? "Yes" : "No") << "\n";
    std::cout << "Packets Received: " << packets_received_.load() << "\n";
    std::cout << "Packets Processed: " << packets_processed_.load() << "\n";
    std::cout << "Processing Errors: " << processing_errors_.load() << "\n";
    
    if(parallel_engine_ && initialized_.load()) {
        parallel_engine_->print_parallel_stats();
    }
    std::cout << "=====================================\n\n";
}

void ParallelSnortSharpInspector::eval(snort::Packet* packet) {
    packets_received_++;
    
    if(!initialized_.load() || !parallel_engine_) {
        processing_errors_++;
        return;
    }
    
    // process through parallel engine
    bool success = parallel_engine_->process_snort_packet_parallel(packet);
    if(success) {
        packets_processed_++;
    } else {
        processing_errors_++;
    }
    
    // process any new alerts
    process_alerts();
}

void ParallelSnortSharpInspector::initialize_parallel_engine() {
    parallel_engine_ = std::make_unique<ParallelSnortSharpEngine>(
        window_size_, queue_capacity_, rules_file_);
    
    if(parallel_engine_->initialize()) {
        initialized_ = true;
        if (ENABLE_VERBOSE_DEBUG) {
            std::cout << "[Parallel Inspector] Parallel engine initialized successfully\n";
        }
    } else {
        std::cerr << "[Parallel Inspector] Failed to initialize parallel engine\n";
        initialized_ = false;
    }
}

void ParallelSnortSharpInspector::process_alerts() {
    if(!parallel_engine_) return;
    
    // get all pending alerts for processing
    auto alerts = parallel_engine_->get_all_pending_alerts();
    for(const auto& alert : alerts) {
        // process alert - could trigger blocking, logging, etc.
        block_flow(alert);
    }
}

bool ParallelSnortSharpInspector::block_flow(const FlowAlert& alert) {
    if (ENABLE_VERBOSE_DEBUG) {
        std::cout << "[Parallel Inspector] COMBINED ENGINE ALERT:\n";
        std::cout << "  Rule SID: " << alert.rule_id << "\n";
        std::cout << "  Message: " << alert.message << "\n";
        std::cout << "  Action: PARALLEL_BLOCK (both engines detected threat)\n";
    }
    return true;
}

void ParallelSnortSharpInspector::print_parallel_stats() const {
    if(parallel_engine_ && initialized_.load()) {
        parallel_engine_->print_parallel_stats();
    }
}

// utility functions
std::shared_ptr<ParallelPacket> create_parallel_packet_from_snort3(const void* /* snort_packet */) {
    // this would be implemented similar to convert_snort_packet_deep_copy
    // but as a standalone utility function
    return nullptr; // placeholder
}

void print_parallel_alert(const FlowAlert& alert) {
    std::cout << "[PARALLEL ALERT] SID:" << alert.rule_id << " - " << alert.message << "\n";
}

bool is_packet_duplicate(const ParallelPacket& p1, const ParallelPacket& p2) {
    return p1.src_ip == p2.src_ip && 
           p1.dst_ip == p2.dst_ip &&
           p1.src_port == p2.src_port &&
           p1.dst_port == p2.dst_port &&
           p1.protocol == p2.protocol &&
           abs((long)(p1.timestamp.tv_sec - p2.timestamp.tv_sec)) < 1;
}
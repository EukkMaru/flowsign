#include "snort3_snortsharp_bridge.hpp"
#include "parallel_snort_integration.hpp"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/ip.h"
#include <memory>
#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>
#include <atomic>

// logging and statistics for debugging
static std::atomic<uint64_t> g_packets_received{0};
static std::atomic<uint64_t> g_packets_copied{0};
static std::atomic<uint64_t> g_copy_failures{0};
static std::atomic<uint64_t> g_total_bytes_copied{0};
static std::atomic<uint64_t> g_null_packets{0};

// global parallel engine instance
static std::unique_ptr<ParallelSnortSharpEngine> g_parallel_engine = nullptr;
bool SnortSharpBridge::initialized_ = false;

// CRITICAL: Deep copy packet data IMMEDIATELY in snort3's thread
// This happens BEFORE any thread handoff to avoid use-after-free
static std::shared_ptr<ParallelPacket> deep_copy_in_snort_thread(const snort::Packet* pkt) {
    auto start_ns = std::chrono::high_resolution_clock::now();

    if(!pkt) {
        g_null_packets++;
        std::cerr << "[Bridge CRITICAL] Received null packet pointer\n";
        return nullptr;
    }

    try {
        auto copied_pkt = std::make_shared<ParallelPacket>();

        // copy timestamp immediately
        gettimeofday(&copied_pkt->timestamp, nullptr);

        // log which thread is doing the copy
        std::thread::id thread_id = std::this_thread::get_id();
        std::cout << "[Bridge Copy Thread " << thread_id << "] Copying packet at "
                  << pkt << "\n";

        // extract IP addresses SAFELY (check existence first)
        if(pkt->ptrs.ip_api.is_ip4()) {
            const auto* src_ip = pkt->ptrs.ip_api.get_src();
            const auto* dst_ip = pkt->ptrs.ip_api.get_dst();

            if(src_ip && dst_ip) {
                // CRITICAL: Copy VALUE not pointer
                copied_pkt->src_ip = src_ip->get_ip4_value();
                copied_pkt->dst_ip = dst_ip->get_ip4_value();
                std::cout << "[Bridge Copy] IPs: " << std::hex << copied_pkt->src_ip
                          << " -> " << copied_pkt->dst_ip << std::dec << "\n";
            } else {
                copied_pkt->src_ip = 0;
                copied_pkt->dst_ip = 0;
                std::cout << "[Bridge Copy] Warning: Null IP pointers\n";
            }
        } else if(pkt->ptrs.ip_api.is_ip6()) {
            // IPv6: hash to 32-bit for compatibility
            copied_pkt->src_ip = 0xFFFFFFFF;
            copied_pkt->dst_ip = 0xFFFFFFFF;
            std::cout << "[Bridge Copy] IPv6 detected (hashed)\n";
        } else {
            copied_pkt->src_ip = 0;
            copied_pkt->dst_ip = 0;
            std::cout << "[Bridge Copy] No IP layer\n";
        }

        // extract TCP/UDP port information SAFELY
        if(pkt->ptrs.tcph) {
            copied_pkt->src_port = pkt->ptrs.tcph->src_port();
            copied_pkt->dst_port = pkt->ptrs.tcph->dst_port();
            copied_pkt->window_size = pkt->ptrs.tcph->win();

            // copy TCP flags individually (NOT struct copy)
            copied_pkt->tcp_flags.fin = pkt->ptrs.tcph->is_fin();
            copied_pkt->tcp_flags.syn = pkt->ptrs.tcph->is_syn();
            copied_pkt->tcp_flags.rst = pkt->ptrs.tcph->is_rst();
            copied_pkt->tcp_flags.psh = pkt->ptrs.tcph->is_psh();
            copied_pkt->tcp_flags.ack = pkt->ptrs.tcph->is_ack();
            copied_pkt->tcp_flags.urg = ((pkt->ptrs.tcph->th_flags & TH_URG) != 0);
            copied_pkt->tcp_flags.cwr = ((pkt->ptrs.tcph->th_flags & TH_CWR) != 0);
            copied_pkt->tcp_flags.ece = ((pkt->ptrs.tcph->th_flags & TH_ECE) != 0);

            std::cout << "[Bridge Copy] TCP ports: " << copied_pkt->src_port
                      << " -> " << copied_pkt->dst_port
                      << " flags: SYN=" << copied_pkt->tcp_flags.syn
                      << " ACK=" << copied_pkt->tcp_flags.ack << "\n";
        } else if(pkt->ptrs.udph) {
            copied_pkt->src_port = pkt->ptrs.udph->src_port();
            copied_pkt->dst_port = pkt->ptrs.udph->dst_port();
            copied_pkt->window_size = 0;
            std::cout << "[Bridge Copy] UDP ports: " << copied_pkt->src_port
                      << " -> " << copied_pkt->dst_port << "\n";
        } else {
            copied_pkt->src_port = 0;
            copied_pkt->dst_port = 0;
            copied_pkt->window_size = 0;
            std::cout << "[Bridge Copy] No transport layer\n";
        }

        // copy packet length information
        copied_pkt->packet_length = pkt->pktlen;
        copied_pkt->header_length = pkt->pktlen - pkt->dsize; // estimate
        copied_pkt->payload_length = pkt->dsize;
        copied_pkt->protocol = static_cast<uint8_t>(pkt->get_ip_proto_next());
        copied_pkt->is_forward = true; // simplified

        std::cout << "[Bridge Copy] Lengths: total=" << copied_pkt->packet_length
                  << " header=" << copied_pkt->header_length
                  << " payload=" << copied_pkt->payload_length << "\n";

        // CRITICAL: Deep copy payload data with memcpy
        if(pkt->data && pkt->dsize > 0) {
            copied_pkt->payload_data.resize(pkt->dsize);
            std::memcpy(copied_pkt->payload_data.data(), pkt->data, pkt->dsize);
            g_total_bytes_copied += pkt->dsize;
            std::cout << "[Bridge Copy] Payload copied: " << pkt->dsize << " bytes\n";
        } else {
            std::cout << "[Bridge Copy] No payload data\n";
        }

        // copy snort3 metadata
        copied_pkt->snort_results.processed = false; // will be set later

        auto end_ns = std::chrono::high_resolution_clock::now();
        auto copy_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end_ns - start_ns).count();

        g_packets_copied++;
        std::cout << "[Bridge Copy] SUCCESS in " << copy_time_us << " us\n";
        std::cout << "[Bridge Copy] Stats: copied=" << g_packets_copied.load()
                  << " failed=" << g_copy_failures.load()
                  << " bytes=" << g_total_bytes_copied.load() << "\n";

        return copied_pkt;

    } catch(const std::exception& e) {
        g_copy_failures++;
        std::cerr << "[Bridge Copy FAILED] Exception: " << e.what() << "\n";
        return nullptr;
    }
}

bool SnortSharpBridge::initialize() {
    if(initialized_) {
        return true;
    }

    try {
        std::cout << "[SnortSharp Bridge] Initializing parallel engine integration...\n";
        std::cout << "[SnortSharp Bridge] Logging enabled for debugging\n";

        // create parallel engine with reasonable defaults
        g_parallel_engine = std::make_unique<ParallelSnortSharpEngine>(
            50,     // window_size
            10000,  // queue_capacity
            "unsw_nb15_rules.txt"  // rules_file
        );

        if(!g_parallel_engine->initialize()) {
            std::cerr << "[SnortSharp Bridge] Failed to initialize parallel engine\n";
            g_parallel_engine.reset();
            return false;
        }

        initialized_ = true;
        std::cout << "[SnortSharp Bridge] Parallel engine initialized successfully\n";
        std::cout << "[SnortSharp Bridge] Ready to receive packets from Snort3\n";
        return true;

    } catch(const std::exception& e) {
        std::cerr << "[SnortSharp Bridge] Initialization failed: " << e.what() << "\n";
        g_parallel_engine.reset();
        return false;
    }
}

void SnortSharpBridge::shutdown() {
    std::cout << "[SnortSharp Bridge] Shutdown requested\n";
    std::cout << "[SnortSharp Bridge] Final stats:\n";
    std::cout << "  Packets received: " << g_packets_received.load() << "\n";
    std::cout << "  Packets copied: " << g_packets_copied.load() << "\n";
    std::cout << "  Copy failures: " << g_copy_failures.load() << "\n";
    std::cout << "  Total bytes copied: " << g_total_bytes_copied.load() << "\n";
    std::cout << "  Null packets: " << g_null_packets.load() << "\n";

    if(g_parallel_engine) {
        std::cout << "[SnortSharp Bridge] Shutting down parallel engine...\n";
        g_parallel_engine->shutdown();
        g_parallel_engine.reset();
    }
    initialized_ = false;
    std::cout << "[SnortSharp Bridge] Shutdown complete\n";
}

void SnortSharpBridge::process_packet_from_snort3(const snort::Packet* snort_packet) {
    g_packets_received++;

    if(!initialized_ || !g_parallel_engine) {
        std::cerr << "[Bridge] Not initialized, dropping packet\n";
        return;
    }

    if(!snort_packet) {
        g_null_packets++;
        std::cerr << "[Bridge] Received null packet\n";
        return;
    }

    std::cout << "[Bridge] Packet #" << g_packets_received.load()
              << " received from Snort3 thread\n";

    try {
        // CRITICAL: Deep copy IMMEDIATELY in this (snort3's) thread
        // This ensures data is copied BEFORE snort3 frees the packet
        auto copied_packet = deep_copy_in_snort_thread(snort_packet);

        if(!copied_packet) {
            g_copy_failures++;
            std::cerr << "[Bridge] Failed to copy packet #" << g_packets_received.load() << "\n";
            return;
        }

        std::cout << "[Bridge] Packet #" << g_packets_received.load()
                  << " deep-copied, now enqueuing to SnortSharp\n";

        // now pass the COPIED packet to snortsharp thread
        // the original snort::Packet can be freed safely after this point
        if(!g_parallel_engine->enqueue_copied_packet(copied_packet)) {
            std::cerr << "[Bridge] Failed to enqueue packet #" << g_packets_received.load() << "\n";
        } else {
            std::cout << "[Bridge] Packet #" << g_packets_received.load()
                      << " successfully handed off to SnortSharp\n";
        }

    } catch(const std::exception& e) {
        std::cerr << "[Bridge] Packet processing error: " << e.what() << "\n";
        g_copy_failures++;
    }
}

bool SnortSharpBridge::is_initialized() {
    return initialized_;
}

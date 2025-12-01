#include "snort3_snortsharp_bridge.hpp"
#include "parallel_snort_integration.hpp"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/ip.h"
#include <memory>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <atomic>

// Enable verbose debugging (set to false for clean alert output)
static const bool ENABLE_VERBOSE_DEBUG = false;

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

        // log which thread is doing the copy (debug only)
        if (ENABLE_VERBOSE_DEBUG) {
            std::thread::id thread_id = std::this_thread::get_id();
            std::cout << "[Bridge Copy Thread " << thread_id << "] Copying packet at "
                      << pkt << "\n";
        }

        // extract IP addresses SAFELY (check existence first)
        if(pkt->ptrs.ip_api.is_ip4()) {
            const auto* src_ip = pkt->ptrs.ip_api.get_src();
            const auto* dst_ip = pkt->ptrs.ip_api.get_dst();

            if(src_ip && dst_ip) {
                // CRITICAL: Copy VALUE not pointer + convert to network byte order
                copied_pkt->src_ip = htonl(src_ip->get_ip4_value());
                copied_pkt->dst_ip = htonl(dst_ip->get_ip4_value());
                if (ENABLE_VERBOSE_DEBUG && g_packets_copied < 5) {
                    std::cout << "[Bridge DEBUG] IPv4 extracted: "
                              << ((copied_pkt->src_ip >> 24) & 0xFF) << "."
                              << ((copied_pkt->src_ip >> 16) & 0xFF) << "."
                              << ((copied_pkt->src_ip >> 8) & 0xFF) << "."
                              << (copied_pkt->src_ip & 0xFF) << " -> "
                              << ((copied_pkt->dst_ip >> 24) & 0xFF) << "."
                              << ((copied_pkt->dst_ip >> 16) & 0xFF) << "."
                              << ((copied_pkt->dst_ip >> 8) & 0xFF) << "."
                              << (copied_pkt->dst_ip & 0xFF) << "\n";
                }
            } else {
                copied_pkt->src_ip = 0;
                copied_pkt->dst_ip = 0;
                if (ENABLE_VERBOSE_DEBUG && g_packets_copied < 5) {
                    std::cout << "[Bridge DEBUG] IPv4 detected but src_ip or dst_ip is NULL\n";
                }
            }
        } else if(pkt->ptrs.ip_api.is_ip6()) {
            // IPv6: hash to 32-bit for compatibility
            copied_pkt->src_ip = 0xFFFFFFFF;
            copied_pkt->dst_ip = 0xFFFFFFFF;
            if (ENABLE_VERBOSE_DEBUG && g_packets_copied < 5) {
                std::cout << "[Bridge DEBUG] IPv6 packet detected\n";
            }
        } else {
            copied_pkt->src_ip = 0;
            copied_pkt->dst_ip = 0;
            if (ENABLE_VERBOSE_DEBUG && g_packets_copied < 5) {
                std::cout << "[Bridge DEBUG] No IP detected (neither IPv4 nor IPv6)\n";
            }
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
        } else if(pkt->ptrs.udph) {
            copied_pkt->src_port = pkt->ptrs.udph->src_port();
            copied_pkt->dst_port = pkt->ptrs.udph->dst_port();
            copied_pkt->window_size = 0;
        } else {
            copied_pkt->src_port = 0;
            copied_pkt->dst_port = 0;
            copied_pkt->window_size = 0;
        }

        // copy packet length information
        copied_pkt->packet_length = pkt->pktlen;
        copied_pkt->header_length = pkt->pktlen - pkt->dsize; // estimate
        copied_pkt->payload_length = pkt->dsize;
        copied_pkt->protocol = static_cast<uint8_t>(pkt->get_ip_proto_next());
        copied_pkt->is_forward = true; // simplified

        // CRITICAL: Deep copy payload data with memcpy
        if(pkt->data && pkt->dsize > 0) {
            copied_pkt->payload_data.resize(pkt->dsize);
            std::memcpy(copied_pkt->payload_data.data(), pkt->data, pkt->dsize);
            g_total_bytes_copied += pkt->dsize;
        }

        // copy snort3 metadata
        copied_pkt->snort_results.processed = false; // will be set later

        g_packets_copied++;
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
        if (ENABLE_VERBOSE_DEBUG) {
            std::cout << "[FlowSign Bridge] Initializing parallel engine integration...\n";
        }

        // Read configuration from environment variables (fallback to defaults)
        const char* rules_file_env = std::getenv("FLOWSIGN_RULES_FILE");
        std::string rules_file = rules_file_env ? rules_file_env : "unsw_nb15_rules.txt";

        const char* window_size_env = std::getenv("FLOWSIGN_WINDOW_SIZE");
        int window_size = window_size_env ? std::atoi(window_size_env) : 50;

        const char* queue_capacity_env = std::getenv("FLOWSIGN_QUEUE_CAPACITY");
        int queue_capacity = queue_capacity_env ? std::atoi(queue_capacity_env) : 10000;

        if (ENABLE_VERBOSE_DEBUG) {
            std::cout << "[FlowSign Bridge] Configuration:\n";
            std::cout << "  Rules file: " << rules_file << "\n";
            std::cout << "  Window size: " << window_size << "\n";
            std::cout << "  Queue capacity: " << queue_capacity << "\n";
        }

        // create parallel engine with configuration
        g_parallel_engine = std::make_unique<ParallelSnortSharpEngine>(
            window_size,
            queue_capacity,
            rules_file
        );

        if(!g_parallel_engine->initialize()) {
            std::cerr << "[FlowSign Bridge] Failed to initialize parallel engine\n";
            g_parallel_engine.reset();
            return false;
        }

        initialized_ = true;
        if (ENABLE_VERBOSE_DEBUG) {
            std::cout << "[FlowSign Bridge] Parallel engine initialized successfully\n";
            std::cout << "[FlowSign Bridge] Ready to receive packets from Snort3\n";
        }
        return true;

    } catch(const std::exception& e) {
        std::cerr << "[FlowSign Bridge] Initialization failed: " << e.what() << "\n";
        g_parallel_engine.reset();
        return false;
    }
}

void SnortSharpBridge::shutdown() {
    // Always show final stats
    std::cout << "[FlowSign Bridge] Final stats:\n";
    std::cout << "  Packets received: " << g_packets_received.load() << "\n";
    std::cout << "  Packets copied: " << g_packets_copied.load() << "\n";
    std::cout << "  Copy failures: " << g_copy_failures.load() << "\n";
    std::cout << "  Total bytes copied: " << g_total_bytes_copied.load() << "\n";
    std::cout << "  Null packets: " << g_null_packets.load() << "\n";

    if(g_parallel_engine) {
        g_parallel_engine->shutdown();
        g_parallel_engine.reset();
    }
    initialized_ = false;
}

void SnortSharpBridge::process_packet_from_snort3(const snort::Packet* snort_packet) {
    g_packets_received++;

    if(!initialized_ || !g_parallel_engine) {
        std::cerr << "[Bridge] Not initialized, dropping packet\n";
        return;
    }

    if(!snort_packet) {
        g_null_packets++;
        if (ENABLE_VERBOSE_DEBUG) {
            std::cerr << "[Bridge] Received null packet\n";
        }
        return;
    }

    try {
        // CRITICAL: Deep copy IMMEDIATELY in this (snort3's) thread
        // This ensures data is copied BEFORE snort3 frees the packet
        auto copied_packet = deep_copy_in_snort_thread(snort_packet);

        if(!copied_packet) {
            g_copy_failures++;
            return;
        }

        // now pass the COPIED packet to FlowSign thread
        // the original snort::Packet can be freed safely after this point
        if(!g_parallel_engine->enqueue_copied_packet(copied_packet)) {
            if (ENABLE_VERBOSE_DEBUG) {
                std::cerr << "[Bridge] Failed to enqueue packet\n";
            }
        }

    } catch(const std::exception& e) {
        std::cerr << "[Bridge] Packet processing error: " << e.what() << "\n";
        g_copy_failures++;
    }
}

bool SnortSharpBridge::is_initialized() {
    return initialized_;
}

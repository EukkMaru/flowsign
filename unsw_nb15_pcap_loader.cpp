#include "unsw_nb15_pcap_loader.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/stat.h>
#include <cstring>

UNSWB15PcapLoader::UNSWB15PcapLoader(const std::string& dataset_path) 
    : dataset_base_path_(dataset_path) {
    
    // ensure path ends with /
    if(!dataset_base_path_.empty() && dataset_base_path_.back() != '/') {
        dataset_base_path_ += '/';
    }
    
    std::cout << "[UNSW-NB15] Initialized loader with dataset path: " << dataset_base_path_ << "\n";
}

bool UNSWB15PcapLoader::discover_pcap_files() {
    pcap_files_.clear();
    
    std::string pcap_dir = dataset_base_path_ + "UNSW-NB15 dataset/pcap files/pcaps 17-2-2015/";
    
    DIR* dir = opendir(pcap_dir.c_str());
    if(!dir) {
        std::cout << "Failed to open PCAP directory: " << pcap_dir << "\n";
        return false;
    }
    
    struct dirent* entry;
    size_t file_index = 0;
    
    while((entry = readdir(dir)) != nullptr) {
        std::string filename = entry->d_name;
        
        // check for .pcap extension
        if(filename.length() > 5 && filename.substr(filename.length() - 5) == ".pcap") {
            PcapFileInfo pcap_info;
            pcap_info.file_path = pcap_dir + filename;
            pcap_info.file_index = file_index++;
            pcap_info.file_size_bytes = get_file_size(pcap_info.file_path);
            
            pcap_files_.push_back(pcap_info);
        }
    }
    
    closedir(dir);
    
    // sort by filename for consistent processing order
    std::sort(pcap_files_.begin(), pcap_files_.end(),
              [](const PcapFileInfo& a, const PcapFileInfo& b) {
                  return a.file_path < b.file_path;
              });
    
    std::cout << "[UNSW-NB15] Discovered " << pcap_files_.size() << " PCAP files\n";
    return !pcap_files_.empty();
}

bool UNSWB15PcapLoader::load_ground_truth_csv(const std::string& csv_filename) {
    std::string csv_path = dataset_base_path_ + "UNSW-NB15 dataset/CSV Files/" + csv_filename;
    
    std::ifstream file(csv_path);
    if(!file.is_open()) {
        std::cout << "Failed to open CSV file: " << csv_path << "\n";
        return false;
    }
    
    ground_truth_records_.clear();
    
    std::string line;
    size_t line_count = 0;
    size_t parsed_count = 0;
    
    while(std::getline(file, line)) {
        line_count++;
        
        if(line.empty() || line[0] == '\xEF') continue; // skip BOM and empty lines
        
        UNSWGroundTruth record;
        if(parse_csv_record(line, record)) {
            ground_truth_records_.push_back(record);
            parsed_count++;
            
            if(record.is_attack) {
                stats_.attack_flows++;
            } else {
                stats_.normal_flows++;
            }
        }
        
        if(line_count % 10000 == 0) {
            std::cout << "Processed " << line_count << " CSV lines...\n";
        }
    }
    
    file.close();
    stats_.ground_truth_records = parsed_count;
    
    std::cout << "[UNSW-NB15] Loaded " << parsed_count << " ground truth records from " 
              << csv_filename << "\n";
    std::cout << "  Attack flows: " << stats_.attack_flows << "\n";
    std::cout << "  Normal flows: " << stats_.normal_flows << "\n";
    
    if(!ground_truth_records_.empty()) {
        build_correlation_index();
        return true;
    }
    
    return false;
}

bool UNSWB15PcapLoader::parse_csv_record(const std::string& csv_line, UNSWGroundTruth& record) {
    std::stringstream ss(csv_line);
    std::string field;
    std::vector<std::string> fields;
    
    // parse CSV fields (handle quoted fields)
    while(std::getline(ss, field, ',')) {
        if(!field.empty() && field.front() == '"' && field.back() == '"') {
            field = field.substr(1, field.length() - 2);
        }
        fields.push_back(field);
    }
    
    if(fields.size() < 44) {
        return false; // insufficient fields
    }
    
    try {
        // parse UNSW-NB15 format: srcip,sport,dstip,dsport,proto,state,dur,sbytes,dbytes,...
        record.src_ip = parse_ip_address(fields[0]);
        record.src_port = static_cast<uint16_t>(std::stoul(fields[1]));
        record.dst_ip = parse_ip_address(fields[2]);
        record.dst_port = static_cast<uint16_t>(std::stoul(fields[3]));
        record.protocol = parse_protocol_string(fields[4]);
        
        // timing and flow stats
        record.duration = std::stod(fields[6]);
        record.src_bytes = std::stoull(fields[7]);
        record.dst_bytes = std::stoull(fields[8]);
        record.src_packets = std::stoul(fields[16]); // spkts
        record.dst_packets = std::stoul(fields[17]); // dpkts
        
        // calculated features
        record.src_load = std::stod(fields[14]); // sload
        record.dst_load = std::stod(fields[15]); // dload
        
        if(fields.size() > 28) {
            record.start_time = std::stod(fields[28]); // stime
        }
        
        // labels (last two fields)
        if(fields.size() > 43) {
            record.attack_category = fields[fields.size()-2];
            std::string label = fields[fields.size()-1];
            record.is_attack = (label == "1" || label == "attack");
        }
        
        // create flow ID for correlation
        record.flow_id = std::to_string(record.src_ip) + ":" + std::to_string(record.src_port) + 
                        "-" + std::to_string(record.dst_ip) + ":" + std::to_string(record.dst_port) +
                        "/" + std::to_string(record.protocol);
        
        return true;
        
    } catch(const std::exception& e) {
        return false;
    }
}

uint32_t UNSWB15PcapLoader::parse_ip_address(const std::string& ip_str) {
    struct in_addr addr;
    if(inet_aton(ip_str.c_str(), &addr) != 0) {
        return addr.s_addr;
    }
    return 0;
}

uint8_t UNSWB15PcapLoader::parse_protocol_string(const std::string& proto_str) {
    if(proto_str == "tcp") return IPPROTO_TCP;
    if(proto_str == "udp") return IPPROTO_UDP;
    if(proto_str == "icmp") return IPPROTO_ICMP;
    return 0;
}

std::vector<SnortPacket> UNSWB15PcapLoader::process_pcap_file(const std::string& pcap_path, 
                                                             size_t max_packets) {
    std::vector<SnortPacket> packets;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(pcap_path.c_str(), errbuf);
    
    if(!pcap) {
        std::cout << "Failed to open PCAP file: " << pcap_path << " - " << errbuf << "\n";
        return packets;
    }
    
    std::cout << "Processing PCAP file: " << pcap_path << "\n";
    
    struct pcap_pkthdr* header;
    const u_char* packet_data;
    size_t packet_count = 0;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    while(pcap_next_ex(pcap, &header, &packet_data) >= 0) {
        if(max_packets > 0 && packet_count >= max_packets) {
            break;
        }
        
        SnortPacket snort_packet = convert_pcap_packet_to_snort(header, packet_data);
        if(snort_packet.packet_length > 0) { // valid packet
            packets.push_back(snort_packet);
            packet_count++;
            stats_.total_packets_processed++;
        }
        
        if(packet_count % 1000 == 0) {
            std::cout << "  Processed " << packet_count << " packets...\n";
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    pcap_close(pcap);
    
    std::cout << "  Completed: " << packet_count << " packets in " 
              << duration.count() << " ms\n";
    
    return packets;
}

SnortPacket UNSWB15PcapLoader::convert_pcap_packet_to_snort(const struct pcap_pkthdr* header,
                                                           const u_char* packet_data) {
    SnortPacket snort_packet;
    
    // copy timestamp
    snort_packet.timestamp = header->ts;
    snort_packet.packet_length = header->caplen;
    
    // parse ethernet header (14 bytes)
    if(header->caplen < 14) {
        return snort_packet; // too short
    }
    
    const u_char* ip_header = packet_data + 14; // skip ethernet
    size_t remaining_length = header->caplen - 14;
    
    if(remaining_length < 20) {
        return snort_packet; // too short for IP header
    }
    
    // parse IP header
    struct iphdr* ip = (struct iphdr*)ip_header;
    
    snort_packet.src_ip = ip->saddr;
    snort_packet.dst_ip = ip->daddr;
    snort_packet.protocol = ip->protocol;
    snort_packet.header_length = (ip->ihl * 4); // IP header length
    
    // determine flow direction (simple heuristic)
    snort_packet.is_forward = (ntohs(snort_packet.src_port) > ntohs(snort_packet.dst_port));
    
    // parse transport layer
    if(ip->protocol == IPPROTO_TCP && remaining_length >= static_cast<size_t>((ip->ihl * 4) + 20)) {
        struct tcphdr* tcp = (struct tcphdr*)(ip_header + (ip->ihl * 4));
        
        snort_packet.src_port = ntohs(tcp->source);
        snort_packet.dst_port = ntohs(tcp->dest);
        snort_packet.window_size = ntohs(tcp->window);
        
        // parse TCP flags
        snort_packet.tcp_flags.syn = tcp->syn;
        snort_packet.tcp_flags.ack = tcp->ack;
        snort_packet.tcp_flags.fin = tcp->fin;
        snort_packet.tcp_flags.rst = tcp->rst;
        snort_packet.tcp_flags.psh = tcp->psh;
        snort_packet.tcp_flags.urg = tcp->urg;
        
        snort_packet.header_length += (tcp->doff * 4);
        
    } else if(ip->protocol == IPPROTO_UDP && remaining_length >= static_cast<size_t>((ip->ihl * 4) + 8)) {
        struct udphdr* udp = (struct udphdr*)(ip_header + (ip->ihl * 4));
        
        snort_packet.src_port = ntohs(udp->source);
        snort_packet.dst_port = ntohs(udp->dest);
        snort_packet.header_length += 8; // UDP header
    }
    
    return snort_packet;
}

void UNSWB15PcapLoader::build_correlation_index() {
    flow_correlation_index_.clear();
    
    for(size_t i = 0; i < ground_truth_records_.size(); i++) {
        FlowCorrelationKey key = create_correlation_key(ground_truth_records_[i]);
        flow_correlation_index_[key].push_back(i);
    }
    
    std::cout << "[UNSW-NB15] Built correlation index with " 
              << flow_correlation_index_.size() << " unique flows\n";
}

FlowCorrelationKey UNSWB15PcapLoader::create_correlation_key(const UNSWGroundTruth& record) {
    return FlowCorrelationKey(record.src_ip, record.dst_ip, record.src_port, 
                             record.dst_port, record.protocol);
}

std::vector<UNSWGroundTruth> UNSWB15PcapLoader::find_matching_ground_truth(
    const FlowFeatures& /* features */, const FlowCorrelationKey& flow_key, double flow_start_time) {
    
    std::vector<UNSWGroundTruth> matches;
    
    // find flows with matching 5-tuple
    auto it = flow_correlation_index_.find(flow_key);
    if(it != flow_correlation_index_.end()) {
        for(size_t record_idx : it->second) {
            const auto& record = ground_truth_records_[record_idx];
            
            // check timestamp proximity
            double time_diff = std::abs(record.start_time - flow_start_time);
            if(time_diff <= 10.0) { // 10 second window
                matches.push_back(record);
            }
        }
    }
    
    // also check bidirectional matches
    FlowCorrelationKey reverse_key(flow_key.dst_ip, flow_key.src_ip, 
                                  flow_key.dst_port, flow_key.src_port, 
                                  flow_key.protocol);
    
    auto reverse_it = flow_correlation_index_.find(reverse_key);
    if(reverse_it != flow_correlation_index_.end()) {
        for(size_t record_idx : reverse_it->second) {
            const auto& record = ground_truth_records_[record_idx];
            double time_diff = std::abs(record.start_time - flow_start_time);
            if(time_diff <= 10.0) {
                matches.push_back(record);
            }
        }
    }
    
    return matches;
}

bool UNSWB15PcapLoader::run_pcap_demo(const std::string& pcap_filename, size_t max_packets) {
    if(pcap_files_.empty() && !discover_pcap_files()) {
        std::cout << "No PCAP files found for demo\n";
        return false;
    }
    
    std::string demo_file;
    if(pcap_filename.empty()) {
        // use first available PCAP file
        demo_file = pcap_files_[0].file_path;
    } else {
        demo_file = get_full_pcap_path(pcap_filename);
    }
    
    std::cout << "\n=== UNSW-NB15 PCAP Demo ===\n";
    std::cout << "Processing: " << demo_file << "\n";
    
    auto packets = process_pcap_file(demo_file, max_packets);
    
    if(packets.empty()) {
        std::cout << "No packets processed from PCAP file\n";
        return false;
    }
    
    std::cout << "\nDemo Results:\n";
    std::cout << "  Packets processed: " << packets.size() << "\n";
    
    // show first few packets
    std::cout << "\nFirst 3 packets:\n";
    for(size_t i = 0; i < std::min(size_t(3), packets.size()); i++) {
        const auto& pkt = packets[i];
        struct in_addr src_addr = {pkt.src_ip};
        struct in_addr dst_addr = {pkt.dst_ip};
        
        std::cout << "  Packet " << (i+1) << ": " 
                  << inet_ntoa(src_addr) << ":" << pkt.src_port << " -> "
                  << inet_ntoa(dst_addr) << ":" << pkt.dst_port << " ("
                  << protocol_number_to_string(pkt.protocol) << ", "
                  << pkt.packet_length << " bytes)\n";
    }
    
    stats_.print_summary();
    return true;
}

void UNSWB15PcapLoader::print_dataset_summary() const {
    std::cout << "\n=== UNSW-NB15 Dataset Summary ===\n";
    std::cout << "Dataset Path: " << dataset_base_path_ << "\n";
    std::cout << "PCAP Files: " << pcap_files_.size() << "\n";
    
    size_t total_pcap_size = 0;
    for(const auto& pcap : pcap_files_) {
        total_pcap_size += pcap.file_size_bytes;
    }
    std::cout << "Total PCAP Size: " << (total_pcap_size / (1024*1024)) << " MB\n";
    
    std::cout << "Ground Truth Records: " << ground_truth_records_.size() << "\n";
    std::cout << "  Normal flows: " << stats_.normal_flows << "\n";
    std::cout << "  Attack flows: " << stats_.attack_flows << "\n";
    
    if(!ground_truth_records_.empty()) {
        // count attack categories
        std::unordered_map<std::string, size_t> attack_counts;
        for(const auto& record : ground_truth_records_) {
            if(record.is_attack) {
                attack_counts[record.attack_category]++;
            }
        }
        
        std::cout << "Attack Categories:\n";
        for(const auto& pair : attack_counts) {
            std::cout << "  " << pair.first << ": " << pair.second << "\n";
        }
    }
    
    std::cout << "================================\n\n";
}

std::string UNSWB15PcapLoader::get_full_pcap_path(const std::string& filename) {
    return dataset_base_path_ + "UNSW-NB15 dataset/pcap files/pcaps 17-2-2015/" + filename;
}

bool UNSWB15PcapLoader::file_exists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

size_t UNSWB15PcapLoader::get_file_size(const std::string& path) {
    struct stat buffer;
    if(stat(path.c_str(), &buffer) == 0) {
        return buffer.st_size;
    }
    return 0;
}

void UNSWB15PcapLoader::reset_stats() {
    stats_ = UNSWProcessingStats{};
}

// utility functions
std::string attack_category_to_description(const std::string& category) {
    if(category == "Normal") return "Benign network traffic";
    if(category == "Fuzzers") return "Fuzzing attacks";
    if(category == "Analysis") return "Network analysis and probing";
    if(category == "Backdoors") return "Backdoor and trojan activity";
    if(category == "DoS") return "Denial of Service attacks";
    if(category == "Exploits") return "Exploitation attempts";
    if(category == "Generic") return "Generic malicious activity";
    if(category == "Reconnaissance") return "Network reconnaissance";
    if(category == "Shellcode") return "Shellcode execution";
    if(category == "Worms") return "Worm propagation";
    return "Unknown attack type";
}

std::string protocol_number_to_string(uint8_t protocol) {
    switch(protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: return "Other";
    }
}

bool is_valid_pcap_file(const std::string& file_path) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(file_path.c_str(), errbuf);
    if(pcap) {
        pcap_close(pcap);
        return true;
    }
    return false;
}
#include "dataset_loader.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <arpa/inet.h>

DatasetLoader::DatasetLoader(const MatchingTolerances& tolerances) 
    : tolerances_(tolerances) {
}

bool DatasetLoader::load_unsw_nb15_csv(const std::string& csv_path) {
    std::ifstream file(csv_path);
    if(!file.is_open()) {
        std::cout << "Failed to open dataset file: " << csv_path << "\n";
        return false;
    }
    
    std::string line;
    bool header_skipped = false;
    size_t line_count = 0;
    size_t parsed_count = 0;
    
    while(std::getline(file, line)) {
        line_count++;
        
        // skip header line
        if(!header_skipped) {
            header_skipped = true;
            continue;
        }
        
        if(line.empty()) continue;
        
        auto fields = parse_csv_line(line);
        if(fields.size() < 40) {  // UNSW-NB15 has ~45 columns
            continue;
        }
        
        try {
            DatasetRecord record;
            
            // parse network 5-tuple (columns vary by UNSW-NB15 version)
            record.src_ip = parse_ip_address(fields[0]);      // srcip
            record.src_port = parse_uint_safe(fields[1]);     // sport
            record.dst_ip = parse_ip_address(fields[2]);      // dstip  
            record.dst_port = parse_uint_safe(fields[3]);     // dsport
            record.protocol = parse_uint_safe(fields[4]);     // proto
            
            // timing and size
            record.timestamp = parse_double_safe(fields[8]);  // stime
            record.packet_size = parse_uint_safe(fields[12]); // spkts (approximate)
            
            // flow-level features for validation
            record.flow_duration = parse_double_safe(fields[9]);    // dur
            record.total_fwd_bytes = parse_uint_safe(fields[11]);   // sbytes
            record.total_bwd_bytes = parse_uint_safe(fields[13]);   // dbytes
            record.total_fwd_packets = parse_uint_safe(fields[12]); // spkts  
            record.total_bwd_packets = parse_uint_safe(fields[14]); // dpkts
            
            // calculated features
            if(record.flow_duration > 0) {
                record.flow_bytes_per_sec = (record.total_fwd_bytes + record.total_bwd_bytes) / record.flow_duration;
                record.flow_packets_per_sec = (record.total_fwd_packets + record.total_bwd_packets) / record.flow_duration;
            }
            
            // additional features (if available in this UNSW-NB15 version)
            if(fields.size() > 30) {
                record.flow_iat_mean = parse_double_safe(fields[20]);
                record.flow_iat_std = parse_double_safe(fields[21]);
                record.packet_length_mean = parse_double_safe(fields[25]);
            }
            
            // attack classification (usually last 2 columns)
            if(fields.size() > 42) {
                record.attack_category = fields[fields.size()-2]; // attack_cat
                std::string label = fields[fields.size()-1];      // label
                record.is_attack = (label == "1" || label == "attack" || label == "Attack");
            }
            
            records_.push_back(record);
            parsed_count++;
            
        } catch(const std::exception& e) {
            // skip malformed records
            continue;
        }
    }
    
    file.close();
    
    std::cout << "Dataset loaded: " << parsed_count << " records from " 
              << line_count << " lines (" << csv_path << ")\n";
    
    if(!records_.empty()) {
        build_flow_index();
        return true;
    }
    
    return false;
}

std::vector<std::string> DatasetLoader::parse_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::stringstream ss(line);
    std::string field;
    
    while(std::getline(ss, field, ',')) {
        // remove quotes if present
        if(!field.empty() && field.front() == '"' && field.back() == '"') {
            field = field.substr(1, field.length() - 2);
        }
        fields.push_back(field);
    }
    
    return fields;
}

uint32_t DatasetLoader::parse_ip_address(const std::string& ip_str) {
    struct in_addr addr;
    if(inet_aton(ip_str.c_str(), &addr) != 0) {
        return addr.s_addr;
    }
    return 0; // invalid IP
}

double DatasetLoader::parse_double_safe(const std::string& str) {
    try {
        if(str.empty() || str == "nan" || str == "inf" || str == "-inf") {
            return 0.0;
        }
        return std::stod(str);
    } catch(const std::exception&) {
        return 0.0;
    }
}

uint32_t DatasetLoader::parse_uint_safe(const std::string& str) {
    try {
        if(str.empty()) return 0;
        return static_cast<uint32_t>(std::stoul(str));
    } catch(const std::exception&) {
        return 0;
    }
}

void DatasetLoader::build_flow_index() {
    flow_index_.clear();
    
    for(size_t i = 0; i < records_.size(); i++) {
        FlowKey key = extract_flow_key(records_[i]).get_canonical();
        flow_index_[key].push_back(i);
    }
    
    std::cout << "Built flow index: " << flow_index_.size() << " unique flows\n";
}

FlowKey DatasetLoader::extract_flow_key(const DatasetRecord& record) {
    return FlowKey(record.src_ip, record.dst_ip, record.src_port, 
                   record.dst_port, record.protocol);
}

std::vector<SnortPacket> DatasetLoader::generate_packets_from_records(size_t max_packets) {
    std::vector<SnortPacket> packets;
    size_t limit = (max_packets > 0) ? std::min(max_packets, records_.size()) : records_.size();
    
    packets.reserve(limit);
    
    for(size_t i = 0; i < limit; i++) {
        packets.push_back(convert_record_to_packet(records_[i]));
    }
    
    std::cout << "Generated " << packets.size() << " packets from dataset records\n";
    return packets;
}

SnortPacket DatasetLoader::convert_record_to_packet(const DatasetRecord& record) {
    SnortPacket packet;
    
    packet.src_ip = record.src_ip;
    packet.dst_ip = record.dst_ip;
    packet.src_port = record.src_port;
    packet.dst_port = record.dst_port;
    packet.protocol = record.protocol;
    packet.packet_length = static_cast<uint16_t>(record.packet_size);
    packet.header_length = (record.protocol == IPPROTO_TCP) ? 40 : 20; // TCP vs UDP/other
    
    // convert timestamp
    double int_part, frac_part;
    frac_part = std::modf(record.timestamp, &int_part);
    packet.timestamp.tv_sec = static_cast<time_t>(int_part);
    packet.timestamp.tv_usec = static_cast<suseconds_t>(frac_part * 1000000);
    
    // determine flow direction (heuristic: higher port = forward)
    packet.is_forward = (record.src_port > record.dst_port);
    
    // parse TCP flags if available
    if(record.protocol == IPPROTO_TCP) {
        uint8_t flags = record.tcp_flags;
        packet.tcp_flags.fin = (flags & 0x01) != 0;
        packet.tcp_flags.syn = (flags & 0x02) != 0;
        packet.tcp_flags.rst = (flags & 0x04) != 0;
        packet.tcp_flags.psh = (flags & 0x08) != 0;
        packet.tcp_flags.ack = (flags & 0x10) != 0;
        packet.tcp_flags.urg = (flags & 0x20) != 0;
        packet.window_size = 65535; // default window
    }
    
    return packet;
}

std::vector<size_t> DatasetLoader::find_candidate_records(const FlowKey& flow_key, 
                                                         double timestamp,
                                                         double time_window) {
    std::vector<size_t> candidates;
    FlowKey canonical_key = flow_key.get_canonical();
    
    auto it = flow_index_.find(canonical_key);
    if(it == flow_index_.end()) {
        return candidates; // no matching flow
    }
    
    for(size_t record_idx : it->second) {
        const auto& record = records_[record_idx];
        double time_diff = std::abs(record.timestamp - timestamp);
        
        if(time_diff <= time_window) {
            candidates.push_back(record_idx);
        }
    }
    
    // sort by timestamp proximity
    std::sort(candidates.begin(), candidates.end(),
              [this, timestamp](size_t a, size_t b) {
                  double diff_a = std::abs(records_[a].timestamp - timestamp);
                  double diff_b = std::abs(records_[b].timestamp - timestamp);
                  return diff_a < diff_b;
              });
    
    return candidates;
}

FlowMatchResult DatasetLoader::match_flow_to_record(const FlowFeatures& features,
                                                   const FlowKey& flow_key,
                                                   double flow_start_time) {
    FlowMatchResult result;
    
    auto candidates = find_candidate_records(flow_key, flow_start_time, 
                                           tolerances_.timestamp_tolerance_sec);
    
    if(candidates.empty()) {
        result.mismatch_reason = "No matching flow key found in dataset";
        return result;
    }
    
    // find best matching candidate
    double best_similarity = 0.0;
    size_t best_candidate = candidates[0];
    
    for(size_t candidate_idx : candidates) {
        const auto& record = records_[candidate_idx];
        
        double similarity = calculate_feature_similarity(features, record);
        if(similarity > best_similarity) {
            best_similarity = similarity;
            best_candidate = candidate_idx;
        }
    }
    
    const auto& best_record = records_[best_candidate];
    
    result.timestamp_diff = std::abs(best_record.timestamp - flow_start_time);
    result.feature_similarity = best_similarity;
    
    if(result.feature_similarity >= tolerances_.feature_similarity_threshold &&
       result.timestamp_diff <= tolerances_.timestamp_tolerance_sec) {
        result.matched = true;
    } else {
        result.matched = false;
        if(result.feature_similarity < tolerances_.feature_similarity_threshold) {
            result.mismatch_reason = "Feature similarity too low: " + 
                                   std::to_string(result.feature_similarity);
        } else {
            result.mismatch_reason = "Timestamp difference too high: " + 
                                   std::to_string(result.timestamp_diff) + "s";
        }
    }
    
    return result;
}

double DatasetLoader::calculate_feature_similarity(const FlowFeatures& generated_features,
                                                  const DatasetRecord& dataset_record) {
    double similarity_score = 0.0;
    int comparable_features = 0;
    
    // compare packet counts
    if(dataset_record.total_fwd_packets > 0 || dataset_record.total_bwd_packets > 0) {
        uint32_t dataset_total = dataset_record.total_fwd_packets + dataset_record.total_bwd_packets;
        uint32_t generated_total = generated_features.total_fwd_packets + generated_features.total_bwd_packets;
        
        if(is_within_tolerance(dataset_total, generated_total, 0.2)) { // 20% tolerance
            similarity_score += 1.0;
        }
        comparable_features++;
    }
    
    // compare byte counts
    if(dataset_record.total_fwd_bytes > 0 || dataset_record.total_bwd_bytes > 0) {
        uint64_t dataset_bytes = dataset_record.total_fwd_bytes + dataset_record.total_bwd_bytes;
        uint64_t generated_bytes = generated_features.total_fwd_bytes + generated_features.total_bwd_bytes;
        
        if(is_within_tolerance(dataset_bytes, generated_bytes, tolerances_.byte_count_tolerance_percent)) {
            similarity_score += 1.0;
        }
        comparable_features++;
    }
    
    // compare flow duration
    if(dataset_record.flow_duration > 0.0 && generated_features.flow_duration > 0.0) {
        if(is_within_tolerance(dataset_record.flow_duration, generated_features.flow_duration, 0.3)) {
            similarity_score += 1.0;
        }
        comparable_features++;
    }
    
    // compare flow rates
    if(dataset_record.flow_bytes_per_sec > 0.0 && generated_features.flow_bytes_per_sec > 0.0) {
        if(is_within_tolerance(dataset_record.flow_bytes_per_sec, generated_features.flow_bytes_per_sec, 0.4)) {
            similarity_score += 1.0;
        }
        comparable_features++;
    }
    
    // compare IAT statistics
    if(dataset_record.flow_iat_mean > 0.0 && generated_features.flow_iat_mean > 0.0) {
        if(is_within_tolerance(dataset_record.flow_iat_mean, generated_features.flow_iat_mean, 0.5)) {
            similarity_score += 1.0;
        }
        comparable_features++;
    }
    
    return comparable_features > 0 ? similarity_score / comparable_features : 0.0;
}

bool DatasetLoader::is_within_tolerance(double value1, double value2, double tolerance_percent) {
    if(value1 == 0.0 && value2 == 0.0) return true;
    if(value1 == 0.0 || value2 == 0.0) return false;
    
    double diff = std::abs(value1 - value2);
    double avg = (value1 + value2) / 2.0;
    double relative_diff = diff / avg;
    
    return relative_diff <= tolerance_percent;
}

EvaluationMetrics DatasetLoader::evaluate_against_dataset(SnortSharpEngine& engine,
                                                         size_t max_records,
                                                         bool verbose) {
    EvaluationMetrics metrics;
    
    size_t limit = (max_records > 0) ? std::min(max_records, records_.size()) : records_.size();
    
    std::cout << "Starting evaluation against " << limit << " dataset records...\n";
    
    for(size_t i = 0; i < limit; i++) {
        const auto& record = records_[i];
        SnortPacket packet = convert_record_to_packet(record);
        
        // process packet through SnortSharp
        if(engine.process_snort_packet(packet)) {
            metrics.total_flows_processed++;
            
            // check if any alerts were generated
            FlowAlert alert;
            bool alert_generated = engine.get_next_alert(alert);
            
            // classify result
            if(record.is_attack && alert_generated) {
                metrics.true_positives++;
                if(verbose) {
                    std::cout << "TP: Attack detected correctly (SID:" << alert.rule_id << ")\n";
                }
            } else if(!record.is_attack && !alert_generated) {
                metrics.true_negatives++;
            } else if(!record.is_attack && alert_generated) {
                metrics.false_positives++;
                if(verbose) {
                    std::cout << "FP: False alarm on normal traffic (SID:" << alert.rule_id << ")\n";
                }
            } else if(record.is_attack && !alert_generated) {
                metrics.false_negatives++;
                if(verbose) {
                    std::cout << "FN: Missed attack (" << record.attack_category << ")\n";
                }
            }
            
            // attempt flow matching (for validation)
            // FlowKey flow_key = extract_flow_key(record);
            // note: we'd need access to generated flow features for full matching
            // this is a simplified evaluation focusing on alert classification
        }
        
        if((i + 1) % 1000 == 0) {
            std::cout << "Processed " << (i + 1) << " records...\n";
        }
    }
    
    metrics.matched_flows = metrics.total_flows_processed; // simplified for now
    
    return metrics;
}

void DatasetLoader::print_dataset_summary() const {
    if(records_.empty()) {
        std::cout << "Dataset is empty\n";
        return;
    }
    
    std::cout << "\n=== Dataset Summary ===\n";
    std::cout << "Total Records: " << records_.size() << "\n";
    std::cout << "Unique Flows: " << flow_index_.size() << "\n";
    
    // count attack types
    std::unordered_map<std::string, uint32_t> attack_counts;
    uint32_t normal_count = 0;
    
    for(const auto& record : records_) {
        if(record.is_attack) {
            attack_counts[record.attack_category]++;
        } else {
            normal_count++;
        }
    }
    
    std::cout << "Normal Traffic: " << normal_count << "\n";
    std::cout << "Attack Types:\n";
    for(const auto& pair : attack_counts) {
        std::cout << "  " << pair.first << ": " << pair.second << "\n";
    }
    
    std::cout << "======================\n\n";
}

void DatasetLoader::print_evaluation_report(const EvaluationMetrics& metrics) const {
    std::cout << "\n=== Evaluation Report ===\n";
    std::cout << "Flows Processed: " << metrics.total_flows_processed << "\n";
    std::cout << "Matched Flows: " << metrics.matched_flows << " (" 
              << (metrics.matching_rate() * 100.0) << "%)\n";
    std::cout << "Unmatched Flows: " << metrics.unmatched_flows << "\n\n";
    
    std::cout << "Classification Results:\n";
    std::cout << "  True Positives:  " << metrics.true_positives << "\n";
    std::cout << "  True Negatives:  " << metrics.true_negatives << "\n";
    std::cout << "  False Positives: " << metrics.false_positives << "\n";
    std::cout << "  False Negatives: " << metrics.false_negatives << "\n\n";
    
    std::cout << "Performance Metrics:\n";
    std::cout << "  Precision: " << (metrics.precision() * 100.0) << "%\n";
    std::cout << "  Recall:    " << (metrics.recall() * 100.0) << "%\n";
    std::cout << "  F1-Score:  " << (metrics.f1_score() * 100.0) << "%\n";
    std::cout << "  Accuracy:  " << (metrics.accuracy() * 100.0) << "%\n";
    std::cout << "=========================\n\n";
}

std::string attack_category_to_string(const std::string& category) {
    if(category.empty()) return "Normal";
    return category;
}

std::string evaluation_summary_to_string(const EvaluationMetrics& metrics) {
    return "P:" + std::to_string(metrics.precision() * 100.0).substr(0,5) + "% " +
           "R:" + std::to_string(metrics.recall() * 100.0).substr(0,5) + "% " +
           "F1:" + std::to_string(metrics.f1_score() * 100.0).substr(0,5) + "% " +
           "A:" + std::to_string(metrics.accuracy() * 100.0).substr(0,5) + "%";
}
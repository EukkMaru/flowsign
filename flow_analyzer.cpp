#include "flow_analyzer.hpp"
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <iostream>
#include <algorithm>
#include <limits>

CircularQueue::CircularQueue(int capacity, int window_size, int step_size)
    : packets_(capacity)
    , capacity_(capacity)
    , size_(0)
    , head_(0) 
    , tail_(0)
    , window_size_(window_size)
    , step_size_(step_size)
    , is_full_(false) {
}

bool CircularQueue::enqueue_packet(const PacketInfo& packet) {
    packets_[tail_] = packet;
    
    tail_ = (tail_ + 1) % capacity_;
    
    if(size_ < window_size_) {
        size_++;
    } else {
        // rolling window: remove oldest packet when we exceed window_size
        head_ = (head_ + 1) % capacity_;
        // size stays at window_size (we replaced the oldest packet)
        size_ = window_size_;
        is_full_ = true;
    }
    
    return true;
}

const PacketInfo& CircularQueue::operator[](int index) const {
    int idx = (head_ + index) % capacity_;
    return packets_[idx];
}

PacketInfo& CircularQueue::operator[](int index) {
    int idx = (head_ + index) % capacity_;
    return packets_[idx];
}

FlowAnalyzer::FlowAnalyzer(int window_capacity, int window_size, int step_size)
    : queue_(std::make_unique<CircularQueue>(window_capacity, window_size, step_size))
    , current_features_{}
    , flow_id_(0)
    , first_packet_processed_(false)
    , first_packet_{} {
}

double calculate_time_diff_microseconds(const struct timeval& start, const struct timeval& end) {
    return (end.tv_sec - start.tv_sec) * 1000000.0 + (end.tv_usec - start.tv_usec);
}

double calculate_mean(const std::vector<double>& values) {
    if(values.empty()) return 0.0;
    double sum = 0.0;
    for(const auto& val : values) {
        sum += val;
    }
    return sum / values.size();
}

double calculate_std_dev(const std::vector<double>& values, double mean) {
    if(values.size() <= 1) return 0.0;
    double sum_sq_diff = 0.0;
    for(const auto& val : values) {
        double diff = val - mean;
        sum_sq_diff += diff * diff;
    }
    return std::sqrt(sum_sq_diff / (values.size() - 1));
}

double calculate_variance(const std::vector<double>& values, double mean) {
    if(values.size() <= 1) return 0.0;
    double sum_sq_diff = 0.0;
    for(const auto& val : values) {
        double diff = val - mean;
        sum_sq_diff += diff * diff;
    }
    return sum_sq_diff / (values.size() - 1);
}

void FlowAnalyzer::calculate_flow_features(const PacketInfo& /* first_packet */, FlowFeatures& features) {
    if(queue_->get_size() == 0) return;

    std::memset(&features, 0, sizeof(FlowFeatures));

    // Populate flow 5-tuple from first packet in queue
    if(queue_->get_size() > 0) {
        const PacketInfo& first_pkt = (*queue_)[0];
        features.src_ip = first_pkt.src_ip;
        features.dst_ip = first_pkt.dst_ip;
        features.src_port = first_pkt.src_port;
        features.dst_port = first_pkt.dst_port;
        features.protocol = first_pkt.protocol;
    }

    std::vector<double> fwd_packet_lengths;
    std::vector<double> bwd_packet_lengths;
    std::vector<double> all_packet_lengths;
    std::vector<double> fwd_iats;
    std::vector<double> bwd_iats;
    std::vector<double> all_iats;
    
    features.packet_length_min = std::numeric_limits<uint16_t>::max();
    features.packet_length_max = 0;
    features.fwd_packet_length_min = std::numeric_limits<uint16_t>::max();
    features.fwd_packet_length_max = 0;
    features.bwd_packet_length_min = std::numeric_limits<uint16_t>::max();
    features.bwd_packet_length_max = 0;
    features.flow_iat_min = std::numeric_limits<double>::infinity();
    features.flow_iat_max = 0;
    features.fwd_iat_min = std::numeric_limits<double>::infinity();
    features.fwd_iat_max = 0;
    features.bwd_iat_min = std::numeric_limits<double>::infinity();
    features.bwd_iat_max = 0;
    features.fwd_seg_size_min = std::numeric_limits<uint16_t>::max();
    
    struct timeval prev_time = {0, 0};
    struct timeval prev_fwd_time = {0, 0};
    struct timeval prev_bwd_time = {0, 0};
    bool first_packet_seen = false;
    bool first_fwd_packet = true;
    bool first_bwd_packet = true;
    
    for(int i = 0; i < queue_->get_size(); i++) {
        const PacketInfo& pkt = (*queue_)[i];
        
        if(i == 0) {
            features.first_packet_time = pkt.timestamp;
            features.fwd_init_win_bytes = pkt.window_size;
        }
        
        if(i == queue_->get_size() - 1) {
            features.last_packet_time = pkt.timestamp;
        }
        
        // packet length stats
        all_packet_lengths.push_back(pkt.packet_length);
        features.packet_length_min = std::min(features.packet_length_min, pkt.packet_length);
        features.packet_length_max = std::max(features.packet_length_max, pkt.packet_length);
        
        // flow direction analysis
        if(pkt.is_forward) {
            features.total_fwd_packets++;
            features.total_fwd_bytes += pkt.packet_length;
            features.fwd_header_length += pkt.header_length;
            
            fwd_packet_lengths.push_back(pkt.packet_length);
            features.fwd_packet_length_min = std::min(features.fwd_packet_length_min, pkt.packet_length);
            features.fwd_packet_length_max = std::max(features.fwd_packet_length_max, pkt.packet_length);
            
            if(pkt.payload_length > 0) {
                features.fwd_act_data_pkts++;
            }
            
            if(pkt.payload_length < features.fwd_seg_size_min) {
                features.fwd_seg_size_min = pkt.payload_length;
            }
            
            if(first_fwd_packet) {
                features.fwd_init_win_bytes = pkt.window_size;
                first_fwd_packet = false;
            } else {
                double iat = calculate_time_diff_microseconds(prev_fwd_time, pkt.timestamp);
                fwd_iats.push_back(iat);
                features.fwd_iat_total += iat;
                features.fwd_iat_min = std::min(features.fwd_iat_min, iat);
                features.fwd_iat_max = std::max(features.fwd_iat_max, iat);
            }
            prev_fwd_time = pkt.timestamp;
            
        } else {
            features.total_bwd_packets++;
            features.total_bwd_bytes += pkt.packet_length;
            features.bwd_header_length += pkt.header_length;
            
            bwd_packet_lengths.push_back(pkt.packet_length);
            features.bwd_packet_length_min = std::min(features.bwd_packet_length_min, pkt.packet_length);
            features.bwd_packet_length_max = std::max(features.bwd_packet_length_max, pkt.packet_length);
            
            if(first_bwd_packet) {
                features.bwd_init_win_bytes = pkt.window_size;
                first_bwd_packet = false;
            } else {
                double iat = calculate_time_diff_microseconds(prev_bwd_time, pkt.timestamp);
                bwd_iats.push_back(iat);
                features.bwd_iat_total += iat;
                features.bwd_iat_min = std::min(features.bwd_iat_min, iat);
                features.bwd_iat_max = std::max(features.bwd_iat_max, iat);
            }
            prev_bwd_time = pkt.timestamp;
        }
        
        // tcp flags
        if(pkt.tcp_flags.fin) features.fin_flag_count++;
        if(pkt.tcp_flags.syn) features.syn_flag_count++;
        if(pkt.tcp_flags.rst) features.rst_flag_count++;
        if(pkt.tcp_flags.psh) {
            features.psh_flag_count++;
            if(pkt.is_forward) features.fwd_psh_flags++;
            else features.bwd_psh_flags++;
        }
        if(pkt.tcp_flags.ack) features.ack_flag_count++;
        if(pkt.tcp_flags.urg) {
            features.urg_flag_count++;
            if(pkt.is_forward) features.fwd_urg_flags++;
            else features.bwd_urg_flags++;
        }
        if(pkt.tcp_flags.cwr) features.cwr_flag_count++;
        if(pkt.tcp_flags.ece) features.ece_flag_count++;
        
        // inter-arrival times
        if(first_packet_seen) {
            double iat = calculate_time_diff_microseconds(prev_time, pkt.timestamp);
            all_iats.push_back(iat);
            features.flow_iat_min = std::min(features.flow_iat_min, iat);
            features.flow_iat_max = std::max(features.flow_iat_max, iat);
        } else {
            first_packet_seen = true;
        }
        prev_time = pkt.timestamp;
    }
    
    // calculate derived metrics
    features.flow_duration = calculate_time_diff_microseconds(features.first_packet_time, features.last_packet_time) / 1000000.0;
    
    if(features.flow_duration > 0) {
        features.flow_bytes_per_sec = (features.total_fwd_bytes + features.total_bwd_bytes) / features.flow_duration;
        features.flow_packets_per_sec = (features.total_fwd_packets + features.total_bwd_packets) / features.flow_duration;
        features.fwd_packets_per_sec = features.total_fwd_packets / features.flow_duration;
        features.bwd_packets_per_sec = features.total_bwd_packets / features.flow_duration;
    }
    
    // packet length statistics
    if(!all_packet_lengths.empty()) {
        features.packet_length_mean = calculate_mean(all_packet_lengths);
        features.packet_length_std = calculate_std_dev(all_packet_lengths, features.packet_length_mean);
        features.packet_length_variance = calculate_variance(all_packet_lengths, features.packet_length_mean);
        features.avg_packet_size = features.packet_length_mean;
    }
    
    if(!fwd_packet_lengths.empty()) {
        features.fwd_packet_length_mean = calculate_mean(fwd_packet_lengths);
        features.fwd_packet_length_std = calculate_std_dev(fwd_packet_lengths, features.fwd_packet_length_mean);
        features.fwd_segment_size_avg = features.fwd_packet_length_mean;
    }
    
    if(!bwd_packet_lengths.empty()) {
        features.bwd_packet_length_mean = calculate_mean(bwd_packet_lengths);
        features.bwd_packet_length_std = calculate_std_dev(bwd_packet_lengths, features.bwd_packet_length_mean);
        features.bwd_segment_size_avg = features.bwd_packet_length_mean;
    }
    
    // inter-arrival time statistics
    if(!all_iats.empty()) {
        features.flow_iat_mean = calculate_mean(all_iats);
        features.flow_iat_std = calculate_std_dev(all_iats, features.flow_iat_mean);
    }
    
    if(!fwd_iats.empty()) {
        features.fwd_iat_mean = calculate_mean(fwd_iats);
        features.fwd_iat_std = calculate_std_dev(fwd_iats, features.fwd_iat_mean);
    }
    
    if(!bwd_iats.empty()) {
        features.bwd_iat_mean = calculate_mean(bwd_iats);
        features.bwd_iat_std = calculate_std_dev(bwd_iats, features.bwd_iat_mean);
    }
    
    // ratio calculations
    if(features.total_fwd_bytes > 0) {
        features.down_up_ratio = (double)features.total_bwd_bytes / features.total_fwd_bytes;
    }
}

bool FlowAnalyzer::process_packet(const PacketInfo& packet, FlowFeatures& features_out) {
    if(!first_packet_processed_) {
        first_packet_ = packet;
        first_packet_processed_ = true;
    }
    
    queue_->enqueue_packet(packet);
    
    if(queue_->get_size() >= queue_->get_window_size()) {
        calculate_flow_features(first_packet_, current_features_);
        features_out = current_features_;
        return true;
    }
    
    return false;
}
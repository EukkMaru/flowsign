#ifndef FLOW_ANALYZER_HPP
#define FLOW_ANALYZER_HPP

#include <memory>
#include <vector>
#include <cstdint>
#include <sys/time.h>

constexpr int MAX_WINDOW_SIZE = 1000;

struct PacketInfo {
    struct timeval timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t packet_length;
    uint16_t header_length;
    uint16_t payload_length;
    bool is_forward;
    
    struct {
        bool fin : 1;
        bool syn : 1;
        bool rst : 1;
        bool psh : 1;
        bool ack : 1;
        bool urg : 1;
        bool cwr : 1;
        bool ece : 1;
    } tcp_flags;
    
    uint16_t window_size;
};

struct FlowFeatures {
    double flow_duration;
    
    uint32_t total_fwd_packets;
    uint32_t total_bwd_packets;
    uint64_t total_fwd_bytes;
    uint64_t total_bwd_bytes;
    
    uint16_t fwd_packet_length_min;
    uint16_t fwd_packet_length_max;
    double fwd_packet_length_mean;
    double fwd_packet_length_std;
    
    uint16_t bwd_packet_length_min;
    uint16_t bwd_packet_length_max;
    double bwd_packet_length_mean;
    double bwd_packet_length_std;
    
    double flow_bytes_per_sec;
    double flow_packets_per_sec;
    
    double flow_iat_mean;
    double flow_iat_std;
    double flow_iat_max;
    double flow_iat_min;
    
    double fwd_iat_min;
    double fwd_iat_max;
    double fwd_iat_mean;
    double fwd_iat_std;
    double fwd_iat_total;
    
    double bwd_iat_min;
    double bwd_iat_max;
    double bwd_iat_mean;
    double bwd_iat_std;
    double bwd_iat_total;
    
    uint32_t fwd_psh_flags;
    uint32_t bwd_psh_flags;
    uint32_t fwd_urg_flags;
    uint32_t bwd_urg_flags;
    
    uint32_t fwd_header_length;
    uint32_t bwd_header_length;
    
    double fwd_packets_per_sec;
    double bwd_packets_per_sec;
    
    uint16_t packet_length_min;
    uint16_t packet_length_max;
    double packet_length_mean;
    double packet_length_std;
    double packet_length_variance;
    
    uint32_t fin_flag_count;
    uint32_t syn_flag_count;
    uint32_t rst_flag_count;
    uint32_t psh_flag_count;
    uint32_t ack_flag_count;
    uint32_t urg_flag_count;
    uint32_t cwr_flag_count;
    uint32_t ece_flag_count;
    
    double down_up_ratio;
    double avg_packet_size;
    double fwd_segment_size_avg;
    double bwd_segment_size_avg;
    
    uint32_t fwd_init_win_bytes;
    uint32_t bwd_init_win_bytes;
    uint32_t fwd_act_data_pkts;
    uint16_t fwd_seg_size_min;

    struct timeval first_packet_time;
    struct timeval last_packet_time;

    // Flow 5-tuple for ground truth matching
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

class CircularQueue {
private:
    std::vector<PacketInfo> packets_;
    int capacity_;
    int size_;
    int head_;
    int tail_;
    int window_size_;
    int step_size_;
    bool is_full_;

public:
    CircularQueue(int capacity, int window_size, int step_size);
    ~CircularQueue() = default;
    
    bool enqueue_packet(const PacketInfo& packet);
    int get_size() const { return size_; }
    int get_capacity() const { return capacity_; }
    int get_window_size() const { return window_size_; }
    int get_step_size() const { return step_size_; }
    bool is_full() const { return is_full_; }
    
    const PacketInfo& operator[](int index) const;
    PacketInfo& operator[](int index);
    
    class Iterator {
    private:
        const CircularQueue* queue_;
        int index_;
    public:
        Iterator(const CircularQueue* queue, int index) : queue_(queue), index_(index) {}
        const PacketInfo& operator*() const { return (*queue_)[index_]; }
        Iterator& operator++() { ++index_; return *this; }
        bool operator!=(const Iterator& other) const { return index_ != other.index_; }
    };
    
    Iterator begin() const { return Iterator(this, 0); }
    Iterator end() const { return Iterator(this, size_); }
};

class FlowAnalyzer {
private:
    std::unique_ptr<CircularQueue> queue_;
    FlowFeatures current_features_;
    uint32_t flow_id_;
    bool first_packet_processed_;
    PacketInfo first_packet_;

public:
    FlowAnalyzer(int window_capacity, int window_size, int step_size);
    ~FlowAnalyzer() = default;
    
    bool process_packet(const PacketInfo& packet, FlowFeatures& features_out);
    const FlowFeatures& get_current_features() const { return current_features_; }
    uint32_t get_flow_id() const { return flow_id_; }
    
private:
    void calculate_flow_features(const PacketInfo& first_packet, FlowFeatures& features);
};

// Utility functions
double calculate_time_diff_microseconds(const struct timeval& start, const struct timeval& end);
double calculate_mean(const std::vector<double>& values);
double calculate_std_dev(const std::vector<double>& values, double mean);
double calculate_variance(const std::vector<double>& values, double mean);

#endif // FLOW_ANALYZER_HPP
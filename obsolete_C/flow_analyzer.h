#ifndef FLOW_ANALYZER_H
#define FLOW_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

#define MAX_WINDOW_SIZE 1000

typedef struct {
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
} packet_info_t;

typedef struct {
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
} flow_features_t;

typedef struct {
    packet_info_t *packets;
    int capacity;
    int size;
    int head;
    int tail;
    int window_size;
    int step_size;
    bool is_full;
} circular_queue_t;

typedef struct {
    circular_queue_t *queue;
    flow_features_t current_features;
    uint32_t flow_id;
    bool first_packet_processed;
    packet_info_t first_packet;
} flow_analyzer_t;

circular_queue_t* create_circular_queue(int capacity, int window_size, int step_size);
void destroy_circular_queue(circular_queue_t *queue);
bool enqueue_packet(circular_queue_t *queue, packet_info_t *packet);
flow_analyzer_t* create_flow_analyzer(int window_capacity, int window_size, int step_size);
void destroy_flow_analyzer(flow_analyzer_t *analyzer);
bool process_packet(flow_analyzer_t *analyzer, packet_info_t *packet, flow_features_t *features_out);
void calculate_flow_features(circular_queue_t *queue, packet_info_t *first_packet, flow_features_t *features);

double calculate_time_diff_microseconds(struct timeval *start, struct timeval *end);
double calculate_mean(double *values, int count);
double calculate_std_dev(double *values, int count, double mean);
double calculate_variance(double *values, int count, double mean);

#endif
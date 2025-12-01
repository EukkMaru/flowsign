#include "flow_analyzer.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

circular_queue_t* create_circular_queue(int capacity, int window_size, int step_size) {
    circular_queue_t *queue = malloc(sizeof(circular_queue_t));
    if (!queue) return NULL;
    
    queue->packets = malloc(sizeof(packet_info_t) * capacity);
    if (!queue->packets) {
        free(queue);
        return NULL;
    }
    
    queue->capacity = capacity;
    queue->size = 0;
    queue->head = 0;
    queue->tail = 0;
    queue->window_size = window_size;
    queue->step_size = step_size;
    queue->is_full = false;
    
    return queue;
}

void destroy_circular_queue(circular_queue_t *queue) {
    if (queue) {
        free(queue->packets);
        free(queue);
    }
}

bool enqueue_packet(circular_queue_t *queue, packet_info_t *packet) {
    if (!queue || !packet) return false;
    
    memcpy(&queue->packets[queue->tail], packet, sizeof(packet_info_t));
    
    queue->tail = (queue->tail + 1) % queue->capacity;
    
    if (queue->size < queue->capacity) {
        queue->size++;
    } else {
        queue->head = (queue->head + 1) % queue->capacity;
        queue->is_full = true;
    }
    
    return true;
}

flow_analyzer_t* create_flow_analyzer(int window_capacity, int window_size, int step_size) {
    flow_analyzer_t *analyzer = malloc(sizeof(flow_analyzer_t));
    if (!analyzer) return NULL;
    
    analyzer->queue = create_circular_queue(window_capacity, window_size, step_size);
    if (!analyzer->queue) {
        free(analyzer);
        return NULL;
    }
    
    memset(&analyzer->current_features, 0, sizeof(flow_features_t));
    analyzer->flow_id = 0;
    analyzer->first_packet_processed = false;
    
    return analyzer;
}

void destroy_flow_analyzer(flow_analyzer_t *analyzer) {
    if (analyzer) {
        destroy_circular_queue(analyzer->queue);
        free(analyzer);
    }
}

double calculate_time_diff_microseconds(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000000.0 + (end->tv_usec - start->tv_usec);
}

double calculate_mean(double *values, int count) {
    if (count == 0) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < count; i++) {
        sum += values[i];
    }
    return sum / count;
}

double calculate_std_dev(double *values, int count, double mean) {
    if (count <= 1) return 0.0;
    double sum_sq_diff = 0.0;
    for (int i = 0; i < count; i++) {
        double diff = values[i] - mean;
        sum_sq_diff += diff * diff;
    }
    return sqrt(sum_sq_diff / (count - 1));
}

double calculate_variance(double *values, int count, double mean) {
    if (count <= 1) return 0.0;
    double sum_sq_diff = 0.0;
    for (int i = 0; i < count; i++) {
        double diff = values[i] - mean;
        sum_sq_diff += diff * diff;
    }
    return sum_sq_diff / (count - 1);
}

void calculate_flow_features(circular_queue_t *queue, packet_info_t *first_packet, flow_features_t *features) {
    if (!queue || !features || queue->size == 0) return;
    
    memset(features, 0, sizeof(flow_features_t));
    
    double *fwd_packet_lengths = malloc(sizeof(double) * queue->size);
    double *bwd_packet_lengths = malloc(sizeof(double) * queue->size);
    double *all_packet_lengths = malloc(sizeof(double) * queue->size);
    double *fwd_iats = malloc(sizeof(double) * queue->size);
    double *bwd_iats = malloc(sizeof(double) * queue->size);
    double *all_iats = malloc(sizeof(double) * queue->size);
    
    int fwd_count = 0, bwd_count = 0, all_count = 0;
    int fwd_iat_count = 0, bwd_iat_count = 0, all_iat_count = 0;
    
    features->packet_length_min = UINT16_MAX;
    features->packet_length_max = 0;
    features->fwd_packet_length_min = UINT16_MAX;
    features->fwd_packet_length_max = 0;
    features->bwd_packet_length_min = UINT16_MAX;
    features->bwd_packet_length_max = 0;
    features->flow_iat_min = INFINITY;
    features->flow_iat_max = 0;
    features->fwd_iat_min = INFINITY;
    features->fwd_iat_max = 0;
    features->bwd_iat_min = INFINITY;
    features->bwd_iat_max = 0;
    features->fwd_seg_size_min = UINT16_MAX;
    
    struct timeval prev_time = {0, 0};
    struct timeval prev_fwd_time = {0, 0};
    struct timeval prev_bwd_time = {0, 0};
    bool first_packet_seen = false;
    bool first_fwd_packet = true;
    bool first_bwd_packet = true;
    
    for (int i = 0; i < queue->size; i++) {
        int idx = (queue->head + i) % queue->capacity;
        packet_info_t *pkt = &queue->packets[idx];
        
        if (i == 0) {
            features->first_packet_time = pkt->timestamp;
            if (!first_packet) {
                first_packet = pkt;
                features->fwd_init_win_bytes = pkt->window_size;
            }
        }
        features->last_packet_time = pkt->timestamp;
        
        all_packet_lengths[all_count++] = pkt->packet_length;
        
        if (pkt->packet_length < features->packet_length_min)
            features->packet_length_min = pkt->packet_length;
        if (pkt->packet_length > features->packet_length_max)
            features->packet_length_max = pkt->packet_length;
        
        if (pkt->is_forward) {
            features->total_fwd_packets++;
            features->total_fwd_bytes += pkt->packet_length;
            features->fwd_header_length += pkt->header_length;
            
            fwd_packet_lengths[fwd_count++] = pkt->packet_length;
            
            if (pkt->packet_length < features->fwd_packet_length_min)
                features->fwd_packet_length_min = pkt->packet_length;
            if (pkt->packet_length > features->fwd_packet_length_max)
                features->fwd_packet_length_max = pkt->packet_length;
            
            if (pkt->payload_length > 0) {
                features->fwd_act_data_pkts++;
            }
            
            if (pkt->payload_length < features->fwd_seg_size_min)
                features->fwd_seg_size_min = pkt->payload_length;
            
            if (pkt->tcp_flags.psh) features->fwd_psh_flags++;
            if (pkt->tcp_flags.urg) features->fwd_urg_flags++;
            
            if (!first_fwd_packet) {
                double iat = calculate_time_diff_microseconds(&prev_fwd_time, &pkt->timestamp);
                fwd_iats[fwd_iat_count++] = iat;
                features->fwd_iat_total += iat;
                
                if (iat < features->fwd_iat_min) features->fwd_iat_min = iat;
                if (iat > features->fwd_iat_max) features->fwd_iat_max = iat;
            } else {
                first_fwd_packet = false;
            }
            prev_fwd_time = pkt->timestamp;
            
        } else {
            features->total_bwd_packets++;
            features->total_bwd_bytes += pkt->packet_length;
            features->bwd_header_length += pkt->header_length;
            
            bwd_packet_lengths[bwd_count++] = pkt->packet_length;
            
            if (pkt->packet_length < features->bwd_packet_length_min)
                features->bwd_packet_length_min = pkt->packet_length;
            if (pkt->packet_length > features->bwd_packet_length_max)
                features->bwd_packet_length_max = pkt->packet_length;
            
            if (pkt->tcp_flags.psh) features->bwd_psh_flags++;
            if (pkt->tcp_flags.urg) features->bwd_urg_flags++;
            
            if (bwd_count == 1) {
                features->bwd_init_win_bytes = pkt->window_size;
            }
            
            if (!first_bwd_packet) {
                double iat = calculate_time_diff_microseconds(&prev_bwd_time, &pkt->timestamp);
                bwd_iats[bwd_iat_count++] = iat;
                features->bwd_iat_total += iat;
                
                if (iat < features->bwd_iat_min) features->bwd_iat_min = iat;
                if (iat > features->bwd_iat_max) features->bwd_iat_max = iat;
            } else {
                first_bwd_packet = false;
            }
            prev_bwd_time = pkt->timestamp;
        }
        
        if (pkt->tcp_flags.fin) features->fin_flag_count++;
        if (pkt->tcp_flags.syn) features->syn_flag_count++;
        if (pkt->tcp_flags.rst) features->rst_flag_count++;
        if (pkt->tcp_flags.psh) features->psh_flag_count++;
        if (pkt->tcp_flags.ack) features->ack_flag_count++;
        if (pkt->tcp_flags.urg) features->urg_flag_count++;
        if (pkt->tcp_flags.cwr) features->cwr_flag_count++;
        if (pkt->tcp_flags.ece) features->ece_flag_count++;
        
        if (first_packet_seen) {
            double iat = calculate_time_diff_microseconds(&prev_time, &pkt->timestamp);
            all_iats[all_iat_count++] = iat;
            
            if (iat < features->flow_iat_min) features->flow_iat_min = iat;
            if (iat > features->flow_iat_max) features->flow_iat_max = iat;
        } else {
            first_packet_seen = true;
        }
        prev_time = pkt->timestamp;
    }
    
    features->flow_duration = calculate_time_diff_microseconds(&features->first_packet_time, &features->last_packet_time);
    
    if (features->flow_duration > 0) {
        features->flow_bytes_per_sec = ((features->total_fwd_bytes + features->total_bwd_bytes) * 1000000.0) / features->flow_duration;
        features->flow_packets_per_sec = ((features->total_fwd_packets + features->total_bwd_packets) * 1000000.0) / features->flow_duration;
        features->fwd_packets_per_sec = (features->total_fwd_packets * 1000000.0) / features->flow_duration;
        features->bwd_packets_per_sec = (features->total_bwd_packets * 1000000.0) / features->flow_duration;
    }
    
    if (fwd_count > 0) {
        features->fwd_packet_length_mean = calculate_mean(fwd_packet_lengths, fwd_count);
        features->fwd_packet_length_std = calculate_std_dev(fwd_packet_lengths, fwd_count, features->fwd_packet_length_mean);
        features->fwd_segment_size_avg = features->fwd_packet_length_mean;
    }
    
    if (bwd_count > 0) {
        features->bwd_packet_length_mean = calculate_mean(bwd_packet_lengths, bwd_count);
        features->bwd_packet_length_std = calculate_std_dev(bwd_packet_lengths, bwd_count, features->bwd_packet_length_mean);
        features->bwd_segment_size_avg = features->bwd_packet_length_mean;
    }
    
    if (all_count > 0) {
        features->packet_length_mean = calculate_mean(all_packet_lengths, all_count);
        features->packet_length_std = calculate_std_dev(all_packet_lengths, all_count, features->packet_length_mean);
        features->packet_length_variance = calculate_variance(all_packet_lengths, all_count, features->packet_length_mean);
        features->avg_packet_size = features->packet_length_mean;
    }
    
    if (all_iat_count > 0) {
        features->flow_iat_mean = calculate_mean(all_iats, all_iat_count);
        features->flow_iat_std = calculate_std_dev(all_iats, all_iat_count, features->flow_iat_mean);
    }
    
    if (fwd_iat_count > 0) {
        features->fwd_iat_mean = calculate_mean(fwd_iats, fwd_iat_count);
        features->fwd_iat_std = calculate_std_dev(fwd_iats, fwd_iat_count, features->fwd_iat_mean);
    }
    
    if (bwd_iat_count > 0) {
        features->bwd_iat_mean = calculate_mean(bwd_iats, bwd_iat_count);
        features->bwd_iat_std = calculate_std_dev(bwd_iats, bwd_iat_count, features->bwd_iat_mean);
    }
    
    if (features->total_bwd_bytes > 0) {
        features->down_up_ratio = (double)features->total_fwd_bytes / features->total_bwd_bytes;
    }
    
    if (features->flow_iat_min == INFINITY) features->flow_iat_min = 0.0;
    if (features->fwd_iat_min == INFINITY) features->fwd_iat_min = 0.0;
    if (features->bwd_iat_min == INFINITY) features->bwd_iat_min = 0.0;
    if (features->fwd_seg_size_min == UINT16_MAX) features->fwd_seg_size_min = 0;
    if (features->fwd_packet_length_min == UINT16_MAX) features->fwd_packet_length_min = 0;
    if (features->bwd_packet_length_min == UINT16_MAX) features->bwd_packet_length_min = 0;
    
    free(fwd_packet_lengths);
    free(bwd_packet_lengths);
    free(all_packet_lengths);
    free(fwd_iats);
    free(bwd_iats);
    free(all_iats);
}

bool process_packet(flow_analyzer_t *analyzer, packet_info_t *packet, flow_features_t *features_out) {
    if (!analyzer || !packet) return false;
    
    if (!analyzer->first_packet_processed) {
        analyzer->first_packet = *packet;
        analyzer->first_packet_processed = true;
    }
    
    enqueue_packet(analyzer->queue, packet);
    
    if (analyzer->queue->size >= analyzer->queue->window_size || analyzer->queue->is_full) {
        calculate_flow_features(analyzer->queue, &analyzer->first_packet, &analyzer->current_features);
        
        if (features_out) {
            *features_out = analyzer->current_features;
        }
        
        return true;
    }
    
    return false;
}
#ifndef SNORTSHARP_INTEGRATION_H
#define SNORTSHARP_INTEGRATION_H

#include "flow_analyzer.h"
#include "flow_rules.h"
#include "event_system.h"
#include <pthread.h>
#include <stdbool.h>

#define MAX_FEATURE_QUEUE_SIZE 1000

typedef struct {
    flow_features_t *features;
    int capacity;
    int count;
    int head;
    int tail;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    bool is_full;
} feature_queue_t;

typedef struct {
    // Process 1: Flow Analysis
    flow_analyzer_t *flow_analyzer;
    
    // Process 2: Rule Engine  
    flow_rule_engine_t *rule_engine;
    
    // Communication between processes
    feature_queue_t *feature_queue;
    event_system_t *event_system;
    bool use_events;  // Whether to use libuv events or traditional queue
    
    // Threading
    pthread_t process1_thread;
    pthread_t process2_thread;
    bool running;
    bool threads_created;
    
    // Statistics
    uint64_t total_packets_processed;
    uint64_t total_features_generated;
    uint64_t total_alerts_generated;
    
    struct {
        uint64_t features_dropped;      // When queue is full
        uint64_t processing_errors;     // Processing failures
        double avg_processing_time_us;  // Average processing time
    } stats;
} snortsharp_engine_t;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t packet_length;
    uint16_t header_length;
    bool is_forward;
    struct timeval timestamp;
    
    struct {
        bool fin : 1;
        bool syn : 1;
        bool rst : 1;
        bool psh : 1;
        bool ack : 1;
        bool urg : 1;
    } tcp_flags;
    
    uint16_t window_size;
} snort_packet_t;

// Feature queue management
feature_queue_t* create_feature_queue(int capacity);
void destroy_feature_queue(feature_queue_t *queue);
bool enqueue_features(feature_queue_t *queue, const flow_features_t *features);
bool dequeue_features(feature_queue_t *queue, flow_features_t *features);

// SnortSharp engine management
snortsharp_engine_t* create_snortsharp_engine(int window_size, int queue_capacity, int alert_capacity);
snortsharp_engine_t* create_snortsharp_engine_with_events(int window_size, int queue_capacity, 
                                                         int alert_capacity, const char *event_pipe);
void destroy_snortsharp_engine(snortsharp_engine_t *engine);
bool start_snortsharp_engine(snortsharp_engine_t *engine);
void stop_snortsharp_engine(snortsharp_engine_t *engine);

// Packet processing (called from Snort integration)
bool process_snort_packet(snortsharp_engine_t *engine, const snort_packet_t *snort_packet);

// Alert retrieval
bool get_next_alert(snortsharp_engine_t *engine, flow_alert_t *alert);

// Rule management
bool load_flow_rules(snortsharp_engine_t *engine, const char *rules_file);
bool add_flow_rule(snortsharp_engine_t *engine, const char *rule_string);

// Statistics and monitoring
void print_snortsharp_stats(const snortsharp_engine_t *engine);
void reset_snortsharp_stats(snortsharp_engine_t *engine);

// Utility functions
snort_packet_t* convert_snort_packet(const void *snort_internal_packet);
void print_flow_alert(const flow_alert_t *alert);

#endif
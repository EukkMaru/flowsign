#define _POSIX_C_SOURCE 200809L
#include "snortsharp_integration.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

feature_queue_t* create_feature_queue(int capacity) {
    feature_queue_t *queue = malloc(sizeof(feature_queue_t));
    if (!queue) return NULL;
    
    queue->features = malloc(sizeof(flow_features_t) * capacity);
    if (!queue->features) {
        free(queue);
        return NULL;
    }
    
    queue->capacity = capacity;
    queue->count = 0;
    queue->head = 0;
    queue->tail = 0;
    queue->is_full = false;
    
    if (pthread_mutex_init(&queue->mutex, NULL) != 0 ||
        pthread_cond_init(&queue->not_empty, NULL) != 0 ||
        pthread_cond_init(&queue->not_full, NULL) != 0) {
        free(queue->features);
        free(queue);
        return NULL;
    }
    
    return queue;
}

void destroy_feature_queue(feature_queue_t *queue) {
    if (queue) {
        pthread_mutex_destroy(&queue->mutex);
        pthread_cond_destroy(&queue->not_empty);
        pthread_cond_destroy(&queue->not_full);
        free(queue->features);
        free(queue);
    }
}

bool enqueue_features(feature_queue_t *queue, const flow_features_t *features) {
    if (!queue || !features) return false;
    
    pthread_mutex_lock(&queue->mutex);
    
    while (queue->count == queue->capacity) {
        // Queue is full, drop oldest features or wait
        // For now, we'll drop the oldest
        queue->head = (queue->head + 1) % queue->capacity;
        queue->count--;
    }
    
    memcpy(&queue->features[queue->tail], features, sizeof(flow_features_t));
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;
    
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
    
    return true;
}

bool dequeue_features(feature_queue_t *queue, flow_features_t *features) {
    if (!queue || !features) return false;
    
    pthread_mutex_lock(&queue->mutex);
    
    while (queue->count == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }
    
    memcpy(features, &queue->features[queue->head], sizeof(flow_features_t));
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;
    
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    
    return true;
}

static void* process1_thread_func(void *arg) {
    snortsharp_engine_t *engine = (snortsharp_engine_t*)arg;
    
    printf("[Process 1] Flow analysis thread started\n");
    
    while (engine->running) {
        // In a real implementation, this would receive packets from Snort
        // For now, we'll just maintain the thread
        struct timespec ts = {0, 1000000}; // 1ms
        nanosleep(&ts, NULL);
    }
    
    printf("[Process 1] Flow analysis thread stopped\n");
    return NULL;
}

static void* process2_thread_func(void *arg) {
    snortsharp_engine_t *engine = (snortsharp_engine_t*)arg;
    
    printf("[Process 2] Rule evaluation thread started\n");
    
    while (engine->running) {
        flow_features_t features;
        
        // Dequeue features from Process 1 (blocking call)
        if (dequeue_features(engine->feature_queue, &features)) {
            // Process features through rule engine
            process_flow_features(engine->rule_engine, &features);
            engine->total_alerts_generated = engine->rule_engine->total_matches;
        }
    }
    
    printf("[Process 2] Rule evaluation thread stopped\n");
    return NULL;
}

snortsharp_engine_t* create_snortsharp_engine(int window_size, int queue_capacity, int alert_capacity) {
    snortsharp_engine_t *engine = malloc(sizeof(snortsharp_engine_t));
    if (!engine) return NULL;
    
    // Create Process 1: Flow Analyzer
    engine->flow_analyzer = create_flow_analyzer(queue_capacity * 2, window_size, 1);
    if (!engine->flow_analyzer) {
        free(engine);
        return NULL;
    }
    
    // Create Process 2: Rule Engine
    engine->rule_engine = create_flow_rule_engine(alert_capacity);
    if (!engine->rule_engine) {
        destroy_flow_analyzer(engine->flow_analyzer);
        free(engine);
        return NULL;
    }
    
    // Create communication queue
    engine->feature_queue = create_feature_queue(queue_capacity);
    if (!engine->feature_queue) {
        destroy_flow_rule_engine(engine->rule_engine);
        destroy_flow_analyzer(engine->flow_analyzer);
        free(engine);
        return NULL;
    }
    
    engine->running = false;
    engine->threads_created = false;
    engine->total_packets_processed = 0;
    engine->total_features_generated = 0;
    engine->total_alerts_generated = 0;
    
    memset(&engine->stats, 0, sizeof(engine->stats));
    
    return engine;
}

snortsharp_engine_t* create_snortsharp_engine_with_events(int window_size, int queue_capacity, 
                                                         int alert_capacity, const char *event_pipe) {
    snortsharp_engine_t *engine = create_snortsharp_engine(window_size, queue_capacity, alert_capacity);
    if (!engine) return NULL;
    
    // Create event system for inter-process communication
    engine->event_system = create_event_system(event_pipe, false); // Client mode for proc1
    if (!engine->event_system) {
        destroy_snortsharp_engine(engine);
        return NULL;
    }
    
    engine->use_events = true;
    
    printf("[SnortSharp] Engine created with libuv event system: %s\n", event_pipe);
    
    return engine;
}

void destroy_snortsharp_engine(snortsharp_engine_t *engine) {
    if (engine) {
        if (engine->threads_created && engine->running) {
            stop_snortsharp_engine(engine);
        }
        
        destroy_feature_queue(engine->feature_queue);
        destroy_flow_rule_engine(engine->rule_engine);
        destroy_flow_analyzer(engine->flow_analyzer);
        
        if (engine->event_system) {
            destroy_event_system(engine->event_system);
        }
        
        free(engine);
    }
}

bool start_snortsharp_engine(snortsharp_engine_t *engine) {
    if (!engine || engine->threads_created) return false;
    
    engine->running = true;
    
    // If using events, connect to event system
    if (engine->use_events && engine->event_system) {
        if (connect_event_client(engine->event_system) != 0) {
            printf("[SnortSharp] Failed to connect to event system\n");
            engine->running = false;
            return false;
        }
        printf("[SnortSharp] Connected to event system\n");
    }
    
    // Start Process 1 thread (Flow Analysis)
    if (pthread_create(&engine->process1_thread, NULL, process1_thread_func, engine) != 0) {
        engine->running = false;
        return false;
    }
    
    // Start Process 2 thread (Rule Evaluation)
    if (pthread_create(&engine->process2_thread, NULL, process2_thread_func, engine) != 0) {
        engine->running = false;
        pthread_join(engine->process1_thread, NULL);
        return false;
    }
    
    engine->threads_created = true;
    
    printf("[SnortSharp] Engine started with %d flow rules\n", 
           engine->rule_engine->ruleset->rule_count);
    
    return true;
}

void stop_snortsharp_engine(snortsharp_engine_t *engine) {
    if (engine && engine->threads_created) {
        printf("[SnortSharp] Stopping engine...\n");
        
        engine->running = false;
        
        // Send shutdown event if using event system
        if (engine->use_events && engine->event_system) {
            send_shutdown_event(engine->event_system);
            disconnect_event_client(engine->event_system);
        }
        
        // Wake up Process 2 thread if it's waiting
        pthread_mutex_lock(&engine->feature_queue->mutex);
        pthread_cond_broadcast(&engine->feature_queue->not_empty);
        pthread_mutex_unlock(&engine->feature_queue->mutex);
        
        pthread_join(engine->process1_thread, NULL);
        pthread_join(engine->process2_thread, NULL);
        
        engine->threads_created = false;
        
        printf("[SnortSharp] Engine stopped\n");
    }
}

packet_info_t convert_snort_to_packet_info(const snort_packet_t *snort_pkt) {
    packet_info_t pkt;
    memset(&pkt, 0, sizeof(packet_info_t));
    
    pkt.timestamp = snort_pkt->timestamp;
    pkt.src_ip = snort_pkt->src_ip;
    pkt.dst_ip = snort_pkt->dst_ip;
    pkt.src_port = snort_pkt->src_port;
    pkt.dst_port = snort_pkt->dst_port;
    pkt.protocol = snort_pkt->protocol;
    pkt.packet_length = snort_pkt->packet_length;
    pkt.header_length = snort_pkt->header_length;
    pkt.payload_length = snort_pkt->packet_length - snort_pkt->header_length;
    pkt.is_forward = snort_pkt->is_forward;
    pkt.window_size = snort_pkt->window_size;
    
    pkt.tcp_flags.fin = snort_pkt->tcp_flags.fin;
    pkt.tcp_flags.syn = snort_pkt->tcp_flags.syn;
    pkt.tcp_flags.rst = snort_pkt->tcp_flags.rst;
    pkt.tcp_flags.psh = snort_pkt->tcp_flags.psh;
    pkt.tcp_flags.ack = snort_pkt->tcp_flags.ack;
    pkt.tcp_flags.urg = snort_pkt->tcp_flags.urg;
    
    return pkt;
}

bool process_snort_packet(snortsharp_engine_t *engine, const snort_packet_t *snort_packet) {
    if (!engine || !snort_packet) return false;
    
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);
    
    // Convert Snort packet to our format
    packet_info_t pkt = convert_snort_to_packet_info(snort_packet);
    
    // Process through flow analyzer (Process 1)
    flow_features_t features;
    if (process_packet(engine->flow_analyzer, &pkt, &features)) {
        // Features generated, send to Process 2
        if (engine->use_events && engine->event_system) {
            // Broadcast event via libuv
            if (broadcast_window_event(engine->event_system, engine->flow_analyzer->flow_id, 
                                     &features, "proc1") == 0) {
                engine->total_features_generated++;
            } else {
                engine->stats.features_dropped++;
            }
        } else {
            // Use traditional queue
            if (enqueue_features(engine->feature_queue, &features)) {
                engine->total_features_generated++;
            } else {
                engine->stats.features_dropped++;
            }
        }
    }
    
    engine->total_packets_processed++;
    
    // Update timing statistics
    gettimeofday(&end_time, NULL);
    double processing_time = calculate_time_diff_microseconds(&start_time, &end_time);
    
    if (engine->total_packets_processed == 1) {
        engine->stats.avg_processing_time_us = processing_time;
    } else {
        engine->stats.avg_processing_time_us = 
            (engine->stats.avg_processing_time_us * 0.9) + (processing_time * 0.1);
    }
    
    return true;
}

bool get_next_alert(snortsharp_engine_t *engine, flow_alert_t *alert) {
    if (!engine || !alert) return false;
    
    return dequeue_alert(engine->rule_engine->alert_queue, alert);
}

bool add_flow_rule(snortsharp_engine_t *engine, const char *rule_string) {
    if (!engine || !rule_string) return false;
    
    return add_rule_from_string(engine->rule_engine->ruleset, rule_string);
}

void print_snortsharp_stats(const snortsharp_engine_t *engine) {
    if (!engine) return;
    
    printf("\n=== SnortSharp Engine Statistics ===\n");
    printf("Packets Processed: %lu\n", engine->total_packets_processed);
    printf("Features Generated: %lu\n", engine->total_features_generated);
    printf("Alerts Generated: %lu\n", engine->total_alerts_generated);
    printf("Features Dropped: %lu\n", engine->stats.features_dropped);
    printf("Processing Errors: %lu\n", engine->stats.processing_errors);
    printf("Avg Processing Time: %.2f us\n", engine->stats.avg_processing_time_us);
    
    printf("\nRule Engine Stats:\n");
    printf("  Total Evaluations: %lu\n", engine->rule_engine->total_evaluations);
    printf("  Total Matches: %lu\n", engine->rule_engine->total_matches);
    printf("  Features Processed: %lu\n", engine->rule_engine->total_features_processed);
    
    if (engine->rule_engine->total_evaluations > 0) {
        printf("  Match Rate: %.2f%%\n", 
               (engine->rule_engine->total_matches * 100.0) / engine->rule_engine->total_evaluations);
    }
    
    printf("\nFeature Queue Stats:\n");
    printf("  Capacity: %d\n", engine->feature_queue->capacity);
    printf("  Current Count: %d\n", engine->feature_queue->count);
    printf("  Utilization: %.1f%%\n", 
           (engine->feature_queue->count * 100.0) / engine->feature_queue->capacity);
    
    printf("=====================================\n\n");
}

void print_flow_alert(const flow_alert_t *alert) {
    if (!alert) return;
    
    printf("[FLOW ALERT] SID:%u - %s\n", alert->rule_id, alert->message);
    printf("  Timestamp: %ld.%06ld\n", alert->timestamp.tv_sec, alert->timestamp.tv_usec);
    printf("  Confidence: %.2f\n", alert->confidence);
    printf("  Flow Stats: %.0f packets, %.0f bytes, %.2f IAT mean\n",
           (double)(alert->features.total_fwd_packets + alert->features.total_bwd_packets),
           (double)(alert->features.total_fwd_bytes + alert->features.total_bwd_bytes),
           alert->features.flow_iat_mean);
}
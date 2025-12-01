#include "performance_test.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include <arpa/inet.h>

// Memory tracking via /proc/self/status
long get_current_memory_kb(void) {
    FILE *file = fopen("/proc/self/status", "r");
    if (!file) return -1;
    
    char line[256];
    long memory_kb = -1;
    
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %ld kB", &memory_kb);
            break;
        }
    }
    
    fclose(file);
    return memory_kb;
}

double timeval_diff_us(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000000.0 + (end->tv_usec - start->tv_usec);
}

double get_cpu_utilization(struct rusage *start, struct rusage *end, double elapsed_time_us) {
    double user_time_us = timeval_diff_us(&start->ru_utime, &end->ru_utime);
    double system_time_us = timeval_diff_us(&start->ru_stime, &end->ru_stime);
    double total_cpu_us = user_time_us + system_time_us;
    
    return (total_cpu_us / elapsed_time_us) * 100.0;
}

performance_test_t* create_performance_test(performance_config_t *config) {
    performance_test_t *test = malloc(sizeof(performance_test_t));
    if (!test) return NULL;
    
    memset(test, 0, sizeof(performance_test_t));
    test->config = *config;
    
    // Create flow analyzer
    test->analyzer = create_flow_analyzer(config->queue_capacity, config->window_size, 1);
    if (!test->analyzer) {
        free(test);
        return NULL;
    }
    
    // Create event system if requested
    if (config->use_events) {
        test->event_system = create_event_system("/tmp/snortsharp_perf", false);
        if (!test->event_system) {
            destroy_flow_analyzer(test->analyzer);
            free(test);
            return NULL;
        }
    }
    
    // Allocate packet timing array
    test->packet_times_capacity = config->num_packets;
    test->packet_times_us = malloc(sizeof(double) * test->packet_times_capacity);
    if (!test->packet_times_us) {
        if (test->event_system) destroy_event_system(test->event_system);
        destroy_flow_analyzer(test->analyzer);
        free(test);
        return NULL;
    }
    
    return test;
}

void destroy_performance_test(performance_test_t *test) {
    if (!test) return;
    
    if (test->analyzer) destroy_flow_analyzer(test->analyzer);
    if (test->event_system) destroy_event_system(test->event_system);
    if (test->packet_times_us) free(test->packet_times_us);
    free(test);
}

packet_info_t generate_test_packet(int seq, int size, bool realistic_timing) {
    packet_info_t packet;
    memset(&packet, 0, sizeof(packet_info_t));
    
    gettimeofday(&packet.timestamp, NULL);
    
    // Add realistic jitter if requested
    if (realistic_timing) {
        int jitter_us = (rand() % 1000) - 500; // ±500 us jitter
        packet.timestamp.tv_usec += jitter_us;
        if (packet.timestamp.tv_usec < 0) {
            packet.timestamp.tv_sec--;
            packet.timestamp.tv_usec += 1000000;
        } else if (packet.timestamp.tv_usec >= 1000000) {
            packet.timestamp.tv_sec++;
            packet.timestamp.tv_usec -= 1000000;
        }
    }
    
    packet.src_ip = inet_addr("192.168.1.100");
    packet.dst_ip = inet_addr("10.0.0.50");
    packet.src_port = 12345;
    packet.dst_port = 80;
    packet.protocol = 6; // TCP
    packet.packet_length = size;
    packet.header_length = 54;
    packet.payload_length = size - 54;
    packet.is_forward = (seq % 2 == 0);
    packet.window_size = 8192;
    
    // Set TCP flags based on sequence
    if (seq == 0) {
        packet.tcp_flags.syn = true;
    } else if (seq == 1) {
        packet.tcp_flags.syn = true;
        packet.tcp_flags.ack = true;
    } else if (seq < 10) {
        packet.tcp_flags.ack = true;
        packet.tcp_flags.psh = true;
    } else {
        packet.tcp_flags.ack = true;
    }
    
    return packet;
}

void start_performance_monitoring(performance_test_t *test) {
    gettimeofday(&test->start_time, NULL);
    getrusage(RUSAGE_SELF, &test->start_usage);
    test->initial_memory_kb = get_current_memory_kb();
    test->peak_memory_kb = test->initial_memory_kb;
}

void stop_performance_monitoring(performance_test_t *test) {
    gettimeofday(&test->end_time, NULL);
    getrusage(RUSAGE_SELF, &test->end_usage);
    
    // Calculate metrics
    calculate_performance_stats(test);
}

void calculate_performance_stats(performance_test_t *test) {
    performance_metrics_t *m = &test->metrics;
    
    // Time calculations
    m->total_processing_time_us = timeval_diff_us(&test->start_time, &test->end_time);
    
    if (test->packet_times_count > 0) {
        double sum = 0, min_time = test->packet_times_us[0], max_time = test->packet_times_us[0];
        
        for (int i = 0; i < test->packet_times_count; i++) {
            double time = test->packet_times_us[i];
            sum += time;
            if (time < min_time) min_time = time;
            if (time > max_time) max_time = time;
        }
        
        m->avg_packet_processing_time_us = sum / test->packet_times_count;
        m->min_packet_processing_time_us = min_time;
        m->max_packet_processing_time_us = max_time;
    }
    
    // Throughput calculations
    if (m->total_processing_time_us > 0) {
        m->packets_per_second = (m->total_packets_processed * 1000000.0) / m->total_processing_time_us;
        m->bytes_per_second = (m->total_bytes_processed * 1000000.0) / m->total_processing_time_us;
        m->windows_per_second = (m->total_windows_generated * 1000000.0) / m->total_processing_time_us;
    }
    
    // CPU calculations
    m->cpu_user_time_ms = timeval_diff_us(&test->start_usage.ru_utime, &test->end_usage.ru_utime) / 1000.0;
    m->cpu_system_time_ms = timeval_diff_us(&test->start_usage.ru_stime, &test->end_usage.ru_stime) / 1000.0;
    m->cpu_total_time_ms = m->cpu_user_time_ms + m->cpu_system_time_ms;
    m->cpu_utilization_percent = get_cpu_utilization(&test->start_usage, &test->end_usage, m->total_processing_time_us);
    
    // Memory calculations
    m->peak_memory_kb = test->peak_memory_kb;
    m->memory_delta_kb = test->peak_memory_kb - test->initial_memory_kb;
    
    // System metrics
    m->context_switches = test->end_usage.ru_nvcsw - test->start_usage.ru_nvcsw + 
                         test->end_usage.ru_nivcsw - test->start_usage.ru_nivcsw;
}

bool run_performance_test(performance_test_t *test) {
    if (!test || !test->analyzer) return false;
    
    printf("[PERF] Starting performance test: %s\n", test->config.test_name);
    printf("[PERF] Configuration: %d packets, window=%d, queue=%d\n", 
           test->config.num_packets, test->config.window_size, test->config.queue_capacity);
    
    start_performance_monitoring(test);
    
    // Generate and process packets
    for (int i = 0; i < test->config.num_packets; i++) {
        struct timeval packet_start, packet_end;
        gettimeofday(&packet_start, NULL);
        
        // Generate packet
        int packet_size = test->config.min_packet_size + 
                         (rand() % (test->config.max_packet_size - test->config.min_packet_size + 1));
        packet_info_t packet = generate_test_packet(i, packet_size, test->config.simulate_realistic_traffic);
        
        // Process packet
        flow_features_t features;
        bool window_ready = process_packet(test->analyzer, &packet, &features);
        
        gettimeofday(&packet_end, NULL);
        
        // Record timing
        if (test->packet_times_count < test->packet_times_capacity) {
            test->packet_times_us[test->packet_times_count++] = 
                timeval_diff_us(&packet_start, &packet_end);
        }
        
        // Update metrics
        test->metrics.total_packets_processed++;
        test->metrics.total_bytes_processed += packet_size;
        
        if (window_ready) {
            test->metrics.total_windows_generated++;
            
            // Send event if using event system
            if (test->config.use_events && test->event_system) {
                struct timeval event_start, event_end;
                gettimeofday(&event_start, NULL);
                
                if (broadcast_window_event(test->event_system, i, &features, "perf_test") == 0) {
                    test->metrics.events_sent++;
                    
                    gettimeofday(&event_end, NULL);
                    double event_latency = timeval_diff_us(&event_start, &event_end);
                    
                    // Update average event latency
                    if (test->metrics.events_sent == 1) {
                        test->metrics.avg_event_latency_us = event_latency;
                    } else {
                        test->metrics.avg_event_latency_us = 
                            (test->metrics.avg_event_latency_us * 0.9) + (event_latency * 0.1);
                    }
                } else {
                    test->metrics.processing_errors++;
                }
            }
        }
        
        // Update peak memory
        long current_memory = get_current_memory_kb();
        if (current_memory > test->peak_memory_kb) {
            test->peak_memory_kb = current_memory;
        }
        
        // Progress indication
        if (test->config.verbose_output && i % (test->config.num_packets / 20) == 0) {
            print_progress_bar(i, test->config.num_packets, "Processing");
        }
        
        // Simulate packet arrival rate
        if (test->config.packet_rate_us > 0) {
            usleep(test->config.packet_rate_us);
        }
    }
    
    stop_performance_monitoring(test);
    
    if (test->config.verbose_output) {
        print_progress_bar(test->config.num_packets, test->config.num_packets, "Processing");
        printf("\n");
    }
    
    printf("[PERF] Test completed successfully\n");
    return true;
}

void print_progress_bar(int current, int total, const char *label) {
    int width = 50;
    int progress = (int)((double)current / total * width);
    
    printf("\r[PERF] %s: [", label);
    for (int i = 0; i < width; i++) {
        if (i < progress) printf("█");
        else printf("░");
    }
    printf("] %d/%d (%.1f%%)", current, total, (double)current / total * 100.0);
    fflush(stdout);
}

const char* format_throughput(double value, char *buffer, size_t size) {
    if (value >= 1000000.0) {
        snprintf(buffer, size, "%.2fM", value / 1000000.0);
    } else if (value >= 1000.0) {
        snprintf(buffer, size, "%.2fK", value / 1000.0);
    } else {
        snprintf(buffer, size, "%.2f", value);
    }
    return buffer;
}

const char* format_memory(long kb, char *buffer, size_t size) {
    if (kb >= 1024 * 1024) {
        snprintf(buffer, size, "%.2f GB", kb / (1024.0 * 1024.0));
    } else if (kb >= 1024) {
        snprintf(buffer, size, "%.2f MB", kb / 1024.0);
    } else {
        snprintf(buffer, size, "%ld KB", kb);
    }
    return buffer;
}

void print_performance_summary(const performance_test_t *test) {
    const performance_metrics_t *m = &test->metrics;
    char buffer[64];
    
    printf("\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("              PERFORMANCE TEST SUMMARY\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("Test: %s\n", test->config.test_name);
    printf("\n");
    
    printf("THROUGHPUT METRICS:\n");
    printf("  Packets processed:     %lu\n", m->total_packets_processed);
    printf("  Bytes processed:       %s\n", format_throughput(m->total_bytes_processed, buffer, sizeof(buffer)));
    printf("  Windows generated:     %lu\n", m->total_windows_generated);
    printf("  Packets/sec:           %s pps\n", format_throughput(m->packets_per_second, buffer, sizeof(buffer)));
    printf("  Bytes/sec:             %s Bps\n", format_throughput(m->bytes_per_second, buffer, sizeof(buffer)));
    printf("  Windows/sec:           %.2f wps\n", m->windows_per_second);
    printf("\n");
    
    printf("TIMING METRICS:\n");
    printf("  Total processing time: %.2f ms\n", m->total_processing_time_us / 1000.0);
    printf("  Avg packet time:       %.2f μs\n", m->avg_packet_processing_time_us);
    printf("  Min packet time:       %.2f μs\n", m->min_packet_processing_time_us);
    printf("  Max packet time:       %.2f μs\n", m->max_packet_processing_time_us);
    printf("\n");
    
    printf("RESOURCE USAGE:\n");
    printf("  CPU user time:         %.2f ms\n", m->cpu_user_time_ms);
    printf("  CPU system time:       %.2f ms\n", m->cpu_system_time_ms);
    printf("  CPU utilization:       %.2f%%\n", m->cpu_utilization_percent);
    printf("  Peak memory:           %s\n", format_memory(m->peak_memory_kb, buffer, sizeof(buffer)));
    printf("  Memory growth:         %s\n", format_memory(m->memory_delta_kb, buffer, sizeof(buffer)));
    printf("  Context switches:      %lu\n", m->context_switches);
    printf("\n");
    
    if (test->config.use_events && m->events_sent > 0) {
        printf("EVENT SYSTEM METRICS:\n");
        printf("  Events sent:           %lu\n", m->events_sent);
        printf("  Avg event latency:     %.2f μs\n", m->avg_event_latency_us);
        printf("\n");
    }
    
    if (m->processing_errors > 0 || m->dropped_packets > 0) {
        printf("ERROR METRICS:\n");
        printf("  Processing errors:     %lu\n", m->processing_errors);
        printf("  Dropped packets:       %lu\n", m->dropped_packets);
        printf("\n");
    }
    
    printf("════════════════════════════════════════════════════════════\n");
}

// Predefined configurations
performance_config_t get_basic_performance_config(void) {
    performance_config_t config = {0};
    config.num_packets = 10000;
    config.window_size = 10;
    config.queue_capacity = 100;
    config.use_events = false;
    config.verbose_output = true;
    config.test_name = "Basic Performance Test";
    config.min_packet_size = 64;
    config.max_packet_size = 1500;
    config.packet_rate_us = 0;
    config.simulate_realistic_traffic = false;
    config.simulate_attack_patterns = false;
    config.test_concurrent_flows = false;
    return config;
}

performance_config_t get_high_throughput_config(void) {
    performance_config_t config = get_basic_performance_config();
    config.num_packets = 100000;
    config.window_size = 5;
    config.queue_capacity = 1000;
    config.test_name = "High Throughput Test";
    config.packet_rate_us = 0; // Maximum speed
    return config;
}

performance_config_t get_low_latency_config(void) {
    performance_config_t config = get_basic_performance_config();
    config.num_packets = 1000;
    config.window_size = 3;
    config.queue_capacity = 50;
    config.test_name = "Low Latency Test";
    config.min_packet_size = 64;
    config.max_packet_size = 128;
    config.simulate_realistic_traffic = true;
    return config;
}

performance_config_t get_event_system_config(void) {
    performance_config_t config = get_basic_performance_config();
    config.num_packets = 5000;
    config.use_events = true;
    config.test_name = "Event System Performance Test";
    return config;
}
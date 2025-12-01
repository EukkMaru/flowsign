#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include "performance_test.h"

static volatile bool running = true;

void signal_handler(int sig) {
    (void)sig;
    printf("\n[BENCHMARK] Interrupted, finishing current test...\n");
    running = false;
}

void run_benchmark_suite(void) {
    printf("════════════════════════════════════════════════════════════\n");
    printf("              SNORTSHARP PERFORMANCE BENCHMARK\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("\n");
    
    // Test 1: Basic Performance
    printf("TEST 1: Basic Performance Baseline\n");
    printf("───────────────────────────────────\n");
    performance_config_t basic_config = get_basic_performance_config();
    performance_test_t *basic_test = create_performance_test(&basic_config);
    
    if (basic_test && running) {
        if (run_performance_test(basic_test)) {
            print_performance_summary(basic_test);
        }
        destroy_performance_test(basic_test);
    }
    
    if (!running) return;
    
    // Test 2: High Throughput
    printf("\nTEST 2: High Throughput Stress Test\n");
    printf("────────────────────────────────────\n");
    performance_config_t throughput_config = get_high_throughput_config();
    performance_test_t *throughput_test = create_performance_test(&throughput_config);
    
    if (throughput_test && running) {
        if (run_performance_test(throughput_test)) {
            print_performance_summary(throughput_test);
        }
        destroy_performance_test(throughput_test);
    }
    
    if (!running) return;
    
    // Test 3: Low Latency
    printf("\nTEST 3: Low Latency Optimization Test\n");
    printf("──────────────────────────────────────\n");
    performance_config_t latency_config = get_low_latency_config();
    performance_test_t *latency_test = create_performance_test(&latency_config);
    
    if (latency_test && running) {
        if (run_performance_test(latency_test)) {
            print_performance_summary(latency_test);
        }
        destroy_performance_test(latency_test);
    }
    
    if (!running) return;
    
    // Test 4: Memory Stress Test
    printf("\nTEST 4: Memory Usage Analysis\n");
    printf("──────────────────────────────\n");
    performance_config_t memory_config = get_basic_performance_config();
    memory_config.num_packets = 50000;
    memory_config.queue_capacity = 5000;
    memory_config.window_size = 100;
    memory_config.test_name = "Memory Stress Test";
    performance_test_t *memory_test = create_performance_test(&memory_config);
    
    if (memory_test && running) {
        if (run_performance_test(memory_test)) {
            print_performance_summary(memory_test);
        }
        destroy_performance_test(memory_test);
    }
    
    if (!running) return;
    
    // Test 5: Event System Performance (if libuv available)
    printf("\nTEST 5: Event System Performance\n");
    printf("─────────────────────────────────\n");
    
    // Check if libuv is available by trying to create event system
    event_system_t *test_event_sys = create_event_system("/tmp/snortsharp_perf_test", false);
    if (test_event_sys) {
        destroy_event_system(test_event_sys);
        
        performance_config_t event_config = get_event_system_config();
        performance_test_t *event_test = create_performance_test(&event_config);
        
        if (event_test && running) {
            if (run_performance_test(event_test)) {
                print_performance_summary(event_test);
            }
            destroy_performance_test(event_test);
        }
    } else {
        printf("[BENCHMARK] libuv not available, skipping event system test\n");
        printf("Install libuv-dev to enable event system performance testing\n");
    }
    
    printf("\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("              BENCHMARK SUITE COMPLETED\n");
    printf("════════════════════════════════════════════════════════════\n");
}

void run_comparative_benchmark(void) {
    printf("════════════════════════════════════════════════════════════\n");
    printf("           COMPARATIVE PERFORMANCE ANALYSIS\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("\n");
    
    // Test different window sizes
    printf("WINDOW SIZE COMPARISON:\n");
    printf("─────────────────────\n");
    
    int window_sizes[] = {5, 10, 20, 50, 100};
    int num_window_tests = sizeof(window_sizes) / sizeof(window_sizes[0]);
    
    for (int i = 0; i < num_window_tests && running; i++) {
        performance_config_t config = get_basic_performance_config();
        config.window_size = window_sizes[i];
        config.num_packets = 20000;
        config.verbose_output = false;
        
        char test_name[64];
        snprintf(test_name, sizeof(test_name), "Window Size %d", window_sizes[i]);
        config.test_name = test_name;
        
        performance_test_t *test = create_performance_test(&config);
        if (test) {
            printf("Testing window size %d... ", window_sizes[i]);
            fflush(stdout);
            
            if (run_performance_test(test)) {
                printf("%.2f μs/packet, %.0f pps\n", 
                       test->metrics.avg_packet_processing_time_us,
                       test->metrics.packets_per_second);
            } else {
                printf("FAILED\n");
            }
            
            destroy_performance_test(test);
        }
    }
    
    printf("\n");
    
    // Test different queue capacities
    printf("QUEUE CAPACITY COMPARISON:\n");
    printf("────────────────────────\n");
    
    int capacities[] = {50, 100, 500, 1000, 5000};
    int num_capacity_tests = sizeof(capacities) / sizeof(capacities[0]);
    
    for (int i = 0; i < num_capacity_tests && running; i++) {
        performance_config_t config = get_basic_performance_config();
        config.queue_capacity = capacities[i];
        config.num_packets = 20000;
        config.verbose_output = false;
        
        char test_name[64];
        snprintf(test_name, sizeof(test_name), "Queue Capacity %d", capacities[i]);
        config.test_name = test_name;
        
        performance_test_t *test = create_performance_test(&config);
        if (test) {
            printf("Testing queue capacity %d... ", capacities[i]);
            fflush(stdout);
            
            if (run_performance_test(test)) {
                char mem_buffer[32];
                printf("%.2f μs/packet, %s peak memory\n", 
                       test->metrics.avg_packet_processing_time_us,
                       format_memory(test->metrics.peak_memory_kb, mem_buffer, sizeof(mem_buffer)));
            } else {
                printf("FAILED\n");
            }
            
            destroy_performance_test(test);
        }
    }
    
    printf("\n");
    printf("════════════════════════════════════════════════════════════\n");
}

void run_stress_test(void) {
    printf("════════════════════════════════════════════════════════════\n");
    printf("                 STRESS TEST SUITE\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("\n");
    
    printf("WARNING: This test will push the system to its limits\n");
    printf("Press Ctrl+C to interrupt if system becomes unresponsive\n");
    printf("Starting in 3 seconds...\n");
    
    for (int i = 3; i > 0 && running; i--) {
        printf("%d... ", i);
        fflush(stdout);
        sleep(1);
    }
    printf("\n\n");
    
    if (!running) return;
    
    // Extreme throughput test
    printf("EXTREME THROUGHPUT TEST:\n");
    printf("──────────────────────\n");
    performance_config_t extreme_config = get_high_throughput_config();
    extreme_config.num_packets = 1000000; // 1M packets
    extreme_config.window_size = 3;
    extreme_config.queue_capacity = 10000;
    extreme_config.test_name = "Extreme Throughput Stress Test";
    extreme_config.verbose_output = true;
    
    performance_test_t *extreme_test = create_performance_test(&extreme_config);
    if (extreme_test && running) {
        printf("Processing 1,000,000 packets...\n");
        if (run_performance_test(extreme_test)) {
            print_performance_summary(extreme_test);
        }
        destroy_performance_test(extreme_test);
    }
    
    printf("\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("                STRESS TEST COMPLETED\n");
    printf("════════════════════════════════════════════════════════════\n");
}

void print_system_info(void) {
    printf("SYSTEM INFORMATION:\n");
    printf("─────────────────\n");
    
    // CPU info
    FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo) {
        char line[256];
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (strncmp(line, "model name", 10) == 0) {
                printf("CPU: %s", strchr(line, ':') + 2);
                break;
            }
        }
        fclose(cpuinfo);
    }
    
    // Memory info
    FILE *meminfo = fopen("/proc/meminfo", "r");
    if (meminfo) {
        char line[256];
        while (fgets(line, sizeof(line), meminfo)) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                printf("Memory: %s", strchr(line, ':') + 2);
                break;
            }
        }
        fclose(meminfo);
    }
    
    // Compiler info
    printf("Compiler: GCC %s\n", __VERSION__);
    printf("Build flags: -O2 -std=gnu99\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Seed random number generator
    srand(time(NULL));
    
    print_system_info();
    
    if (argc < 2) {
        printf("Usage: %s <test_type>\n", argv[0]);
        printf("\nAvailable tests:\n");
        printf("  benchmark  - Complete benchmark suite\n");
        printf("  compare    - Comparative analysis (window sizes, queue capacities)\n");
        printf("  stress     - Stress test with extreme loads\n");
        printf("  basic      - Single basic performance test\n");
        printf("  throughput - High throughput test only\n");
        printf("  latency    - Low latency test only\n");
        printf("  memory     - Memory usage analysis\n");
        printf("  events     - Event system performance (requires libuv)\n");
        return 1;
    }
    
    const char *test_type = argv[1];
    
    if (strcmp(test_type, "benchmark") == 0) {
        run_benchmark_suite();
    } else if (strcmp(test_type, "compare") == 0) {
        run_comparative_benchmark();
    } else if (strcmp(test_type, "stress") == 0) {
        run_stress_test();
    } else if (strcmp(test_type, "basic") == 0) {
        performance_config_t config = get_basic_performance_config();
        performance_test_t *test = create_performance_test(&config);
        if (test) {
            run_performance_test(test);
            print_performance_summary(test);
            destroy_performance_test(test);
        }
    } else if (strcmp(test_type, "throughput") == 0) {
        performance_config_t config = get_high_throughput_config();
        performance_test_t *test = create_performance_test(&config);
        if (test) {
            run_performance_test(test);
            print_performance_summary(test);
            destroy_performance_test(test);
        }
    } else if (strcmp(test_type, "latency") == 0) {
        performance_config_t config = get_low_latency_config();
        performance_test_t *test = create_performance_test(&config);
        if (test) {
            run_performance_test(test);
            print_performance_summary(test);
            destroy_performance_test(test);
        }
    } else if (strcmp(test_type, "memory") == 0) {
        performance_config_t config = get_basic_performance_config();
        config.num_packets = 100000;
        config.queue_capacity = 10000;
        config.window_size = 100;
        config.test_name = "Memory Analysis Test";
        performance_test_t *test = create_performance_test(&config);
        if (test) {
            run_performance_test(test);
            print_performance_summary(test);
            destroy_performance_test(test);
        }
    } else if (strcmp(test_type, "events") == 0) {
        performance_config_t config = get_event_system_config();
        performance_test_t *test = create_performance_test(&config);
        if (test) {
            run_performance_test(test);
            print_performance_summary(test);
            destroy_performance_test(test);
        } else {
            printf("Error: Could not create event system test (libuv not available?)\n");
            return 1;
        }
    } else {
        printf("Unknown test type: %s\n", test_type);
        return 1;
    }
    
    return 0;
}
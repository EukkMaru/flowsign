#include <iostream>
#include <memory>
#include <csignal>
#include <unistd.h>
#include <sys/time.h>
#include <atomic>
#include <iomanip>
#include "flow_rules.hpp"
#include "event_system.hpp"

static std::atomic<bool> running{true};
static EventSystem* event_sys = nullptr;
static FlowRuleEngine* rule_engine = nullptr;

void signal_handler(int sig) {
    (void)sig;
    std::cout << "\n[PROC2] Shutting down..." << std::endl;
    running = false;
}

void process_window_event(const WindowEvent& event, void* user_data) {
    (void)user_data;
    
    if(event.type == EventType::SHUTDOWN) {
        std::cout << "[PROC2] Received shutdown event from " 
                  << event.source_process << std::endl;
        running = false;
        return;
    }
    
    if(event.type != EventType::WINDOW_UPDATE) {
        return;
    }
    
    std::cout << "\n[PROC2] *** RECEIVED WINDOW EVENT ***" << std::endl;
    std::cout << "[PROC2] Flow ID: " << event.flow_id 
              << ", Source: " << event.source_process << std::endl;
    std::cout << "[PROC2] Timestamp: " << event.timestamp.tv_sec 
              << "." << std::setw(6) << std::setfill('0') 
              << event.timestamp.tv_usec << std::endl;
    
    // Extract features from event
    const FlowFeatures& features = event.features;
    
    std::cout << "[PROC2] Flow Features:" << std::endl;
    std::cout << "  - Duration: " << (features.flow_duration / 1000.0) << " ms" << std::endl;
    std::cout << "  - Total packets: " << (features.total_fwd_packets + features.total_bwd_packets) 
              << ", Total bytes: " << (features.total_fwd_bytes + features.total_bwd_bytes) << std::endl;
    std::cout << "  - Forward: packets=" << features.total_fwd_packets 
              << ", bytes=" << features.total_fwd_bytes 
              << ", avg_len=" << features.fwd_packet_length_mean << std::endl;
    std::cout << "  - Backward: packets=" << features.total_bwd_packets 
              << ", bytes=" << features.total_bwd_bytes 
              << ", avg_len=" << features.bwd_packet_length_mean << std::endl;
    std::cout << "  - IAT mean: " << features.flow_iat_mean 
              << " us, IAT std: " << features.flow_iat_std << " us" << std::endl;
    std::cout << "  - TCP flags: SYN=" << features.syn_flag_count 
              << ", ACK=" << features.ack_flag_count
              << ", FIN=" << features.fin_flag_count 
              << ", PSH=" << features.psh_flag_count << std::endl;
    
    // Run rule engine on the features
    std::cout << "[PROC2] Running rule engine analysis..." << std::endl;
    
    rule_engine->process_flow_features(features);
    
    // Check for alerts
    FlowAlert alert{};
    int alert_count = 0;
    while(rule_engine->get_next_alert(alert)) {
        alert_count++;
        if(alert_count == 1) {
            std::cout << "[PROC2] *** ALERT: Rule matches detected! ***" << std::endl;
        }
        std::cout << "[PROC2] ALERT: Rule ID " << alert.rule_id 
                  << " - " << alert.message << std::endl;
        std::cout << "         Confidence: " << alert.confidence << std::endl;
    }
    
    if(alert_count == 0) {
        std::cout << "[PROC2] No rule matches - traffic appears normal" << std::endl;
    } else {
        std::cout << "[PROC2] Total alerts: " << alert_count << std::endl;
    }
    
    std::cout << "[PROC2] Event processing complete" << std::endl;
}

void create_sample_rules(FlowRuleEngine& engine) {
    std::cout << "[PROC2] Creating sample flow detection rules..." << std::endl;
    
    FlowRuleset* ruleset = engine.get_ruleset();
    
    // Rule 1: Port scan detection (fast IAT + multiple SYN flags)
    ruleset->add_rule_from_string("sid:1001 msg:\"Port Scan Detected\" flow_iat_mean < 1000 AND syn_flag_count > 3");
    
    // Rule 2: Large file transfer detection
    ruleset->add_rule_from_string("sid:1002 msg:\"Large File Transfer\" fwd_packet_length_mean > 1200 AND flow_bytes_per_sec > 1000000");
    
    // Rule 3: DoS attack detection (many packets, low bytes per packet)
    ruleset->add_rule_from_string("sid:1003 msg:\"Potential DoS Attack\" fwd_packets > 10 AND fwd_packet_length_mean < 100");
    
    // Rule 4: Suspicious flow timing
    ruleset->add_rule_from_string("sid:1004 msg:\"Suspicious Flow Timing\" flow_iat_std > 5000 OR flow_iat_min < 100");
    
    // Rule 5: Asymmetric flow (potential data exfiltration)
    ruleset->add_rule_from_string("sid:1005 msg:\"Asymmetric Flow Pattern\" down_up_ratio > 10");
    
    std::cout << "[PROC2] Created " << ruleset->get_rule_count() << " flow detection rules" << std::endl;
    
    // Print loaded rules
    std::cout << "[PROC2] Loaded rules:" << std::endl;
    ruleset->print_ruleset();
}

int main() {
    std::cout << "[PROC2] Rule Engine Process - Event Listener Demo" << std::endl;
    std::cout << "===============================================" << std::endl;
    
    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create rule engine
    auto rule_eng = std::make_unique<FlowRuleEngine>(50);  // Alert capacity of 50
    rule_engine = rule_eng.get();
    
    // Create sample rules
    create_sample_rules(*rule_engine);
    
    // Start rule engine thread
    if(!rule_engine->start_engine_thread()) {
        std::cerr << "[PROC2] Failed to start rule engine thread" << std::endl;
        return 1;
    }
    
    // Create event system (server)
    auto event_system = std::make_unique<EventSystem>("/tmp/snortsharp_events", true);
    event_sys = event_system.get();
    
    // Start event server
    std::cout << "[PROC2] Starting event server..." << std::endl;
    if(event_system->start_event_server(process_window_event, nullptr) != 0) {
        std::cerr << "[PROC2] Failed to start event server" << std::endl;
        return 1;
    }
    
    std::cout << "[PROC2] Event server started, waiting for window events from proc1..." << std::endl;
    std::cout << "[PROC2] Press Ctrl+C to stop" << std::endl << std::endl;
    
    // Main event loop - just wait for events
    while(running) {
        usleep(100000); // 100ms
    }
    
    // Print final statistics
    std::cout << "\n[PROC2] Final Rule Statistics:" << std::endl;
    std::cout << "===============================================" << std::endl;
    rule_engine->get_ruleset()->print_rule_stats();
    
    // Print engine statistics
    std::cout << "\n[PROC2] Engine Statistics:" << std::endl;
    std::cout << "  Total evaluations: " << rule_engine->get_total_evaluations() << std::endl;
    std::cout << "  Total matches: " << rule_engine->get_total_matches() << std::endl;
    std::cout << "  Features processed: " << rule_engine->get_total_features_processed() << std::endl;
    
    // Cleanup
    event_system->stop_event_server();
    rule_engine->stop_engine_thread();
    
    std::cout << "[PROC2] Process 2 (Rule Engine) finished" << std::endl;
    return 0;
}
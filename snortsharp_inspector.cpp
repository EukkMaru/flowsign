#include "snortsharp_inspector.hpp"
#include "snortsharp_integration.hpp"
#include <iostream>
#include <chrono>

// Snort3 includes
#include "snort3/src/framework/inspector.h"
#include "snort3/src/framework/module.h"
#include "snort3/src/detection/detection_engine.h"
#include "snort3/src/managers/inspector_manager.h"

SnortSharpInspector::SnortSharpInspector() 
    : initialized_(false)
    , window_size_(50)
    , queue_capacity_(1000) 
    , alert_capacity_(500)
    , rules_file_("snortsharp_rules.txt") {
}

SnortSharpInspector::~SnortSharpInspector() {
    shutdown();
}

void SnortSharpInspector::set_parameters(uint32_t window_size, uint32_t queue_capacity,
                                        uint32_t alert_capacity, const std::string& rules_file) {
    window_size_ = window_size;
    queue_capacity_ = queue_capacity;
    alert_capacity_ = alert_capacity;
    rules_file_ = rules_file;

    std::cout << "[SnortSharp Inspector] Parameters set:\n";
    std::cout << "  window_size = " << window_size_ << "\n";
    std::cout << "  queue_capacity = " << queue_capacity_ << "\n";
    std::cout << "  alert_capacity = " << alert_capacity_ << "\n";
    std::cout << "  rules_file = " << rules_file_ << "\n";
}

bool SnortSharpInspector::configure(snort::SnortConfig* /* config */) {
    std::cout << "[SnortSharp] Configuring inspector with parameters:\n";
    std::cout << "  Window Size: " << window_size_ << "\n";
    std::cout << "  Queue Capacity: " << queue_capacity_ << "\n"; 
    std::cout << "  Alert Capacity: " << alert_capacity_ << "\n";
    std::cout << "  Rules File: " << rules_file_ << "\n";
    
    initialize_engine();
    return initialized_.load();
}

void SnortSharpInspector::show(const snort::SnortConfig* /* config */) const {
    std::cout << "\n=== SnortSharp Inspector Configuration ===\n";
    std::cout << "Window Size: " << window_size_ << "\n";
    std::cout << "Queue Capacity: " << queue_capacity_ << "\n";
    std::cout << "Alert Capacity: " << alert_capacity_ << "\n";
    std::cout << "Rules File: " << rules_file_ << "\n";
    std::cout << "Initialized: " << (initialized_.load() ? "Yes" : "No") << "\n";
    
    if(engine_ && initialized_.load()) {
        engine_->print_stats();
    }
    std::cout << "=========================================\n\n";
}

void SnortSharpInspector::eval(snort::Packet* packet) {
    if(!initialized_.load() || !engine_) {
        return;
    }
    
    // convert snort packet to our format with safe memory copying
    auto our_packet = convert_snort_packet_from_raw(packet);
    if(!our_packet) {
        return;
    }
    
    // process packet through our flow analyzer engine
    bool success = engine_->process_snort_packet(*our_packet);
    if(!success) {
        std::cerr << "[SnortSharp] Failed to process packet\n";
        return;
    }
    
    // check for new flow alerts and process them
    process_alerts();
}

bool SnortSharpInspector::block_flow(const FlowAlert& alert) {
    if(!initialized_.load()) {
        return false;
    }
    
    std::cout << "[SnortSharp] Flow blocking action requested for alert SID:" << alert.rule_id << "\n";
    std::cout << "  Message: " << alert.message << "\n";
    std::cout << "  Confidence: " << alert.confidence << "\n";
    
    // in a real implementation, this would interface with snort's active response
    // for now, we just log the blocking action
    std::cout << "  Action: BLOCK_FLOW (logged only)\n";
    
    return true;
}

void SnortSharpInspector::print_stats() const {
    if(engine_ && initialized_.load()) {
        engine_->print_stats();
    } else {
        std::cout << "[SnortSharp] Inspector not initialized or no engine available\n";
    }
}

void SnortSharpInspector::shutdown() {
    if(initialized_.load() && engine_) {
        std::cout << "[SnortSharp] Shutting down inspector...\n";
        engine_->stop();
        initialized_ = false;
        std::cout << "[SnortSharp] Inspector shutdown complete\n";
    }
}

void SnortSharpInspector::initialize_engine() {
    if(initialized_.load()) {
        return;
    }
    
    try {
        // create engine without event system for now (traditional queue mode)
        engine_ = std::make_unique<SnortSharpEngine>(window_size_, queue_capacity_, alert_capacity_);
        
        // load flow rules if rules file is specified
        if(!rules_file_.empty()) {
            std::cout << "[SnortSharp] Loading rules from: " << rules_file_ << "\n";
            if(!engine_->load_flow_rules(rules_file_)) {
                std::cout << "[SnortSharp] Warning: Could not load rules file, using default rules\n";
            }
        }
        
        // start the engine threads
        if(engine_->start()) {
            initialized_ = true;
            std::cout << "[SnortSharp] Engine initialized successfully\n";
        } else {
            std::cerr << "[SnortSharp] Failed to start engine\n";
            engine_.reset();
        }
        
    } catch(const std::exception& e) {
        std::cerr << "[SnortSharp] Failed to initialize engine: " << e.what() << "\n";
        engine_.reset();
    }
}

void SnortSharpInspector::process_alerts() {
    if(!engine_) return;
    
    FlowAlert alert;
    while(engine_->get_next_alert(alert)) {
        // print alert information
        print_flow_alert(alert);
        
        // determine if this alert requires flow blocking
        if(alert.confidence >= 0.8) {  // high confidence threshold
            block_flow(alert);
        }
    }
}

// snort3 plugin api structures
static const char* snortsharp_name = "snortsharp";
static const char* snortsharp_help = "SnortSharp flow-based intrusion detection inspector";

// module for configuration with proper parameter storage
class SnortSharpModule : public snort::Module {
public:
    SnortSharpModule()
        : snort::Module(snortsharp_name, snortsharp_help)
        , window_size(50)
        , queue_capacity(1000)
        , alert_capacity(500)
        , rules_file("snortsharp_rules.txt") {}

    bool set(const char* fqn, snort::Value& val, snort::SnortConfig* /* sc */) override {
        if (!fqn) {
            return false;
        }

        std::string param_name(fqn);

        // Parse the parameter name (remove module prefix if present)
        size_t dot_pos = param_name.find_last_of('.');
        if (dot_pos != std::string::npos) {
            param_name = param_name.substr(dot_pos + 1);
        }

        // Set the appropriate parameter based on name
        if (param_name == "window_size") {
            window_size = val.get_uint32();
            std::cout << "[SnortSharp Module] Set window_size = " << window_size << "\n";
            return true;
        }
        else if (param_name == "queue_capacity") {
            queue_capacity = val.get_uint32();
            std::cout << "[SnortSharp Module] Set queue_capacity = " << queue_capacity << "\n";
            return true;
        }
        else if (param_name == "alert_capacity") {
            alert_capacity = val.get_uint32();
            std::cout << "[SnortSharp Module] Set alert_capacity = " << alert_capacity << "\n";
            return true;
        }
        else if (param_name == "rules_file") {
            rules_file = val.get_string();
            std::cout << "[SnortSharp Module] Set rules_file = " << rules_file << "\n";
            return true;
        }

        return false;
    }

    // Configuration parameters (accessed by inspector during construction)
    uint32_t window_size;
    uint32_t queue_capacity;
    uint32_t alert_capacity;
    std::string rules_file;
};

// inspector creation function
static snort::Inspector* snortsharp_ctor(snort::Module* mod) {
    SnortSharpModule* config_module = dynamic_cast<SnortSharpModule*>(mod);
    if (!config_module) {
        std::cerr << "[SnortSharp] ERROR: Invalid module passed to constructor\n";
        return new SnortSharpInspector(); // Fallback to defaults
    }

    // Create inspector with parameters from module
    auto inspector = new SnortSharpInspector();
    inspector->set_parameters(
        config_module->window_size,
        config_module->queue_capacity,
        config_module->alert_capacity,
        config_module->rules_file
    );

    return inspector;
}

static void snortsharp_dtor(snort::Inspector* p) {
    delete p;
}

// module creation/destruction for Snort3
static snort::Module* snortsharp_mod_ctor() {
    return new SnortSharpModule();
}

static void snortsharp_mod_dtor(snort::Module* m) {
    delete m;
}

// plugin api structure
const snort::InspectApi snortsharp_api = {
    {
        PT_INSPECTOR,
        sizeof(snort::InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        nullptr, // API_OPTIONS - not used for now
        snortsharp_name,
        snortsharp_help,
        snortsharp_mod_ctor,  // Register module constructor
        snortsharp_mod_dtor   // Register module destructor
    },
    snort::IT_NETWORK,  // inspect network packets
    PROTO_BIT__TCP | PROTO_BIT__UDP,  // inspect TCP and UDP traffic
    nullptr,  // buffers - not used
    nullptr,  // service - not used
    nullptr,  // pinit - not used
    nullptr,  // pterm - not used
    nullptr,  // tinit - not used
    nullptr,  // tterm - not used
    snortsharp_ctor,
    snortsharp_dtor,
    nullptr,  // ssn - not used
    nullptr   // reset - not used
};
#ifndef SNORTSHARP_INSPECTOR_HPP
#define SNORTSHARP_INSPECTOR_HPP

#include "snortsharp_integration.hpp"
#include "snort3/src/framework/inspector.h"
#include <memory>
#include <atomic>

namespace snort {
    struct Packet;
}

class SnortSharpInspector : public snort::Inspector {
private:
    std::unique_ptr<SnortSharpEngine> engine_;
    std::atomic<bool> initialized_;
    
    // Configuration parameters
    int window_size_;
    int queue_capacity_;
    int alert_capacity_;
    std::string rules_file_;

public:
    SnortSharpInspector();
    ~SnortSharpInspector() override;
    
    // Disable copy constructor and assignment
    SnortSharpInspector(const SnortSharpInspector&) = delete;
    SnortSharpInspector& operator=(const SnortSharpInspector&) = delete;
    
    // Inspector interface implementation
    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    
    // Packet processing - this is where we intercept packets from Snort
    void eval(snort::Packet* packet) override;
    
    // Flow-based blocking actions
    bool block_flow(const FlowAlert& alert);

    // Configuration setter (called by module during construction)
    void set_parameters(uint32_t window_size, uint32_t queue_capacity,
                       uint32_t alert_capacity, const std::string& rules_file);

    // Statistics and management
    void print_stats() const;
    void shutdown();
    
private:
    void initialize_engine();
    void process_alerts();
};

// Plugin API structures for Snort3 integration
extern const snort::InspectApi snortsharp_api;

#endif // SNORTSHARP_INSPECTOR_HPP
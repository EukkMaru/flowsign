#ifndef SNORT3_SNORTSHARP_BRIDGE_HPP
#define SNORT3_SNORTSHARP_BRIDGE_HPP

// snort3 + snortsharp integration bridge
// this header allows snort3 to pass packets to snortsharp parallel system

// forward declaration to avoid full snort3 headers
namespace snort {
    struct Packet;
}

// snortsharp integration interface
class SnortSharpBridge {
public:
    static bool initialize();
    static void shutdown();
    static void process_packet_from_snort3(const snort::Packet* snort_packet);
    static bool is_initialized();
    
private:
    static bool initialized_;
};

#endif // SNORT3_SNORTSHARP_BRIDGE_HPP
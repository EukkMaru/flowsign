#include "flow_rules.hpp"
#include <iostream>

int main() {
    FlowRuleset ruleset;
    
    // Test with a simple rule (should work)
    std::string simple_rule = "sid:5000 msg:\"Test\" bwd_packet_length_mean <= 75.50 AND fwd_packet_length_mean <= 131.50";
    std::cout << "Testing simple rule (2 conditions):" << std::endl;
    if(ruleset.add_rule_from_string(simple_rule)) {
        std::cout << "  ✓ PARSED SUCCESSFULLY" << std::endl;
        ruleset.print_ruleset();
    } else {
        std::cout << "  ✗ FAILED TO PARSE" << std::endl;
    }
    
    // Test with medium rule (10 conditions - at the limit)
    std::string medium_rule = "sid:5001 msg:\"Test\" bwd_packet_length_mean <= 75.50 AND fwd_packet_length_mean <= 131.50 AND bwd_packets <= 34.50 AND fwd_iat_mean <= 8606.62 AND fwd_packet_length_mean <= 45.50 AND flow_iat_std <= 1771.00 AND fwd_bytes <= 855.00 AND fwd_bytes <= 89.50 AND fwd_bytes <= 81.50 AND flow_duration <= 0.000008";
    std::cout << "\nTesting medium rule (10 conditions):" << std::endl;
    if(ruleset.add_rule_from_string(medium_rule)) {
        std::cout << "  ✓ PARSED SUCCESSFULLY" << std::endl;
        std::cout << "  Condition count: " << ruleset.get_rule(1)->conditions.size() << std::endl;
    } else {
        std::cout << "  ✗ FAILED TO PARSE" << std::endl;
    }
    
    // Test with complex rule (13 conditions - the failing one)
    std::string complex_rule = "sid:5002 msg:\"Test\" bwd_packet_length_mean <= 75.50 AND fwd_packet_length_mean <= 131.50 AND bwd_packets <= 34.50 AND fwd_iat_mean <= 8606.62 AND fwd_packet_length_mean <= 45.50 AND flow_iat_std <= 1771.00 AND fwd_bytes <= 855.00 AND fwd_bytes <= 89.50 AND fwd_bytes <= 81.50 AND flow_duration <= 0.000008 AND flow_bytes_per_sec <= 64000000 AND flow_bytes_per_sec <= 57200000 AND fwd_iat_mean > 0.01";
    std::cout << "\nTesting complex rule (13 conditions):" << std::endl;
    if(ruleset.add_rule_from_string(complex_rule)) {
        std::cout << "  ✓ PARSED SUCCESSFULLY" << std::endl;
        std::cout << "  Condition count: " << ruleset.get_rule(2)->conditions.size() << std::endl;
    } else {
        std::cout << "  ✗ FAILED TO PARSE" << std::endl;
    }
    
    return 0;
}

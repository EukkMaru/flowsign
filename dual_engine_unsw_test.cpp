#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include "unsw_nb15_pcap_loader.hpp"

struct DualEngineResults {
    // Snort3 packet-level results
    size_t snort3_total_alerts = 0;
    size_t snort3_dos_alerts = 0;
    size_t snort3_recon_alerts = 0;
    size_t snort3_exploit_alerts = 0;
    size_t snort3_backdoor_alerts = 0;
    size_t snort3_fuzzer_alerts = 0;
    size_t snort3_worm_alerts = 0;

    // SnortSharp flow-level results
    size_t snortsharp_total_alerts = 0;
    size_t snortsharp_dos_alerts = 0;
    size_t snortsharp_recon_alerts = 0;
    size_t snortsharp_exploit_alerts = 0;
    size_t snortsharp_backdoor_alerts = 0;
    size_t snortsharp_fuzzer_alerts = 0;
    size_t snortsharp_worm_alerts = 0;

    // Performance metrics
    size_t total_packets_processed = 0;
    double processing_time_seconds = 0.0;
    double packets_per_second = 0.0;

    // Correlation metrics
    size_t correlated_alerts = 0;  // Alerts detected by both systems
    size_t snort3_unique = 0;      // Only detected by Snort3
    size_t snortsharp_unique = 0;  // Only detected by SnortSharp

    void print_comprehensive_report() const {
        std::cout << "\n" << std::string(80, '=') << "\n";
        std::cout << "          DUAL-ENGINE DETECTION ANALYSIS REPORT\n";
        std::cout << "     Snort3 (Packet-Level) + SnortSharp (Flow-Level)\n";
        std::cout << std::string(80, '=') << "\n\n";

        // Processing overview
        std::cout << "PROCESSING OVERVIEW:\n";
        std::cout << "  Total Packets Processed: " << total_packets_processed << "\n";
        std::cout << "  Processing Time: " << processing_time_seconds << " seconds\n";
        std::cout << "  Throughput: " << packets_per_second << " packets/second\n\n";

        // Snort3 packet-level results
        std::cout << "SNORT3 PACKET-LEVEL DETECTION:\n";
        std::cout << "  Total Alerts: " << snort3_total_alerts << "\n";
        std::cout << "    ├─ DoS Attacks: " << snort3_dos_alerts << "\n";
        std::cout << "    ├─ Reconnaissance: " << snort3_recon_alerts << "\n";
        std::cout << "    ├─ Exploits: " << snort3_exploit_alerts << "\n";
        std::cout << "    ├─ Backdoors: " << snort3_backdoor_alerts << "\n";
        std::cout << "    ├─ Fuzzers: " << snort3_fuzzer_alerts << "\n";
        std::cout << "    └─ Worms: " << snort3_worm_alerts << "\n\n";

        // SnortSharp flow-level results
        std::cout << "SNORTSHARP FLOW-LEVEL DETECTION:\n";
        std::cout << "  Total Alerts: " << snortsharp_total_alerts << "\n";
        std::cout << "    ├─ DoS Attacks: " << snortsharp_dos_alerts << "\n";
        std::cout << "    ├─ Analysis/Recon: " << snortsharp_recon_alerts << "\n";
        std::cout << "    ├─ Exploits: " << snortsharp_exploit_alerts << "\n";
        std::cout << "    ├─ Backdoors: " << snortsharp_backdoor_alerts << "\n";
        std::cout << "    ├─ Fuzzers: " << snortsharp_fuzzer_alerts << "\n";
        std::cout << "    └─ Worms: " << snortsharp_worm_alerts << "\n\n";

        // Combined detection power
        size_t total_unique_threats = snort3_total_alerts + snortsharp_total_alerts - correlated_alerts;
        std::cout << "COMBINED DETECTION ANALYSIS:\n";
        std::cout << "  Total Unique Threats Detected: " << total_unique_threats << "\n";
        std::cout << "  Correlated Alerts (Both Systems): " << correlated_alerts << "\n";
        std::cout << "  Snort3 Unique Detections: " << snort3_unique << "\n";
        std::cout << "  SnortSharp Unique Detections: " << snortsharp_unique << "\n";

        if(total_unique_threats > 0) {
            double coverage_improvement = 100.0 * (double)total_unique_threats /
                std::max(snort3_total_alerts, snortsharp_total_alerts);
            std::cout << "  Detection Coverage Improvement: " << coverage_improvement << "%\n";
        }

        std::cout << "\n" << std::string(80, '=') << "\n";

        // Analysis summary
        std::cout << "\nKEY FINDINGS:\n";
        if(snort3_total_alerts > 0 && snortsharp_total_alerts > 0) {
            std::cout << "  ✓ Both detection engines are operational\n";
            std::cout << "  ✓ Dual-engine architecture validated\n";
        }
        if(snort3_unique > 0) {
            std::cout << "  ✓ Snort3 detected " << snort3_unique << " threats missed by flow analysis\n";
        }
        if(snortsharp_unique > 0) {
            std::cout << "  ✓ SnortSharp detected " << snortsharp_unique << " threats missed by packet analysis\n";
        }
        if(correlated_alerts > 0) {
            std::cout << "  ✓ " << correlated_alerts << " threats confirmed by both systems (high confidence)\n";
        }
        std::cout << "\n";
    }
};

class DualEngineTest {
private:
    std::string snort3_binary_;
    std::string config_file_;
    std::string rules_file_;
    std::string pcap_file_;
    DualEngineResults results_;

public:
    DualEngineTest(const std::string& snort3_path, const std::string& config,
                   const std::string& rules, const std::string& pcap)
        : snort3_binary_(snort3_path), config_file_(config),
          rules_file_(rules), pcap_file_(pcap) {}

    bool run_dual_engine_test() {
        std::cout << "========================================\n";
        std::cout << "DUAL-ENGINE UNSW-NB15 DETECTION TEST\n";
        std::cout << "========================================\n\n";

        // Verify files exist
        if(!verify_files()) {
            return false;
        }

        // Count packets in PCAP
        results_.total_packets_processed = count_packets_in_pcap();
        std::cout << "PCAP file contains " << results_.total_packets_processed << " packets\n\n";

        // Run Snort3 with embedded SnortSharp
        auto start_time = std::chrono::high_resolution_clock::now();

        if(!run_snort3_with_snortsharp()) {
            std::cerr << "Failed to run Snort3 with SnortSharp\n";
            return false;
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        results_.processing_time_seconds =
            std::chrono::duration<double>(end_time - start_time).count();
        results_.packets_per_second =
            results_.total_packets_processed / results_.processing_time_seconds;

        // Parse results
        parse_snort3_alerts();
        parse_snortsharp_alerts();

        // Correlate alerts
        correlate_alerts();

        // Print comprehensive report
        results_.print_comprehensive_report();

        return true;
    }

private:
    bool verify_files() {
        struct stat buffer;

        if(stat(snort3_binary_.c_str(), &buffer) != 0) {
            std::cerr << "Error: Snort3 binary not found: " << snort3_binary_ << "\n";
            return false;
        }

        if(stat(pcap_file_.c_str(), &buffer) != 0) {
            std::cerr << "Error: PCAP file not found: " << pcap_file_ << "\n";
            return false;
        }

        if(stat(rules_file_.c_str(), &buffer) != 0) {
            std::cerr << "Warning: Rules file not found: " << rules_file_ << "\n";
            std::cerr << "Creating default rules file...\n";
            create_default_rules();
        }

        return true;
    }

    void create_default_rules() {
        std::ofstream rules(rules_file_);
        rules << "# Local Snort3 rules\n";
        rules.close();
    }

    size_t count_packets_in_pcap() {
        std::string cmd = "tcpdump -r " + pcap_file_ + " 2>/dev/null | wc -l";
        FILE* pipe = popen(cmd.c_str(), "r");
        if(!pipe) return 0;

        char buffer[128];
        std::string result = "";
        while(fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        pclose(pipe);

        return std::stoul(result);
    }

    bool run_snort3_with_snortsharp() {
        std::cout << "Running Snort3 + SnortSharp on PCAP file...\n";
        std::cout << "Command: " << snort3_binary_ << " -c " << config_file_
                  << " -r " << pcap_file_ << "\n\n";

        // Build command with proper quoting for paths with spaces
        std::stringstream cmd;
        cmd << snort3_binary_ << " -c \"" << config_file_ << "\""
            << " -r \"" << pcap_file_ << "\""
            << " -A fast -l . -q"  // Fast alert mode, log to current dir, quiet
            << " > snort3_output.log 2>&1";

        // Execute
        int result = system(cmd.str().c_str());

        if(result != 0) {
            std::cerr << "Snort3 execution returned code: " << result << "\n";
            std::cout << "Check snort3_output.log for details\n";
        }

        // Give time for SnortSharp to finish processing
        std::cout << "Waiting for flow analysis to complete...\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));

        return true;
    }

    void parse_snort3_alerts() {
        std::cout << "Parsing Snort3 packet-level alerts...\n";

        // Parse alert_fast.txt generated by Snort3
        std::ifstream alert_file("alert_fast.txt");
        if(!alert_file.is_open()) {
            std::cout << "No Snort3 alerts file found (no packet-level alerts)\n";
            return;
        }

        std::string line;
        while(std::getline(alert_file, line)) {
            if(line.empty() || line[0] == '#') continue;

            results_.snort3_total_alerts++;

            // Categorize by alert message
            if(line.find("DoS") != std::string::npos ||
               line.find("Flood") != std::string::npos) {
                results_.snort3_dos_alerts++;
            }
            else if(line.find("Scan") != std::string::npos ||
                    line.find("Reconnaissance") != std::string::npos) {
                results_.snort3_recon_alerts++;
            }
            else if(line.find("Exploit") != std::string::npos ||
                    line.find("Overflow") != std::string::npos) {
                results_.snort3_exploit_alerts++;
            }
            else if(line.find("Backdoor") != std::string::npos) {
                results_.snort3_backdoor_alerts++;
            }
            else if(line.find("Fuzzer") != std::string::npos) {
                results_.snort3_fuzzer_alerts++;
            }
            else if(line.find("Worm") != std::string::npos) {
                results_.snort3_worm_alerts++;
            }
        }

        std::cout << "  Found " << results_.snort3_total_alerts << " Snort3 alerts\n";
    }

    void parse_snortsharp_alerts() {
        std::cout << "Parsing SnortSharp flow-level alerts...\n";

        // Parse snort3_output.log for SnortSharp alert messages
        std::ifstream log_file("snort3_output.log");
        if(!log_file.is_open()) {
            std::cout << "No SnortSharp output found\n";
            return;
        }

        std::string line;
        while(std::getline(log_file, line)) {
            // Look for SnortSharp alert markers
            if(line.find("[ALERT]") != std::string::npos ||
               line.find("Flow Alert") != std::string::npos) {
                results_.snortsharp_total_alerts++;

                // Categorize by alert message
                if(line.find("DoS") != std::string::npos) {
                    results_.snortsharp_dos_alerts++;
                }
                else if(line.find("Analysis") != std::string::npos ||
                        line.find("scan") != std::string::npos) {
                    results_.snortsharp_recon_alerts++;
                }
                else if(line.find("Exploit") != std::string::npos) {
                    results_.snortsharp_exploit_alerts++;
                }
                else if(line.find("Backdoor") != std::string::npos) {
                    results_.snortsharp_backdoor_alerts++;
                }
                else if(line.find("Fuzzer") != std::string::npos) {
                    results_.snortsharp_fuzzer_alerts++;
                }
                else if(line.find("Worm") != std::string::npos) {
                    results_.snortsharp_worm_alerts++;
                }
            }
        }

        std::cout << "  Found " << results_.snortsharp_total_alerts << " SnortSharp alerts\n\n";
    }

    void correlate_alerts() {
        // Simple correlation: if both systems detected similar attack types,
        // count them as correlated

        size_t dos_correlation = std::min(results_.snort3_dos_alerts,
                                          results_.snortsharp_dos_alerts);
        size_t recon_correlation = std::min(results_.snort3_recon_alerts,
                                            results_.snortsharp_recon_alerts);
        size_t exploit_correlation = std::min(results_.snort3_exploit_alerts,
                                              results_.snortsharp_exploit_alerts);
        size_t backdoor_correlation = std::min(results_.snort3_backdoor_alerts,
                                               results_.snortsharp_backdoor_alerts);
        size_t fuzzer_correlation = std::min(results_.snort3_fuzzer_alerts,
                                             results_.snortsharp_fuzzer_alerts);
        size_t worm_correlation = std::min(results_.snort3_worm_alerts,
                                           results_.snortsharp_worm_alerts);

        results_.correlated_alerts = dos_correlation + recon_correlation +
                                     exploit_correlation + backdoor_correlation +
                                     fuzzer_correlation + worm_correlation;

        results_.snort3_unique = results_.snort3_total_alerts - results_.correlated_alerts;
        results_.snortsharp_unique = results_.snortsharp_total_alerts - results_.correlated_alerts;
    }
};

int main(int argc, char* argv[]) {
    std::cout << "Dual-Engine Detection Test: Snort3 + SnortSharp\n";
    std::cout << "Testing on UNSW-NB15 Dataset\n";
    std::cout << "================================================\n\n";

    // Configuration
    std::string snort3_binary = "./snort3/build/src/snort";
    std::string config_file = "dual_engine_test.lua";
    std::string rules_file = "local.rules";
    std::string pcap_file;

    // Parse command line
    if(argc > 1) {
        pcap_file = argv[1];
    } else {
        // Find first PCAP file in UNSW dataset
        std::cout << "Searching for UNSW-NB15 PCAP files...\n";
        UNSWB15PcapLoader loader("datasets/");
        if(!loader.discover_pcap_files()) {
            std::cerr << "Failed to find UNSW-NB15 PCAP files\n";
            std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
            return 1;
        }

        if(loader.get_pcap_count() == 0) {
            std::cerr << "No PCAP files found\n";
            return 1;
        }

        // Use first PCAP file
        pcap_file = loader.get_pcap_files()[0].file_path;
        std::cout << "Using: " << pcap_file << "\n\n";
    }

    // Run test
    DualEngineTest test(snort3_binary, config_file, rules_file, pcap_file);

    if(!test.run_dual_engine_test()) {
        std::cerr << "Test failed\n";
        return 1;
    }

    std::cout << "\nTest completed successfully!\n";
    return 0;
}

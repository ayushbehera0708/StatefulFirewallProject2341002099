#include "FirewallDaemon.h"

#include <cstdlib>
#include <iostream>
#include <string>

void printUsage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  -q, --queue-num <num>       Netfilter queue number to bind (default: 0)\n"
              << "  -r, --rules <path>          Path to L7 signature rules file (default: rules/default_rules.conf)\n"
              << "  -l, --log-file <path>       Destination file for firewall logs (default: firewall.log)\n"
              << "  -v, --log-level <level>     Log verbosity: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)\n"
              << "  -m, --max-entries <n>       Maximum concurrent conntrack entries (default: 100000)\n"
              << "  -g, --gc-interval <sec>     Conntrack garbage collection interval in seconds (default: 5)\n"
              << "  --no-strict-tcp             Allow non-SYN packets to establish new TCP state entries\n"
              << "  -h, --help                  Display this help message and exit\n\n"
              << "Author: Ayush Behera\n"
              << "Example:\n"
              << "  sudo " << prog_name << " --queue-num 0 --rules rules/default_rules.conf --log-level DEBUG\n";
}

int main(int argc, char* argv[]) {
    firewall::DaemonConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return EXIT_SUCCESS;
        } else if ((arg == "-q" || arg == "--queue-num") && i + 1 < argc) {
            config.queue_num = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "-r" || arg == "--rules") && i + 1 < argc) {
            config.rules_file = argv[++i];
        } else if ((arg == "-l" || arg == "--log-file") && i + 1 < argc) {
            config.log_file = argv[++i];
        } else if ((arg == "-v" || arg == "--log-level") && i + 1 < argc) {
            config.log_level = firewall::Logger::stringToLevel(argv[++i]);
        } else if ((arg == "-m" || arg == "--max-entries") && i + 1 < argc) {
            config.max_conntrack_entries = static_cast<size_t>(std::stoul(argv[++i]));
        } else if ((arg == "-g" || arg == "--gc-interval") && i + 1 < argc) {
            config.gc_interval = std::chrono::seconds(std::stoi(argv[++i]));
        } else if (arg == "--no-strict-tcp") {
            config.strict_tcp = false;
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << "\n";
            printUsage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    try {
        firewall::FirewallDaemon daemon(config);
        daemon.run();
    } catch (const std::exception& ex) {
        std::cerr << "Fatal error encountered in FirewallDaemon: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

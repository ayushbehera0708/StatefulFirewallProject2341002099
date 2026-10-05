#include "FirewallDaemon.h"

#include <csignal>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

namespace firewall {

std::atomic<bool> FirewallDaemon::shutdown_requested_{false};
FirewallDaemon* FirewallDaemon::active_instance_{nullptr};

FirewallDaemon::FirewallDaemon(DaemonConfig config)
    : config_(std::move(config)) {
    active_instance_ = this;
}

FirewallDaemon::~FirewallDaemon() {
    shutdown();
    if (active_instance_ == this) {
        active_instance_ = nullptr;
    }
}

void FirewallDaemon::setupSignalHandlers() {
    struct sigaction sa{};
    sa.sa_handler = &FirewallDaemon::handleSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
}

void FirewallDaemon::handleSignal(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        shutdown_requested_.store(true);
        if (active_instance_) {
            LOG_INFO("Shutdown signal (" + std::to_string(signum) + ") received. Initiating graceful shutdown...");
        }
    } else if (signum == SIGHUP) {
        if (active_instance_ && active_instance_->inspector_) {
            LOG_INFO("SIGHUP received. Reloading rules from: " + active_instance_->config_.rules_file);
            active_instance_->inspector_->loadRulesFromFile(active_instance_->config_.rules_file);
        }
    }
}

void FirewallDaemon::printBanner() const {
    std::cout << "\033[1;36m"
              << "====================================================================\n"
              << "   STATEFUL APPLICATION-LAYER FIREWALL & INTRUSION FILTER\n"
              << "   Author: Ayush Behera\n"
              << "   Platform: Linux Netfilter (libnetfilter_queue)\n"
              << "====================================================================\n"
              << "\033[0m" << std::endl;
}

bool FirewallDaemon::init() {
    if (is_initialized_.exchange(true)) {
        return true;
    }

    // 1. Initialize Asynchronous Logger Subsystem
    LoggerConfig log_cfg;
    log_cfg.file_path = config_.log_file;
    log_cfg.min_level = config_.log_level;
    log_cfg.log_to_console = config_.log_to_console;
    log_cfg.log_to_file = !config_.log_file.empty();
    Logger::getInstance().init(log_cfg);

    printBanner();
    LOG_INFO("Initializing Firewall Daemon subsystems...");

    // 2. Register Signal Handlers
    setupSignalHandlers();

    // 3. Initialize Layer 7 Inspector & Load Rules
    inspector_ = std::make_shared<Inspector>();
    if (!config_.rules_file.empty()) {
        size_t loaded = inspector_->loadRulesFromFile(config_.rules_file);
        LOG_INFO("Loaded " + std::to_string(loaded) + " custom L7 rules from " + config_.rules_file);
    }

    // 4. Initialize Stateful Conntrack Table
    ConntrackConfig ct_cfg;
    ct_cfg.max_entries = config_.max_conntrack_entries;
    ct_cfg.gc_interval = config_.gc_interval;
    ct_cfg.strict_tcp_handshake = config_.strict_tcp;
    conntrack_ = std::make_shared<ConntrackTable>(ct_cfg);

    // 5. Initialize Netfilter Interceptor
    interceptor_ = std::make_unique<Interceptor>(conntrack_, inspector_, config_.queue_num);
    if (!interceptor_->init()) {
        LOG_CRITICAL("Failed to initialize Netfilter Interceptor. Ensure root/CAP_NET_ADMIN privileges.");
        return false;
    }

    LOG_INFO("All Firewall Daemon subsystems successfully initialized.");
    return true;
}

void FirewallDaemon::run() {
    if (!is_initialized_.load()) {
        if (!init()) {
            return;
        }
    }

    if (is_running_.exchange(true)) {
        return; // Already running
    }

    LOG_INFO("Starting Stateful Firewall engine on NFQUEUE #" + std::to_string(config_.queue_num));

    // Start background threads
    conntrack_->startGC();
    interceptor_->start();

    LOG_INFO("Firewall is active and filtering network traffic.");

    // Main periodic stats monitoring loop
    while (!shutdown_requested_.load()) {
        std::this_thread::sleep_for(config_.stats_interval);
        if (!shutdown_requested_.load()) {
            printPeriodicStats();
        }
    }

    shutdown();
}

void FirewallDaemon::printPeriodicStats() const {
    if (!interceptor_ || !conntrack_) return;

    auto istats = interceptor_->getStats();
    auto cstats = conntrack_->getStats();
    size_t active_flows = conntrack_->getConnectionCount();

    std::ostringstream ss;
    ss << "\n--- [FIREWALL STATS MONITOR] ---\n"
       << "  Active Connections : " << active_flows << "\n"
       << "  Total Pkts Seen    : " << istats.total_packets << "\n"
       << "  Packets Accepted   : " << istats.accepted_packets << "\n"
       << "  Conntrack Drops    : " << istats.dropped_conntrack << "\n"
       << "  L7 Threats Dropped : " << istats.dropped_inspector << "\n"
       << "  L7 Threats Alerted : " << istats.alerts_inspector << "\n"
       << "  Conntrack Evicted  : " << cstats.total_evicted << "\n"
       << "--------------------------------";

    LOG_INFO(ss.str());
}

void FirewallDaemon::shutdown() {
    if (!is_running_.exchange(false)) {
        return;
    }

    LOG_INFO("Commencing Firewall Daemon teardown sequence...");

    // 1. Stop Interceptor first to halt packet queue ingestion
    if (interceptor_) {
        interceptor_->stop();
    }

    // 2. Stop Conntrack garbage collection thread
    if (conntrack_) {
        conntrack_->stopGC();
    }

    // 3. Print Final Lifetime Statistics
    printPeriodicStats();

    LOG_INFO("Firewall Daemon successfully stopped. Flushing logs...");
    Logger::getInstance().flush();
}

} // namespace firewall

#ifndef FIREWALL_DAEMON_H
#define FIREWALL_DAEMON_H

#include "ConntrackTable.h"
#include "Inspector.h"
#include "Interceptor.h"
#include "Logger.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <string>

namespace firewall {

/**
 * @brief Configuration parameters for the FirewallDaemon orchestrator.
 */
struct DaemonConfig {
    uint16_t queue_num{0};
    std::string rules_file{"rules/default_rules.conf"};
    std::string log_file{"firewall.log"};
    LogLevel log_level{LogLevel::INFO};
    bool log_to_console{true};
    size_t max_conntrack_entries{100000};
    std::chrono::seconds gc_interval{5};
    std::chrono::seconds stats_interval{10};
    bool strict_tcp{true};
};

/**
 * @brief Central Daemon orchestrating Interceptor, Conntrack, Inspector, and Logger.
 */
class FirewallDaemon {
public:
    explicit FirewallDaemon(DaemonConfig config = DaemonConfig{});
    ~FirewallDaemon();

    // Prevent copies and moves
    FirewallDaemon(const FirewallDaemon&) = delete;
    FirewallDaemon& operator=(const FirewallDaemon&) = delete;
    FirewallDaemon(FirewallDaemon&&) = delete;
    FirewallDaemon& operator=(FirewallDaemon&&) = delete;

    /**
     * @brief Initializes all subsystems, logging, and Netfilter queues.
     */
    bool init();

    /**
     * @brief Starts the main monitoring and periodic reporting loop.
     */
    void run();

    /**
     * @brief Initiates graceful shutdown, draining queues and restoring state.
     */
    void shutdown();

    /**
     * @brief Configures OS signal handlers (SIGINT, SIGTERM, SIGHUP).
     */
    static void setupSignalHandlers();

    /**
     * @brief Signal callback invoked by kernel.
     */
    static void handleSignal(int signum);

    static bool isShutdownRequested() noexcept {
        return shutdown_requested_.load();
    }

private:
    void printBanner() const;
    void printPeriodicStats() const;

    DaemonConfig config_;
    std::shared_ptr<ConntrackTable> conntrack_;
    std::shared_ptr<Inspector> inspector_;
    std::unique_ptr<Interceptor> interceptor_;

    std::atomic<bool> is_initialized_{false};
    std::atomic<bool> is_running_{false};

    static std::atomic<bool> shutdown_requested_;
    static FirewallDaemon* active_instance_;
};

} // namespace firewall

#endif // FIREWALL_DAEMON_H

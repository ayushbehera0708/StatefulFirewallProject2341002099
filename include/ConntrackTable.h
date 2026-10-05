#ifndef FIREWALL_CONNTRACK_TABLE_H
#define FIREWALL_CONNTRACK_TABLE_H

#include "Protocol.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace firewall {

/**
 * @brief Standard TCP flag bitmasks.
 */
inline constexpr uint8_t TCP_FLAG_FIN = 0x01;
inline constexpr uint8_t TCP_FLAG_SYN = 0x02;
inline constexpr uint8_t TCP_FLAG_RST = 0x04;
inline constexpr uint8_t TCP_FLAG_PSH = 0x08;
inline constexpr uint8_t TCP_FLAG_ACK = 0x10;
inline constexpr uint8_t TCP_FLAG_URG = 0x20;

/**
 * @brief Result status returned after evaluating a packet against the conntrack table.
 */
enum class ConntrackStatus : uint8_t {
    NEW_FLOW = 0,
    ESTABLISHED_FLOW,
    STATE_TRANSITION,
    INVALID_PACKET,
    TABLE_FULL,
    CLOSED_FLOW
};

/**
 * @brief Configuration timeouts for stateful tracking.
 */
struct ConntrackConfig {
    std::chrono::seconds syn_sent_timeout{30};
    std::chrono::seconds syn_recv_timeout{30};
    std::chrono::seconds established_timeout{3600};
    std::chrono::seconds fin_wait_timeout{60};
    std::chrono::seconds close_wait_timeout{60};
    std::chrono::seconds closed_timeout{10};
    std::chrono::seconds udp_timeout{60};
    std::chrono::seconds icmp_timeout{10};
    std::chrono::seconds gc_interval{5};
    size_t max_entries{100000};
    bool strict_tcp_handshake{true};
};

/**
 * @brief Thread-safe in-memory connection tracking table.
 */
class ConntrackTable {
public:
    explicit ConntrackTable(const ConntrackConfig& config = ConntrackConfig{});
    ~ConntrackTable();

    // Prevent copies and moves
    ConntrackTable(const ConntrackTable&) = delete;
    ConntrackTable& operator=(const ConntrackTable&) = delete;
    ConntrackTable(ConntrackTable&&) = delete;
    ConntrackTable& operator=(ConntrackTable&&) = delete;

    /**
     * @brief Evaluates an incoming packet, tracking and updating connection state.
     * @param tuple 5-tuple of the packet.
     * @param tcp_flags TCP flags bitmask (if protocol is TCP).
     * @param payload_length Byte size of L4 payload.
     * @return ConntrackStatus indicating state outcome.
     */
    ConntrackStatus processPacket(const FlowTuple& tuple, uint8_t tcp_flags, size_t payload_length);

    /**
     * @brief Thread-safe lookup of an active flow using shared_lock.
     */
    std::shared_ptr<ConnectionEntry> lookup(const FlowTuple& tuple) const;

    /**
     * @brief Launches the periodic garbage collection background thread.
     */
    void startGC();

    /**
     * @brief Stops the garbage collection thread gracefully.
     */
    void stopGC();

    /**
     * @brief Manually triggers a garbage collection cycle and returns evicted count.
     */
    size_t evictExpired();

    /**
     * @brief Returns the current number of flow keys in the table.
     */
    size_t getTableSize() const;

    /**
     * @brief Returns distinct connection entries count (half of table size since bidirectionally keyed).
     */
    size_t getConnectionCount() const;

    /**
     * @brief Conntrack statistics.
     */
    struct Stats {
        uint64_t total_processed{0};
        uint64_t total_new_flows{0};
        uint64_t total_invalid_packets{0};
        uint64_t total_evicted{0};
    };
    Stats getStats() const;

private:
    void gcCleanupLoop();
    bool isExpired(const ConnectionEntry& entry, std::chrono::steady_clock::time_point now) const;

    ConntrackConfig config_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<FlowTuple, std::shared_ptr<ConnectionEntry>> table_;

    std::atomic<bool> gc_running_{false};
    std::thread gc_thread_;
    std::mutex gc_mutex_;
    std::condition_variable gc_cv_;

    // Metrics counters
    std::atomic<uint64_t> stat_total_processed_{0};
    std::atomic<uint64_t> stat_total_new_flows_{0};
    std::atomic<uint64_t> stat_total_invalid_packets_{0};
    std::atomic<uint64_t> stat_total_evicted_{0};
};

} // namespace firewall

#endif // FIREWALL_CONNTRACK_TABLE_H

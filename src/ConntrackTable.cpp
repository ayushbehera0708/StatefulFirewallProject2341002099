#include "ConntrackTable.h"
#include "Logger.h"

#include <unordered_set>

namespace firewall {

ConntrackTable::ConntrackTable(const ConntrackConfig& config)
    : config_(config) {}

ConntrackTable::~ConntrackTable() {
    stopGC();
}

void ConntrackTable::startGC() {
    if (gc_running_.exchange(true)) {
        return; // Already running
    }
    gc_thread_ = std::thread(&ConntrackTable::gcCleanupLoop, this);
    LOG_INFO("Conntrack garbage collection thread started (interval: " +
             std::to_string(config_.gc_interval.count()) + "s)");
}

void ConntrackTable::stopGC() {
    if (!gc_running_.exchange(false)) {
        return;
    }
    gc_cv_.notify_all();
    if (gc_thread_.joinable()) {
        gc_thread_.join();
    }
    LOG_INFO("Conntrack garbage collection thread stopped");
}

ConntrackStatus ConntrackTable::processPacket(const FlowTuple& tuple, uint8_t tcp_flags, size_t payload_length) {
    ++stat_total_processed_;
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = table_.find(tuple);
    if (it == table_.end()) {
        // Enforce maximum table capacity to prevent resource exhaustion attacks
        if (table_.size() >= config_.max_entries) {
            LOG_WARN("Conntrack table full (" + std::to_string(table_.size()) + " entries). Dropping flow: " + tuple.toString());
            return ConntrackStatus::TABLE_FULL;
        }

        // Validate initial TCP handshake if strict mode is active
        if (tuple.protocol == TransportProtocol::TCP && config_.strict_tcp_handshake) {
            // New connection MUST start with SYN flag alone, without ACK, RST, or FIN
            bool has_syn = (tcp_flags & TCP_FLAG_SYN) != 0;
            bool has_invalid_flags = (tcp_flags & (TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN)) != 0;

            if (!has_syn || has_invalid_flags) {
                ++stat_total_invalid_packets_;
                LOG_WARN("Conntrack: Non-SYN packet for untracked TCP flow rejected: " +
                         tuple.toString() + " [flags: 0x" + std::to_string(tcp_flags) + "]");
                return ConntrackStatus::INVALID_PACKET;
            }
        }

        // Initialize new connection entry
        TcpState initial_state = (tuple.protocol == TransportProtocol::TCP) ? TcpState::SYN_SENT : TcpState::NONE;
        auto entry = std::make_shared<ConnectionEntry>(tuple, initial_state);
        entry->updateForward(payload_length);

        // Register both directional keys pointing to the same shared entry
        table_[tuple] = entry;
        table_[tuple.reverse()] = entry;

        ++stat_total_new_flows_;
        LOG_DEBUG("Conntrack: New flow registered: " + tuple.toString() +
                  " [" + tcpStateToString(initial_state) + "]");
        return ConntrackStatus::NEW_FLOW;
    }

    // Existing flow identified
    auto entry = it->second;
    bool is_forward = (tuple == entry->tuple);

    if (is_forward) {
        entry->updateForward(payload_length);
    } else {
        entry->updateReverse(payload_length);
    }

    if (tuple.protocol != TransportProtocol::TCP) {
        return ConntrackStatus::ESTABLISHED_FLOW;
    }

    // TCP State Machine processing
    if (tcp_flags & TCP_FLAG_RST) {
        entry->state = TcpState::CLOSED;
        LOG_DEBUG("Conntrack: RST received for " + tuple.toString() + " -> CLOSED");
        return ConntrackStatus::CLOSED_FLOW;
    }

    switch (entry->state) {
        case TcpState::SYN_SENT:
            if (!is_forward && (tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
                entry->state = TcpState::SYN_RECV;
                LOG_DEBUG("Conntrack: SYN-ACK observed for " + tuple.toString() + " -> SYN_RECV");
                return ConntrackStatus::STATE_TRANSITION;
            } else if (is_forward && (tcp_flags & TCP_FLAG_SYN)) {
                // SYN retransmission
                return ConntrackStatus::ESTABLISHED_FLOW;
            }
            break;

        case TcpState::SYN_RECV:
            if (is_forward && (tcp_flags & TCP_FLAG_ACK)) {
                entry->state = TcpState::ESTABLISHED;
                LOG_DEBUG("Conntrack: Handshake complete for " + tuple.toString() + " -> ESTABLISHED");
                return ConntrackStatus::STATE_TRANSITION;
            } else if (!is_forward && (tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK))) {
                // SYN-ACK retransmission
                return ConntrackStatus::ESTABLISHED_FLOW;
            }
            break;

        case TcpState::ESTABLISHED:
            if (tcp_flags & TCP_FLAG_FIN) {
                if (is_forward) {
                    entry->state = TcpState::FIN_WAIT;
                    LOG_DEBUG("Conntrack: Forward FIN observed for " + tuple.toString() + " -> FIN_WAIT");
                } else {
                    entry->state = TcpState::CLOSE_WAIT;
                    LOG_DEBUG("Conntrack: Reverse FIN observed for " + tuple.toString() + " -> CLOSE_WAIT");
                }
                return ConntrackStatus::STATE_TRANSITION;
            }
            return ConntrackStatus::ESTABLISHED_FLOW;

        case TcpState::FIN_WAIT:
            if (!is_forward && (tcp_flags & TCP_FLAG_FIN)) {
                entry->state = TcpState::CLOSED;
                LOG_DEBUG("Conntrack: Mutual FIN observed for " + tuple.toString() + " -> CLOSED");
                return ConntrackStatus::CLOSED_FLOW;
            } else if (!is_forward && (tcp_flags & TCP_FLAG_ACK)) {
                return ConntrackStatus::ESTABLISHED_FLOW;
            }
            break;

        case TcpState::CLOSE_WAIT:
            if (is_forward && (tcp_flags & TCP_FLAG_FIN)) {
                entry->state = TcpState::CLOSED;
                LOG_DEBUG("Conntrack: Closing FIN observed for " + tuple.toString() + " -> CLOSED");
                return ConntrackStatus::CLOSED_FLOW;
            }
            return ConntrackStatus::ESTABLISHED_FLOW;

        case TcpState::CLOSED:
            return ConntrackStatus::CLOSED_FLOW;

        default:
            break;
    }

    return ConntrackStatus::ESTABLISHED_FLOW;
}

std::shared_ptr<ConnectionEntry> ConntrackTable::lookup(const FlowTuple& tuple) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = table_.find(tuple);
    if (it != table_.end()) {
        return it->second;
    }
    return nullptr;
}

bool ConntrackTable::isExpired(const ConnectionEntry& entry, std::chrono::steady_clock::time_point now) const {
    auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - entry.last_seen);

    if (entry.tuple.protocol == TransportProtocol::TCP) {
        switch (entry.state) {
            case TcpState::SYN_SENT:
                return idle >= config_.syn_sent_timeout;
            case TcpState::SYN_RECV:
                return idle >= config_.syn_recv_timeout;
            case TcpState::ESTABLISHED:
                return idle >= config_.established_timeout;
            case TcpState::FIN_WAIT:
                return idle >= config_.fin_wait_timeout;
            case TcpState::CLOSE_WAIT:
                return idle >= config_.close_wait_timeout;
            case TcpState::CLOSED:
                return idle >= config_.closed_timeout;
            default:
                return idle >= config_.established_timeout;
        }
    } else if (entry.tuple.protocol == TransportProtocol::UDP) {
        return idle >= config_.udp_timeout;
    } else if (entry.tuple.protocol == TransportProtocol::ICMP) {
        return idle >= config_.icmp_timeout;
    }

    return idle >= config_.udp_timeout;
}

size_t ConntrackTable::evictExpired() {
    auto now = std::chrono::steady_clock::now();
    std::vector<FlowTuple> keys_to_remove;
    std::unordered_set<const ConnectionEntry*> evicted_entries;

    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        for (const auto& [tuple, entry] : table_) {
            if (isExpired(*entry, now)) {
                keys_to_remove.push_back(tuple);
                evicted_entries.insert(entry.get());
            }
        }

        for (const auto& key : keys_to_remove) {
            table_.erase(key);
        }
    }

    size_t count = evicted_entries.size();
    if (count > 0) {
        stat_total_evicted_ += count;
        LOG_INFO("Conntrack GC: Evicted " + std::to_string(count) +
                 " expired connections. Active flows: " + std::to_string(getTableSize() / 2));
    }

    return count;
}

void ConntrackTable::gcCleanupLoop() {
    while (gc_running_.load()) {
        {
            std::unique_lock<std::mutex> lock(gc_mutex_);
            gc_cv_.wait_for(lock, config_.gc_interval, [this]() {
                return !gc_running_.load();
            });
        }

        if (!gc_running_.load()) {
            break;
        }

        evictExpired();
    }
}

size_t ConntrackTable::getTableSize() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return table_.size();
}

size_t ConntrackTable::getConnectionCount() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return table_.size() / 2;
}

ConntrackTable::Stats ConntrackTable::getStats() const {
    return Stats{
        stat_total_processed_.load(),
        stat_total_new_flows_.load(),
        stat_total_invalid_packets_.load(),
        stat_total_evicted_.load()
    };
}

} // namespace firewall

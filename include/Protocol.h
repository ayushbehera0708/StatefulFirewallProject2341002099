#ifndef FIREWALL_PROTOCOL_H
#define FIREWALL_PROTOCOL_H

#include <cstdint>
#include <string>
#include <chrono>
#include <functional>
#include <sstream>

namespace firewall {

/**
 * @brief Strongly-typed enumeration for supported transport-layer protocols.
 */
enum class TransportProtocol : uint8_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    UNKNOWN = 255
};

/**
 * @brief RFC 793 / Linux Netfilter compatible TCP state machine states.
 */
enum class TcpState : uint8_t {
    NONE = 0,
    SYN_SENT,
    SYN_RECV,
    ESTABLISHED,
    FIN_WAIT,
    CLOSE_WAIT,
    CLOSED
};

/**
 * @brief Converts TransportProtocol enum to human-readable string.
 */
std::string protocolToString(TransportProtocol proto);

/**
 * @brief Converts raw protocol integer to TransportProtocol enum.
 */
TransportProtocol protocolFromNumber(uint8_t proto_num);

/**
 * @brief Converts TcpState enum to human-readable string.
 */
std::string tcpStateToString(TcpState state);

/**
 * @brief 5-tuple identifying a directional network flow.
 */
struct FlowTuple {
    uint32_t src_ip{0};      ///< Source IPv4 address in host byte order
    uint32_t dst_ip{0};      ///< Destination IPv4 address in host byte order
    uint16_t src_port{0};    ///< Source L4 port in host byte order
    uint16_t dst_port{0};    ///< Destination L4 port in host byte order
    TransportProtocol protocol{TransportProtocol::UNKNOWN}; ///< L4 Transport protocol

    constexpr FlowTuple() noexcept = default;

    constexpr FlowTuple(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, TransportProtocol proto) noexcept
        : src_ip(sip), dst_ip(dip), src_port(sport), dst_port(dport), protocol(proto) {}

    /**
     * @brief Computes the inverse (return flow) tuple.
     */
    constexpr FlowTuple reverse() const noexcept {
        return FlowTuple(dst_ip, src_ip, dst_port, src_port, protocol);
    }

    /**
     * @brief Equality comparison for hash table lookups.
     */
    bool operator==(const FlowTuple& other) const noexcept {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }

    bool operator!=(const FlowTuple& other) const noexcept {
        return !(*this == other);
    }

    /**
     * @brief String representation in "src_ip:src_port -> dst_ip:dst_port [PROTO]" format.
     */
    std::string toString() const;

    /**
     * @brief Formats 32-bit integer IPv4 to dotted-decimal notation.
     */
    static std::string ipToString(uint32_t ip);

    /**
     * @brief Parses dotted-decimal IPv4 string to host byte order 32-bit integer.
     */
    static uint32_t stringToIp(const std::string& ip_str);
};

/**
 * @brief Tracking entry for an active or closed network connection in conntrack table.
 */
struct ConnectionEntry {
    FlowTuple tuple;                                    ///< Original flow tuple
    TcpState state{TcpState::NONE};                     ///< Current TCP state
    uint64_t packets_forward{0};                        ///< Packet counter (initiator -> responder)
    uint64_t packets_reverse{0};                        ///< Packet counter (responder -> initiator)
    uint64_t bytes_forward{0};                          ///< Byte counter (initiator -> responder)
    uint64_t bytes_reverse{0};                          ///< Byte counter (responder -> initiator)
    std::chrono::steady_clock::time_point created_at;   ///< Connection initiation time
    std::chrono::steady_clock::time_point last_seen;    ///< Most recent packet timestamp

    explicit ConnectionEntry(const FlowTuple& t, TcpState s = TcpState::NONE);

    void updateForward(size_t bytes) noexcept;
    void updateReverse(size_t bytes) noexcept;

    std::chrono::seconds getIdleTime() const noexcept;
    std::string toString() const;
};

} // namespace firewall

namespace std {
/**
 * @brief Standard hash specialization for FlowTuple enabling std::unordered_map usage.
 */
template <>
struct hash<firewall::FlowTuple> {
    size_t operator()(const firewall::FlowTuple& t) const noexcept {
        // Boost-style hash_combine with golden ratio constant
        size_t seed = 0;
        auto combine = [&seed](size_t val) {
            seed ^= val + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        };
        combine(std::hash<uint32_t>{}(t.src_ip));
        combine(std::hash<uint32_t>{}(t.dst_ip));
        combine(std::hash<uint16_t>{}(t.src_port));
        combine(std::hash<uint16_t>{}(t.dst_port));
        combine(std::hash<uint8_t>{}(static_cast<uint8_t>(t.protocol)));
        return seed;
    }
};
} // namespace std

#endif // FIREWALL_PROTOCOL_H

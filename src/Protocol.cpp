#include "Protocol.h"

#include <arpa/inet.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace firewall {

std::string protocolToString(TransportProtocol proto) {
    switch (proto) {
        case TransportProtocol::ICMP:
            return "ICMP";
        case TransportProtocol::TCP:
            return "TCP";
        case TransportProtocol::UDP:
            return "UDP";
        default:
            return "UNKNOWN(" + std::to_string(static_cast<uint8_t>(proto)) + ")";
    }
}

TransportProtocol protocolFromNumber(uint8_t proto_num) {
    switch (proto_num) {
        case 1:
            return TransportProtocol::ICMP;
        case 6:
            return TransportProtocol::TCP;
        case 17:
            return TransportProtocol::UDP;
        default:
            return TransportProtocol::UNKNOWN;
    }
}

std::string tcpStateToString(TcpState state) {
    switch (state) {
        case TcpState::NONE:
            return "NONE";
        case TcpState::SYN_SENT:
            return "SYN_SENT";
        case TcpState::SYN_RECV:
            return "SYN_RECV";
        case TcpState::ESTABLISHED:
            return "ESTABLISHED";
        case TcpState::FIN_WAIT:
            return "FIN_WAIT";
        case TcpState::CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TcpState::CLOSED:
            return "CLOSED";
        default:
            return "UNKNOWN";
    }
}

std::string FlowTuple::ipToString(uint32_t ip) {
    char buf[INET_ADDRSTRLEN];
    uint32_t net_ip = htonl(ip);
    if (inet_ntop(AF_INET, &net_ip, buf, sizeof(buf)) != nullptr) {
        return std::string(buf);
    }
    return "0.0.0.0";
}

uint32_t FlowTuple::stringToIp(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) <= 0) {
        throw std::invalid_argument("Invalid IPv4 address string: " + ip_str);
    }
    return ntohl(addr.s_addr);
}

std::string FlowTuple::toString() const {
    std::ostringstream oss;
    oss << ipToString(src_ip) << ":" << src_port
        << " -> "
        << ipToString(dst_ip) << ":" << dst_port
        << " [" << protocolToString(protocol) << "]";
    return oss.str();
}

ConnectionEntry::ConnectionEntry(const FlowTuple& t, TcpState s)
    : tuple(t),
      state(s),
      packets_forward(0),
      packets_reverse(0),
      bytes_forward(0),
      bytes_reverse(0),
      created_at(std::chrono::steady_clock::now()),
      last_seen(created_at) {}

void ConnectionEntry::updateForward(size_t bytes) noexcept {
    ++packets_forward;
    bytes_forward += bytes;
    last_seen = std::chrono::steady_clock::now();
}

void ConnectionEntry::updateReverse(size_t bytes) noexcept {
    ++packets_reverse;
    bytes_reverse += bytes;
    last_seen = std::chrono::steady_clock::now();
}

std::chrono::seconds ConnectionEntry::getIdleTime() const noexcept {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now - last_seen);
}

std::string ConnectionEntry::toString() const {
    std::ostringstream oss;
    oss << "Flow: " << tuple.toString()
        << " | State: " << tcpStateToString(state)
        << " | Fwd: " << packets_forward << " pkts (" << bytes_forward << " B)"
        << " | Rev: " << packets_reverse << " pkts (" << bytes_reverse << " B)"
        << " | Idle: " << getIdleTime().count() << "s";
    return oss.str();
}

} // namespace firewall

#include "Interceptor.h"
#include "Logger.h"

#include <arpa/inet.h>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace firewall {

Interceptor::Interceptor(std::shared_ptr<ConntrackTable> conntrack,
                         std::shared_ptr<Inspector> inspector,
                         uint16_t queue_num)
    : conntrack_(std::move(conntrack)),
      inspector_(std::move(inspector)),
      queue_num_(queue_num) {}

Interceptor::~Interceptor() {
    stop();
    releaseHandles();
}

void Interceptor::releaseHandles() noexcept {
#if HAVE_NETFILTER_QUEUE
    if (nfq_qh_) {
        nfq_destroy_queue(nfq_qh_);
        nfq_qh_ = nullptr;
    }
    if (nfq_h_) {
        nfq_unbind_pf(nfq_h_, AF_INET);
        nfq_close(nfq_h_);
        nfq_h_ = nullptr;
    }
    if (netlink_fd_ >= 0) {
        close(netlink_fd_);
        netlink_fd_ = -1;
    }
#endif
}

bool Interceptor::init() {
#if HAVE_NETFILTER_QUEUE
    LOG_INFO("Interceptor: Initializing libnetfilter_queue for queue #" + std::to_string(queue_num_));

    nfq_h_ = nfq_open();
    if (!nfq_h_) {
        LOG_CRITICAL("Interceptor: nfq_open() failed. Ensure root privileges and netfilter modules are loaded.");
        return false;
    }

    if (nfq_unbind_pf(nfq_h_, AF_INET) < 0) {
        LOG_WARN("Interceptor: nfq_unbind_pf(AF_INET) returned warning (ignorable)");
    }

    if (nfq_bind_pf(nfq_h_, AF_INET) < 0) {
        LOG_CRITICAL("Interceptor: nfq_bind_pf(AF_INET) failed");
        releaseHandles();
        return false;
    }

    nfq_qh_ = nfq_create_queue(nfq_h_, queue_num_, &Interceptor::nfqCallbackDispatcher, this);
    if (!nfq_qh_) {
        LOG_CRITICAL("Interceptor: nfq_create_queue() failed for queue #" + std::to_string(queue_num_));
        releaseHandles();
        return false;
    }

    if (nfq_set_mode(nfq_qh_, NFQNL_COPY_PACKET, 0xffff) < 0) {
        LOG_CRITICAL("Interceptor: nfq_set_mode(NFQNL_COPY_PACKET) failed");
        releaseHandles();
        return false;
    }

    netlink_fd_ = nfq_fd(nfq_h_);
    if (netlink_fd_ < 0) {
        LOG_CRITICAL("Interceptor: Failed to obtain netlink socket descriptor");
        releaseHandles();
        return false;
    }

    LOG_INFO("Interceptor: Netfilter Queue successfully bound to queue #" + std::to_string(queue_num_));
    return true;
#else
    LOG_INFO("Interceptor: Running in non-Linux or simulated environment. Netfilter hooks disabled.");
    return true;
#endif
}

void Interceptor::start() {
    if (is_running_.exchange(true)) {
        return;
    }
    worker_thread_ = std::thread(&Interceptor::eventLoop, this);
    LOG_INFO("Interceptor worker thread started");
}

void Interceptor::stop() {
    if (!is_running_.exchange(false)) {
        return;
    }
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    LOG_INFO("Interceptor worker thread stopped");
}

#if HAVE_NETFILTER_QUEUE
int Interceptor::nfqCallbackDispatcher(struct nfq_q_handle* qh,
                                      struct nfgenmsg* /*nfmsg*/,
                                      struct nfq_data* nfa,
                                      void* data) {
    auto* self = static_cast<Interceptor*>(data);
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        return 0;
    }

    uint32_t id = ntohl(ph->packet_id);
    unsigned char* raw_payload = nullptr;
    int payload_len = nfq_get_payload(nfa, &raw_payload);

    uint32_t verdict = NF_ACCEPT;
    if (payload_len >= 0 && raw_payload != nullptr) {
        verdict = self->processPacketData(id, raw_payload, static_cast<size_t>(payload_len));
    }

    return nfq_set_verdict(qh, id, verdict, 0, nullptr);
}
#endif

void Interceptor::eventLoop() {
#if HAVE_NETFILTER_QUEUE
    constexpr size_t BUF_SIZE = 65536;
    alignas(16) char buffer[BUF_SIZE];

    struct pollfd pfd;
    pfd.fd = netlink_fd_;
    pfd.events = POLLIN;

    while (is_running_.load()) {
        int poll_res = poll(&pfd, 1, 200); // 200ms timeout for clean responsiveness
        if (poll_res < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("Interceptor: poll() failed with error: " + std::string(strerror(errno)));
            break;
        }

        if (poll_res == 0) {
            continue; // Timeout, check is_running_
        }

        if (pfd.revents & POLLIN) {
            ssize_t rv = recv(netlink_fd_, buffer, sizeof(buffer), 0);
            if (rv >= 0) {
                nfq_handle_packet(nfq_h_, buffer, static_cast<int>(rv));
            } else if (errno != EAGAIN && errno != EINTR) {
                LOG_ERROR("Interceptor: recv() failed: " + std::string(strerror(errno)));
            }
        }
    }
#else
    // Simulated loop for test/development environments
    while (is_running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
#endif
}

DecodedPacket Interceptor::decodeIpPacket(const uint8_t* data, size_t length) {
    DecodedPacket pkt;
    if (data == nullptr || length < 20) {
        return pkt;
    }

    // Parse IPv4 Header
    uint8_t ver = (data[0] >> 4) & 0x0F;
    uint8_t ihl = (data[0] & 0x0F) * 4;

    if (ver != 4 || ihl < 20 || length < ihl) {
        return pkt; // Non-IPv4 or truncated IP header
    }

    size_t total_len = (static_cast<size_t>(data[2]) << 8) | data[3];
    if (length < total_len) {
        total_len = length; // Handle captured truncated packets
    }

    uint8_t proto_num = data[9];
    pkt.protocol = protocolFromNumber(proto_num);

    pkt.src_ip = (static_cast<uint32_t>(data[12]) << 24) |
                 (static_cast<uint32_t>(data[13]) << 16) |
                 (static_cast<uint32_t>(data[14]) << 8)  |
                 static_cast<uint32_t>(data[15]);

    pkt.dst_ip = (static_cast<uint32_t>(data[16]) << 24) |
                 (static_cast<uint32_t>(data[17]) << 16) |
                 (static_cast<uint32_t>(data[18]) << 8)  |
                 static_cast<uint32_t>(data[19]);

    // Parse Transport Layer Header
    if (pkt.protocol == TransportProtocol::TCP) {
        if (total_len < ihl + 20) {
            return pkt; // Truncated TCP header
        }
        const uint8_t* tcp_hdr = data + ihl;
        pkt.src_port = (static_cast<uint16_t>(tcp_hdr[0]) << 8) | tcp_hdr[1];
        pkt.dst_port = (static_cast<uint16_t>(tcp_hdr[2]) << 8) | tcp_hdr[3];

        uint8_t tcp_offset = ((tcp_hdr[12] >> 4) & 0x0F) * 4;
        if (tcp_offset < 20 || ihl + tcp_offset > total_len) {
            return pkt;
        }

        pkt.tcp_flags = tcp_hdr[13];
        pkt.payload = data + ihl + tcp_offset;
        pkt.payload_len = total_len - (ihl + tcp_offset);
    } else if (pkt.protocol == TransportProtocol::UDP) {
        if (total_len < ihl + 8) {
            return pkt; // Truncated UDP header
        }
        const uint8_t* udp_hdr = data + ihl;
        pkt.src_port = (static_cast<uint16_t>(udp_hdr[0]) << 8) | udp_hdr[1];
        pkt.dst_port = (static_cast<uint16_t>(udp_hdr[2]) << 8) | udp_hdr[3];

        size_t udp_len = (static_cast<size_t>(udp_hdr[4]) << 8) | udp_hdr[5];
        pkt.payload = data + ihl + 8;
        pkt.payload_len = (udp_len >= 8 && ihl + udp_len <= total_len) ? (udp_len - 8) : 0;
    } else if (pkt.protocol == TransportProtocol::ICMP) {
        pkt.src_port = 0;
        pkt.dst_port = 0;
        pkt.payload = data + ihl;
        pkt.payload_len = total_len - ihl;
    } else {
        return pkt; // Unsupported L4 protocol
    }

    pkt.tuple = FlowTuple(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol);
    pkt.valid = true;
    return pkt;
}

uint32_t Interceptor::processPacketData(uint32_t /*id*/, const uint8_t* data, size_t length) {
    ++stat_total_packets_;

    DecodedPacket pkt = decodeIpPacket(data, length);
    if (!pkt.valid) {
        // Allow unparsable packets through to prevent breaking non-IP/unknown traffic
        ++stat_accepted_packets_;
        return NF_ACCEPT;
    }

    // 1. Stateful Connection Tracking Evaluation
    ConntrackStatus c_status = conntrack_->processPacket(pkt.tuple, pkt.tcp_flags, pkt.payload_len);
    if (c_status == ConntrackStatus::INVALID_PACKET || c_status == ConntrackStatus::TABLE_FULL) {
        ++stat_dropped_conntrack_;
        LOG_WARN("FIREWALL DROP [CONNTRACK]: Invalid packet state on " + pkt.tuple.toString());
        return NF_DROP;
    }

    // 2. Layer 7 Deep Packet Inspection (DPI)
    if (pkt.payload_len > 0 && pkt.payload != nullptr) {
        InspectionResult insp_res = inspector_->inspect(pkt.tuple, pkt.payload, pkt.payload_len);
        if (insp_res.is_threat) {
            if (insp_res.action == RuleAction::DROP) {
                ++stat_dropped_inspector_;
                LOG_CRITICAL("FIREWALL DROP [L7 THREAT]: Rule=" + insp_res.rule_id +
                             " [" + insp_res.category + "] Flow=" + pkt.tuple.toString() +
                             " Snippet=\"" + insp_res.matched_snippet + "\"");
                return NF_DROP;
            } else if (insp_res.action == RuleAction::ALERT) {
                ++stat_alerts_inspector_;
                LOG_WARN("FIREWALL ALERT [L7 THREAT]: Rule=" + insp_res.rule_id +
                         " [" + insp_res.category + "] Flow=" + pkt.tuple.toString() +
                         " Snippet=\"" + insp_res.matched_snippet + "\"");
            }
        }
    }

    ++stat_accepted_packets_;
    return NF_ACCEPT;
}

InterceptorStats Interceptor::getStats() const {
    return InterceptorStats{
        stat_total_packets_.load(),
        stat_accepted_packets_.load(),
        stat_dropped_conntrack_.load(),
        stat_dropped_inspector_.load(),
        stat_alerts_inspector_.load()
    };
}

} // namespace firewall

#ifndef FIREWALL_INTERCEPTOR_H
#define FIREWALL_INTERCEPTOR_H

#include "ConntrackTable.h"
#include "Inspector.h"
#include "Logger.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

// Conditional inclusion for Linux Netfilter Queue
#if defined(__linux__) && __has_include(<libnetfilter_queue/libnetfilter_queue.h>)
    #define HAVE_NETFILTER_QUEUE 1
    #include <linux/netfilter.h>
    #include <libnetfilter_queue/libnetfilter_queue.h>
#else
    #define HAVE_NETFILTER_QUEUE 0
    // Netfilter standard verdict constants
    #ifndef NF_DROP
        #define NF_DROP 0
    #endif
    #ifndef NF_ACCEPT
        #define NF_ACCEPT 1
    #endif

    // Forward declarations and opaque dummy structs for non-Linux / simulated builds
    struct nfq_handle;
    struct nfq_q_handle;
    struct nfq_data;
    struct nfgenmsg;
#endif

namespace firewall {

/**
 * @brief Decoded IPv4 and Transport layer packet headers.
 */
struct DecodedPacket {
    bool valid{false};
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    TransportProtocol protocol{TransportProtocol::UNKNOWN};
    uint8_t tcp_flags{0};
    const uint8_t* payload{nullptr};
    size_t payload_len{0};
    FlowTuple tuple;
};

/**
 * @brief Interceptor statistics counter.
 */
struct InterceptorStats {
    uint64_t total_packets{0};
    uint64_t accepted_packets{0};
    uint64_t dropped_conntrack{0};
    uint64_t dropped_inspector{0};
    uint64_t alerts_inspector{0};
};

/**
 * @brief Netfilter Queue Interceptor utilizing libnetfilter_queue with RAII handle management.
 */
class Interceptor {
public:
    Interceptor(std::shared_ptr<ConntrackTable> conntrack,
                std::shared_ptr<Inspector> inspector,
                uint16_t queue_num = 0);
    ~Interceptor();

    // Prevent copies and moves
    Interceptor(const Interceptor&) = delete;
    Interceptor& operator=(const Interceptor&) = delete;
    Interceptor(Interceptor&&) = delete;
    Interceptor& operator=(Interceptor&&) = delete;

    /**
     * @brief Initializes Netfilter queue socket, unbinds, binds AF_INET, and sets copy mode.
     */
    bool init();

    /**
     * @brief Starts the packet interception polling loop on a background thread.
     */
    void start();

    /**
     * @brief Stops the interception loop and cleans up Netfilter handles.
     */
    void stop();

    /**
     * @brief Evaluates an intercepted raw packet buffer and returns the verdict (NF_ACCEPT or NF_DROP).
     */
    uint32_t processPacketData(uint32_t id, const uint8_t* data, size_t length);

    /**
     * @brief Decodes raw IPv4 packet bytes into structured metadata.
     */
    static DecodedPacket decodeIpPacket(const uint8_t* data, size_t length);

    InterceptorStats getStats() const;

    uint16_t getQueueNumber() const noexcept { return queue_num_; }

private:
    void eventLoop();
    void releaseHandles() noexcept;

#if HAVE_NETFILTER_QUEUE
    static int nfqCallbackDispatcher(struct nfq_q_handle* qh,
                                     struct nfgenmsg* nfmsg,
                                     struct nfq_data* nfa,
                                     void* data);
#endif

    std::shared_ptr<ConntrackTable> conntrack_;
    std::shared_ptr<Inspector> inspector_;
    uint16_t queue_num_{0};

    std::atomic<bool> is_running_{false};
    std::thread worker_thread_;

    // RAII Netfilter Queue handles
    [[maybe_unused]] struct nfq_handle* nfq_h_{nullptr};
    [[maybe_unused]] struct nfq_q_handle* nfq_qh_{nullptr};
    [[maybe_unused]] int netlink_fd_{-1};

    // Statistics
    std::atomic<uint64_t> stat_total_packets_{0};
    std::atomic<uint64_t> stat_accepted_packets_{0};
    std::atomic<uint64_t> stat_dropped_conntrack_{0};
    std::atomic<uint64_t> stat_dropped_inspector_{0};
    std::atomic<uint64_t> stat_alerts_inspector_{0};
};

} // namespace firewall

#endif // FIREWALL_INTERCEPTOR_H

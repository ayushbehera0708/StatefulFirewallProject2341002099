#include "Protocol.h"
#include "ConntrackTable.h"
#include "Inspector.h"
#include "Interceptor.h"
#include "Logger.h"

#include <cassert>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using namespace firewall;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "\033[31m[FAILED]\033[0m " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            std::exit(EXIT_FAILURE); \
        } else { \
            std::cout << "\033[32m[PASSED]\033[0m " << msg << "\n"; \
        } \
    } while(0)

void testProtocolAndHashing() {
    std::cout << "\n=== Running Protocol & Hashing Tests ===\n";

    FlowTuple t1(FlowTuple::stringToIp("192.168.1.50"), FlowTuple::stringToIp("10.0.0.1"), 54321, 80, TransportProtocol::TCP);
    FlowTuple t2 = t1.reverse();

    TEST_ASSERT(FlowTuple::ipToString(t1.src_ip) == "192.168.1.50", "IPv4 string conversion");
    TEST_ASSERT(FlowTuple::ipToString(t1.dst_ip) == "10.0.0.1", "IPv4 destination string conversion");
    TEST_ASSERT(t2.src_ip == t1.dst_ip && t2.dst_ip == t1.src_ip, "Tuple reverse IP logic");
    TEST_ASSERT(t2.src_port == 80 && t2.dst_port == 54321, "Tuple reverse Port logic");

    std::hash<FlowTuple> hasher;
    size_t h1 = hasher(t1);
    size_t h2 = hasher(t1);
    size_t h_rev = hasher(t2);

    TEST_ASSERT(h1 == h2, "Hash consistency for identical tuples");
    TEST_ASSERT(h1 != h_rev, "Hash distinction for reverse flows");

    ConnectionEntry entry(t1, TcpState::SYN_SENT);
    entry.updateForward(128);
    entry.updateReverse(256);
    TEST_ASSERT(entry.packets_forward == 1 && entry.bytes_forward == 128, "Connection forward counters");
    TEST_ASSERT(entry.packets_reverse == 1 && entry.bytes_reverse == 256, "Connection reverse counters");
}

void testConntrackStateMachine() {
    std::cout << "\n=== Running Conntrack State Machine Tests ===\n";

    ConntrackConfig cfg;
    cfg.strict_tcp_handshake = true;
    ConntrackTable ct(cfg);

    FlowTuple client_to_server(
        FlowTuple::stringToIp("10.10.10.2"), FlowTuple::stringToIp("10.10.10.1"),
        40000, 80, TransportProtocol::TCP
    );
    FlowTuple server_to_client = client_to_server.reverse();

    // 1. Invalid initial packet (non-SYN: e.g. ACK without preceding SYN)
    ConntrackStatus st0 = ct.processPacket(client_to_server, TCP_FLAG_ACK, 0);
    TEST_ASSERT(st0 == ConntrackStatus::INVALID_PACKET, "Reject out-of-state ACK on unestablished flow");

    // 2. Client sends SYN
    ConntrackStatus st1 = ct.processPacket(client_to_server, TCP_FLAG_SYN, 0);
    TEST_ASSERT(st1 == ConntrackStatus::NEW_FLOW, "Client initial SYN registers NEW_FLOW");

    auto entry = ct.lookup(client_to_server);
    TEST_ASSERT(entry != nullptr && entry->state == TcpState::SYN_SENT, "State is SYN_SENT");

    // Lookup using reverse tuple must return the same connection object
    auto entry_rev = ct.lookup(server_to_client);
    TEST_ASSERT(entry_rev == entry, "Bidirectional conntrack lookup points to same entry");

    // 3. Server responds with SYN-ACK
    ConntrackStatus st2 = ct.processPacket(server_to_client, TCP_FLAG_SYN | TCP_FLAG_ACK, 0);
    TEST_ASSERT(st2 == ConntrackStatus::STATE_TRANSITION, "Server SYN-ACK transitions state");
    TEST_ASSERT(entry->state == TcpState::SYN_RECV, "State is SYN_RECV");

    // 4. Client completes handshake with ACK
    ConntrackStatus st3 = ct.processPacket(client_to_server, TCP_FLAG_ACK, 50);
    TEST_ASSERT(st3 == ConntrackStatus::STATE_TRANSITION, "Client ACK completes 3-way handshake");
    TEST_ASSERT(entry->state == TcpState::ESTABLISHED, "State is ESTABLISHED");

    // 5. Normal established data transfer
    ConntrackStatus st4 = ct.processPacket(client_to_server, TCP_FLAG_ACK | TCP_FLAG_PSH, 200);
    TEST_ASSERT(st4 == ConntrackStatus::ESTABLISHED_FLOW, "Established data transfer accepted");

    // 6. Client initiates teardown with FIN
    ConntrackStatus st5 = ct.processPacket(client_to_server, TCP_FLAG_FIN | TCP_FLAG_ACK, 0);
    TEST_ASSERT(st5 == ConntrackStatus::STATE_TRANSITION, "Client FIN transitions to FIN_WAIT");
    TEST_ASSERT(entry->state == TcpState::FIN_WAIT, "State is FIN_WAIT");

    // 7. Server sends FIN
    ConntrackStatus st6 = ct.processPacket(server_to_client, TCP_FLAG_FIN | TCP_FLAG_ACK, 0);
    TEST_ASSERT(st6 == ConntrackStatus::CLOSED_FLOW, "Mutual FIN closes connection");
    TEST_ASSERT(entry->state == TcpState::CLOSED, "State is CLOSED");
}

void testInspectorHttpAndSignatures() {
    std::cout << "\n=== Running L7 Inspector (HTTP & Signatures) Tests ===\n";

    Inspector inspector;
    FlowTuple http_flow(FlowTuple::stringToIp("192.168.1.100"), FlowTuple::stringToIp("192.168.1.1"), 33333, 80, TransportProtocol::TCP);

    // 1. Clean Benign HTTP Request
    std::string clean_http =
        "GET /index.html?page=home HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: Mozilla/5.0\r\n\r\n";

    auto res_clean = inspector.inspect(http_flow, reinterpret_cast<const uint8_t*>(clean_http.data()), clean_http.size());
    TEST_ASSERT(!res_clean.is_threat && res_clean.action == RuleAction::ALLOW, "Benign HTTP Request allowed");

    // 2. SQL Injection: UNION SELECT
    std::string sqli_union =
        "GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1\r\n"
        "Host: example.com\r\n\r\n";

    auto res_sqli1 = inspector.inspect(http_flow, reinterpret_cast<const uint8_t*>(sqli_union.data()), sqli_union.size());
    TEST_ASSERT(res_sqli1.is_threat && res_sqli1.action == RuleAction::DROP, "SQLi UNION SELECT detected & dropped");
    TEST_ASSERT(res_sqli1.category == "SQLI", "Threat category is SQLI");

    // 3. SQL Injection: Boolean tautology (' OR '1'='1)
    std::string sqli_or =
        "POST /login.php HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "user=' OR '1'='1&pass=foo";

    auto res_sqli2 = inspector.inspect(http_flow, reinterpret_cast<const uint8_t*>(sqli_or.data()), sqli_or.size());
    TEST_ASSERT(res_sqli2.is_threat && res_sqli2.action == RuleAction::DROP, "SQLi Boolean tautology detected & dropped");

    // 4. XSS: Script tag injection
    std::string xss_script =
        "GET /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1\r\n"
        "Host: vulnerable.org\r\n\r\n";

    auto res_xss1 = inspector.inspect(http_flow, reinterpret_cast<const uint8_t*>(xss_script.data()), xss_script.size());
    TEST_ASSERT(res_xss1.is_threat && res_xss1.action == RuleAction::DROP, "XSS script tag detected & dropped");

    // 5. Path Traversal: /etc/passwd
    std::string path_trav =
        "GET /download.php?file=../../../../etc/passwd HTTP/1.1\r\n"
        "Host: target.com\r\n\r\n";

    auto res_trav = inspector.inspect(http_flow, reinterpret_cast<const uint8_t*>(path_trav.data()), path_trav.size());
    TEST_ASSERT(res_trav.is_threat && res_trav.action == RuleAction::DROP, "Path traversal detected & dropped");

    // 6. Malicious Scanner User-Agent: sqlmap
    std::string scanner_ua =
        "GET /api/v1/test HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "User-Agent: sqlmap/1.6#stable (https://sqlmap.org)\r\n\r\n";

    auto res_scan = inspector.inspect(http_flow, reinterpret_cast<const uint8_t*>(scanner_ua.data()), scanner_ua.size());
    TEST_ASSERT(res_scan.is_threat && res_scan.category == "MALICIOUS_UA", "Malicious scanner User-Agent detected");
}

void testInspectorDnsAndEntropy() {
    std::cout << "\n=== Running L7 Inspector (DNS & Tunneling) Tests ===\n";

    Inspector inspector;
    FlowTuple dns_flow(FlowTuple::stringToIp("192.168.1.10"), FlowTuple::stringToIp("8.8.8.8"), 51234, 53, TransportProtocol::UDP);

    // Build synthetic DNS Query wire format for "www.google.com"
    std::vector<uint8_t> clean_dns = {
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Standard query, recursion desired
        0x00, 0x01, // 1 Question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answers, Authority, Additional = 0
        0x03, 'w', 'w', 'w',
        0x06, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00, // Terminating null byte
        0x00, 0x01, // Type A
        0x00, 0x01  // Class IN
    };

    auto res_clean_dns = inspector.inspect(dns_flow, clean_dns.data(), clean_dns.size());
    TEST_ASSERT(!res_clean_dns.is_threat, "Standard DNS query accepted");

    // High Entropy DNS Tunneling Payload: "4a8f9c2d1b7e3f0a5b6c7d8e9f0a1b2c3d4e5f6a.tunnel.evil.com"
    std::string tunnel_label = "4a8f9c2d1b7e3f0a5b6c7d8e9f0a1b2c3d4e5f6a";
    std::vector<uint8_t> tunnel_dns = {
        0x56, 0x78,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    tunnel_dns.push_back(static_cast<uint8_t>(tunnel_label.size()));
    for (char c : tunnel_label) tunnel_dns.push_back(static_cast<uint8_t>(c));
    tunnel_dns.push_back(0x06);
    for (char c : std::string("tunnel")) tunnel_dns.push_back(static_cast<uint8_t>(c));
    tunnel_dns.push_back(0x04);
    for (char c : std::string("evil")) tunnel_dns.push_back(static_cast<uint8_t>(c));
    tunnel_dns.push_back(0x03);
    for (char c : std::string("com")) tunnel_dns.push_back(static_cast<uint8_t>(c));
    tunnel_dns.push_back(0x00);
    tunnel_dns.push_back(0x00); tunnel_dns.push_back(0x10); // TXT
    tunnel_dns.push_back(0x00); tunnel_dns.push_back(0x01); // IN

    auto res_tunnel = inspector.inspect(dns_flow, tunnel_dns.data(), tunnel_dns.size());
    TEST_ASSERT(res_tunnel.is_threat && res_tunnel.category == "DNS_TUNNEL", "High entropy DNS tunneling detected & blocked");
}

void testPacketDecoder() {
    std::cout << "\n=== Running Packet Decoder Tests ===\n";

    // Synthetic raw IPv4 + TCP packet buffer
    std::vector<uint8_t> raw_pkt = {
        // IPv4 Header (20 bytes)
        0x45, 0x00, 0x00, 0x3C, // Version=4, IHL=5, Total Len=60
        0x1C, 0x46, 0x40, 0x00, // ID, Flags=DF, Frag=0
        0x40, 0x06, 0x00, 0x00, // TTL=64, Proto=TCP(6), Checksum=0
        0x7F, 0x00, 0x00, 0x01, // Src IP: 127.0.0.1
        0x7F, 0x00, 0x00, 0x01, // Dst IP: 127.0.0.1
        // TCP Header (20 bytes)
        0x1F, 0x90, 0x00, 0x50, // Src Port: 8080, Dst Port: 80
        0x00, 0x00, 0x00, 0x01, // Seq Num
        0x00, 0x00, 0x00, 0x00, // Ack Num
        0x50, 0x02, 0x72, 0x10, // Data Offset=5 (20 bytes), Flags=SYN(0x02), Win Size
        0x00, 0x00, 0x00, 0x00  // Checksum, Urgent Pointer
    };
    // Append 20 bytes of dummy payload
    for (int i = 0; i < 20; ++i) raw_pkt.push_back(static_cast<uint8_t>('A' + i));

    DecodedPacket decoded = Interceptor::decodeIpPacket(raw_pkt.data(), raw_pkt.size());
    TEST_ASSERT(decoded.valid, "Packet decoding succeeded");
    TEST_ASSERT(decoded.protocol == TransportProtocol::TCP, "Protocol is TCP");
    TEST_ASSERT(decoded.src_port == 8080 && decoded.dst_port == 80, "Ports match expected 8080 -> 80");
    TEST_ASSERT(decoded.tcp_flags == TCP_FLAG_SYN, "Flags match SYN");
    TEST_ASSERT(decoded.payload_len == 20, "Payload length correctly calculated");
}

int main() {
    std::cout << "\033[1;33m====================================================\n"
              << "   STATEFUL FIREWALL UNIT & INTEGRATION TEST SUITE\n"
              << "====================================================\033[0m\n";

    testProtocolAndHashing();
    testConntrackStateMachine();
    testInspectorHttpAndSignatures();
    testInspectorDnsAndEntropy();
    testPacketDecoder();

    std::cout << "\n\033[1;32m====================================================\n"
              << "   ALL TEST SUITES PASSED SUCCESSFULLY (100% OK)\n"
              << "====================================================\033[0m\n";

    return EXIT_SUCCESS;
}

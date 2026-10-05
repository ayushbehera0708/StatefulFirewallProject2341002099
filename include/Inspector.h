#ifndef FIREWALL_INSPECTOR_H
#define FIREWALL_INSPECTOR_H

#include "Protocol.h"

#include <cstdint>
#include <memory>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

namespace firewall {

/**
 * @brief Action executed when an inspection rule matches.
 */
enum class RuleAction : uint8_t {
    ALLOW = 0,
    ALERT,
    DROP
};

/**
 * @brief Target packet or application layer payload region for rule evaluation.
 */
enum class TargetField : uint8_t {
    ANY = 0,
    URI,
    HEADER,
    BODY,
    DNS
};

/**
 * @brief Represents a compiled signature rule.
 */
struct Rule {
    std::string id;
    TargetField target{TargetField::ANY};
    RuleAction action{RuleAction::DROP};
    std::regex pattern;
    std::string raw_pattern;
    std::string category;       // e.g., "SQLI", "XSS", "TRAVERSAL", "RCE", "MALICIOUS_UA", "DNS"
    std::string description;
};

/**
 * @brief Outcome of a Layer 7 payload inspection.
 */
struct InspectionResult {
    bool is_threat{false};
    RuleAction action{RuleAction::ALLOW};
    std::string rule_id;
    std::string category;
    std::string description;
    std::string matched_field;
    std::string matched_snippet;

    std::string toString() const;
};

/**
 * @brief Parsed HTTP Request elements.
 */
struct HttpRequest {
    bool is_http{false};
    std::string method;
    std::string uri;
    std::string decoded_uri;
    std::string version;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

/**
 * @brief Parsed DNS Query elements.
 */
struct DnsQuery {
    bool is_dns{false};
    uint16_t transaction_id{0};
    uint16_t flags{0};
    uint16_t qdcount{0};
    std::string domain_name;
    uint16_t qtype{0};
    uint16_t qclass{0};
    double entropy{0.0};
};

/**
 * @brief Layer 7 Deep Packet Inspection (DPI) & Intrusion Filter engine.
 */
class Inspector {
public:
    Inspector();
    ~Inspector() = default;

    /**
     * @brief Loads custom signature rules from a configuration file.
     * @param filepath Path to the rules configuration file.
     * @return Number of rules successfully loaded.
     */
    size_t loadRulesFromFile(const std::string& filepath);

    /**
     * @brief Adds a programmatic rule to the engine.
     */
    void addRule(const Rule& rule);

    /**
     * @brief Inspects application layer payload for threats.
     * @param tuple Network flow 5-tuple.
     * @param payload Raw payload bytes.
     * @param length Payload length in bytes.
     * @return InspectionResult detailing threat or allow decision.
     */
    InspectionResult inspect(const FlowTuple& tuple, const uint8_t* payload, size_t length) const;

    /**
     * @brief Parses an unencrypted HTTP request from raw payload bytes.
     */
    static HttpRequest parseHttpRequest(const uint8_t* payload, size_t length);

    /**
     * @brief Parses a DNS query packet from raw payload bytes.
     */
    static DnsQuery parseDnsQuery(const uint8_t* payload, size_t length);

    /**
     * @brief URL-decodes percentage-encoded strings (%20 -> space, %27 -> ', etc.).
     */
    static std::string urlDecode(const std::string& encoded);

    /**
     * @brief Computes Shannon entropy of a string (useful for DNS tunneling detection).
     */
    static double calculateEntropy(const std::string& str);

    static std::string targetFieldToString(TargetField target);
    static TargetField stringToTargetField(const std::string& str);
    static std::string ruleActionToString(RuleAction action);
    static RuleAction stringToRuleAction(const std::string& str);

private:
    void initDefaultRules();
    InspectionResult evaluateTarget(TargetField field, const std::string& content, const std::string& field_name) const;

    std::vector<Rule> rules_;
};

} // namespace firewall

#endif // FIREWALL_INSPECTOR_H

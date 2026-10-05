#include "Inspector.h"
#include "Logger.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace firewall {

Inspector::Inspector() {
    initDefaultRules();
}

void Inspector::initDefaultRules() {
    constexpr auto icase_opt = std::regex::icase | std::regex::optimize;
    constexpr auto opt = std::regex::optimize;

    // -------------------------------------------------------------
    // SQL Injection Rules
    // -------------------------------------------------------------
    addRule({
        "SQLI-001",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"((union\s+(all\s+)?select))", icase_opt),
        R"((union\s+(all\s+)?select))",
        "SQLI",
        "Classic UNION SELECT SQL injection attempt"
    });

    addRule({
        "SQLI-002",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"('(\s*or\s*|\s*and\s*)[^\r\n]+[=<>])", icase_opt),
        R"('(\s*or\s*|\s*and\s*)[^\r\n]+[=<>])",
        "SQLI",
        "Boolean-based tautology SQL injection (' OR 1=1)"
    });

    addRule({
        "SQLI-003",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"((sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay|pg_sleep))", icase_opt),
        R"((sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay|pg_sleep))",
        "SQLI",
        "Time-based blind SQL injection attempt"
    });

    addRule({
        "SQLI-004",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"((information_schema\.(tables|columns)|sys\.(tables|databases)))", icase_opt),
        R"((information_schema\.(tables|columns)|sys\.(tables|databases)))",
        "SQLI",
        "Database schema metadata enumeration probe"
    });

    addRule({
        "SQLI-005",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"((;\s*exec\s*\(|xp_cmdshell|exec\s+sp_))", icase_opt),
        R"((;\s*exec\s*\(|xp_cmdshell|exec\s+sp_))",
        "SQLI",
        "Stacked query / Command execution SQLi"
    });

    // -------------------------------------------------------------
    // Cross-Site Scripting (XSS) Rules
    // -------------------------------------------------------------
    addRule({
        "XSS-001",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"((<\s*script[^>]*>|javascript\s*:))", icase_opt),
        R"((<\s*script[^>]*>|javascript\s*:))",
        "XSS",
        "Inline script tag or javascript URI vector"
    });

    addRule({
        "XSS-002",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"((on(load|error|click|mouseover|submit|focus|blur)\s*=))", icase_opt),
        R"((on(load|error|click|mouseover|submit|focus|blur)\s*=))",
        "XSS",
        "DOM Event Handler injection vector"
    });

    addRule({
        "XSS-003",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"((<\s*(img|svg|iframe|body|input)[^>]+(onerror|onload)\s*=))", icase_opt),
        R"((<\s*(img|svg|iframe|body|input)[^>]+(onerror|onload)\s*=))",
        "XSS",
        "HTML5 media tag payload vector"
    });

    addRule({
        "XSS-004",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"((document\.(cookie|location|write)|window\.location))", icase_opt),
        R"((document\.(cookie|location|write)|window\.location))",
        "XSS",
        "Sensitive client-side DOM object access"
    });

    // -------------------------------------------------------------
    // Path Traversal & LFI Rules
    // -------------------------------------------------------------
    addRule({
        "TRAV-001",
        TargetField::URI,
        RuleAction::DROP,
        std::regex(R"((\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f))", opt),
        R"((\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f))",
        "TRAVERSAL",
        "Directory traversal path manipulation"
    });

    addRule({
        "TRAV-002",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"((/etc/(passwd|shadow|hosts|issue)|boot\.ini|winnt/system32))", icase_opt),
        R"((/etc/(passwd|shadow|hosts|issue)|boot\.ini|winnt/system32))",
        "TRAVERSAL",
        "Critical system file access attempt"
    });

    // -------------------------------------------------------------
    // Remote Code Execution (RCE) / Command Injection Rules
    // -------------------------------------------------------------
    addRule({
        "RCE-001",
        TargetField::ANY,
        RuleAction::DROP,
        std::regex(R"((\|\||;|&|`|\$\()\s*(cat\s+/etc/passwd|id\b|whoami\b|uname\s+-a|nc\s+-e|bash\s+-i|curl\s+http|wget\s+http))", opt),
        R"((\|\||;|&|`|\$\()\s*(cat\s+/etc/passwd|id\b|whoami\b|uname\s+-a|nc\s+-e|bash\s+-i|curl\s+http|wget\s+http))",
        "RCE",
        "Shell command chaining and reverse shell execution"
    });

    // -------------------------------------------------------------
    // Malicious Scanner / Bot Detection Rules
    // -------------------------------------------------------------
    addRule({
        "SCAN-001",
        TargetField::HEADER,
        RuleAction::DROP,
        std::regex(R"((sqlmap|nikto|w3af|dirbuster|acunetix|masscan|zgrab|nmap\s+scripting))", icase_opt),
        R"((sqlmap|nikto|w3af|dirbuster|acunetix|masscan|zgrab|nmap\s+scripting))",
        "MALICIOUS_UA",
        "Known vulnerability scanner or crawler User-Agent"
    });
}

void Inspector::addRule(const Rule& rule) {
    rules_.push_back(rule);
}

size_t Inspector::loadRulesFromFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        LOG_WARN("Inspector: Unable to open rule configuration file: " + filepath);
        return 0;
    }

    std::string line;
    size_t count = 0;
    size_t line_num = 0;

    while (std::getline(file, line)) {
        ++line_num;
        // Trim leading whitespace
        line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));

        if (line.empty() || line[0] == '#') {
            continue; // Skip comments and blank lines
        }

        // Expected format: RULE <id> <target> <action> <category> "<pattern>" <description>
        if (line.rfind("RULE", 0) != 0) {
            continue;
        }

        std::istringstream iss(line);
        std::string token, id, target_str, action_str, category;
        iss >> token >> id >> target_str >> action_str >> category;

        // Extract quoted pattern
        size_t first_quote = line.find('"', iss.tellg());
        if (first_quote == std::string::npos) {
            LOG_WARN("Inspector: Missing pattern quotes at line " + std::to_string(line_num));
            continue;
        }
        size_t second_quote = line.find('"', first_quote + 1);
        if (second_quote == std::string::npos) {
            LOG_WARN("Inspector: Unclosed pattern quote at line " + std::to_string(line_num));
            continue;
        }

        std::string pattern_str = line.substr(first_quote + 1, second_quote - first_quote - 1);
        std::string desc = line.substr(second_quote + 1);
        // Trim desc
        desc.erase(desc.begin(), std::find_if(desc.begin(), desc.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));

        try {
            Rule rule;
            rule.id = id;
            rule.target = stringToTargetField(target_str);
            rule.action = stringToRuleAction(action_str);
            rule.category = category;
            auto regex_flags = std::regex::optimize;
            if (pattern_str.rfind("(?i)", 0) == 0) {
                pattern_str = pattern_str.substr(4);
                regex_flags |= std::regex::icase;
            }
            rule.pattern = std::regex(pattern_str, regex_flags);

            addRule(std::move(rule));
            ++count;
        } catch (const std::regex_error& e) {
            LOG_ERROR("Inspector: Invalid regex on line " + std::to_string(line_num) + ": " + e.what());
        }
    }

    LOG_INFO("Inspector: Successfully loaded " + std::to_string(count) + " rules from " + filepath);
    return count;
}

std::string Inspector::urlDecode(const std::string& encoded) {
    std::string out;
    out.reserve(encoded.size());

    for (size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            char h1 = encoded[i + 1];
            char h2 = encoded[i + 2];
            if (std::isxdigit(h1) && std::isxdigit(h2)) {
                auto hexToVal = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    return 0;
                };
                char byte = static_cast<char>((hexToVal(h1) << 4) | hexToVal(h2));
                out.push_back(byte);
                i += 2;
                continue;
            }
        } else if (encoded[i] == '+') {
            out.push_back(' ');
            continue;
        }
        out.push_back(encoded[i]);
    }
    return out;
}

double Inspector::calculateEntropy(const std::string& str) {
    if (str.empty()) return 0.0;
    std::unordered_map<char, size_t> freqs;
    for (char c : str) {
        ++freqs[c];
    }
    double entropy = 0.0;
    double len = static_cast<double>(str.size());
    for (const auto& [_, count] : freqs) {
        double p = count / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

HttpRequest Inspector::parseHttpRequest(const uint8_t* payload, size_t length) {
    HttpRequest req;
    if (payload == nullptr || length < 10) {
        return req;
    }

    std::string raw(reinterpret_cast<const char*>(payload), length);

    // Fast check for standard HTTP methods
    const std::vector<std::string> valid_methods = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "
    };

    bool method_found = false;
    for (const auto& m : valid_methods) {
        if (raw.rfind(m, 0) == 0) {
            method_found = true;
            break;
        }
    }

    if (!method_found) {
        return req;
    }

    req.is_http = true;

    // Parse Request Line
    size_t line_end = raw.find("\r\n");
    if (line_end == std::string::npos) {
        line_end = raw.find('\n');
    }
    if (line_end == std::string::npos) {
        return req;
    }

    std::string req_line = raw.substr(0, line_end);
    std::istringstream line_iss(req_line);
    line_iss >> req.method >> req.uri >> req.version;
    req.decoded_uri = urlDecode(req.uri);

    // Parse Headers
    size_t header_start = line_end + (raw[line_end] == '\r' ? 2 : 1);
    size_t header_end = raw.find("\r\n\r\n", header_start);
    size_t body_start = std::string::npos;

    if (header_end != std::string::npos) {
        body_start = header_end + 4;
    } else {
        header_end = raw.find("\n\n", header_start);
        if (header_end != std::string::npos) {
            body_start = header_end + 2;
        }
    }

    size_t headers_len = (header_end != std::string::npos) ? (header_end - header_start) : (raw.size() - header_start);
    std::string headers_blob = raw.substr(header_start, headers_len);

    std::istringstream headers_iss(headers_blob);
    std::string hline;
    while (std::getline(headers_iss, hline)) {
        if (!hline.empty() && hline.back() == '\r') {
            hline.pop_back();
        }
        size_t colon = hline.find(':');
        if (colon != std::string::npos) {
            std::string key = hline.substr(0, colon);
            std::string val = hline.substr(colon + 1);
            // Trim leading space
            val.erase(val.begin(), std::find_if(val.begin(), val.end(), [](unsigned char ch) {
                return !std::isspace(ch);
            }));
            // Lowercase header key
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
                return std::tolower(c);
            });
            req.headers[key] = val;
        }
    }

    if (body_start != std::string::npos && body_start < raw.size()) {
        req.body = raw.substr(body_start);
    }

    return req;
}

DnsQuery Inspector::parseDnsQuery(const uint8_t* payload, size_t length) {
    DnsQuery dns;
    // Standard DNS Header is 12 bytes
    if (payload == nullptr || length < 12) {
        return dns;
    }

    dns.transaction_id = static_cast<uint16_t>((payload[0] << 8) | payload[1]);
    dns.flags = static_cast<uint16_t>((payload[2] << 8) | payload[3]);
    dns.qdcount = static_cast<uint16_t>((payload[4] << 8) | payload[5]);

    // If QDCOUNT is 0 or QR bit is 1 (response), it's not a standard query
    bool is_query = (dns.flags & 0x8000) == 0;
    if (!is_query || dns.qdcount == 0) {
        return dns;
    }

    size_t offset = 12;
    std::string domain;
    bool jumped = false;
    size_t jump_count = 0;

    while (offset < length) {
        uint8_t len = payload[offset];
        if (len == 0) {
            offset += 1;
            break; // End of domain labels
        }

        // Pointer compression check (0xC0)
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= length) break;
            uint16_t ptr_offset = static_cast<uint16_t>(((len & 0x3F) << 8) | payload[offset + 1]);
            offset += 2;
            if (!jumped) {
                // follow pointer
                offset = ptr_offset;
                jumped = true;
            }
            if (++jump_count > 10) break; // Avoid pointer cycles
            continue;
        }

        offset += 1;
        if (offset + len > length) {
            break; // Malformed label length
        }

        if (!domain.empty()) {
            domain.push_back('.');
        }
        domain.append(reinterpret_cast<const char*>(payload + offset), len);
        offset += len;
    }

    if (offset + 4 <= length) {
        dns.qtype = static_cast<uint16_t>((payload[offset] << 8) | payload[offset + 1]);
        dns.qclass = static_cast<uint16_t>((payload[offset + 2] << 8) | payload[offset + 3]);
    }

    if (!domain.empty()) {
        dns.is_dns = true;
        dns.domain_name = domain;
        dns.entropy = calculateEntropy(domain);
    }

    return dns;
}

InspectionResult Inspector::evaluateTarget(TargetField field, const std::string& content, const std::string& field_name) const {
    InspectionResult res;
    if (content.empty()) {
        return res;
    }

    for (const auto& rule : rules_) {
        if (rule.target != TargetField::ANY && rule.target != field) {
            continue;
        }

        std::smatch match;
        if (std::regex_search(content, match, rule.pattern)) {
            res.is_threat = true;
            res.action = rule.action;
            res.rule_id = rule.id;
            res.category = rule.category;
            res.description = rule.description;
            res.matched_field = field_name;
            res.matched_snippet = match.str();
            return res;
        }
    }

    return res;
}

InspectionResult Inspector::inspect(const FlowTuple& tuple, const uint8_t* payload, size_t length) const {
    InspectionResult result;
    if (payload == nullptr || length == 0) {
        return result;
    }

    // 1. Check for DNS Queries (UDP or TCP port 53)
    if (tuple.dst_port == 53 || tuple.src_port == 53) {
        DnsQuery dns = parseDnsQuery(payload, length);
        if (dns.is_dns) {
            // Check RFC limits
            if (dns.domain_name.size() > 253) {
                result.is_threat = true;
                result.action = RuleAction::DROP;
                result.rule_id = "DNS-RFC-OVERSIZE";
                result.category = "DNS_ANOMALY";
                result.description = "Domain length exceeds RFC limit of 253 bytes";
                result.matched_field = "dns.qname";
                result.matched_snippet = dns.domain_name.substr(0, 50) + "...";
                return result;
            }

            // High-entropy tunneling heuristic: long domain name with entropy > 4.4
            if (dns.domain_name.size() > 50 && dns.entropy > 4.4) {
                result.is_threat = true;
                result.action = RuleAction::DROP;
                result.rule_id = "DNS-TUNNEL-ENTROPY";
                result.category = "DNS_TUNNEL";
                result.description = "Suspicious high-entropy DNS query indicative of tunneling or DGA";
                result.matched_field = "dns.qname";
                std::ostringstream ss;
                ss << dns.domain_name << " (entropy: " << std::fixed << std::setprecision(2) << dns.entropy << ")";
                result.matched_snippet = ss.str();
                return result;
            }

            // Run DNS signature checks
            result = evaluateTarget(TargetField::DNS, dns.domain_name, "dns.qname");
            if (result.is_threat) return result;
        }
    }

    // 2. Check for HTTP Request
    HttpRequest http = parseHttpRequest(payload, length);
    if (http.is_http) {
        // Inspect URI (both raw and URL-decoded)
        result = evaluateTarget(TargetField::URI, http.uri, "http.uri");
        if (result.is_threat) return result;

        if (http.uri != http.decoded_uri) {
            result = evaluateTarget(TargetField::URI, http.decoded_uri, "http.decoded_uri");
            if (result.is_threat) return result;
        }

        // Inspect Headers
        for (const auto& [header_name, header_val] : http.headers) {
            result = evaluateTarget(TargetField::HEADER, header_val, "http.header." + header_name);
            if (result.is_threat) return result;
        }

        // Inspect Body
        if (!http.body.empty()) {
            result = evaluateTarget(TargetField::BODY, http.body, "http.body");
            if (result.is_threat) return result;
        }
    }

    // 3. Fallback generic inspection against ANY rules on raw payload
    std::string raw_str(reinterpret_cast<const char*>(payload), std::min(length, size_t(4096)));
    result = evaluateTarget(TargetField::ANY, raw_str, "payload.raw");
    return result;
}

std::string InspectionResult::toString() const {
    std::ostringstream oss;
    oss << "Threat: " << (is_threat ? "YES" : "NO")
        << " | Action: " << Inspector::ruleActionToString(action)
        << " | Rule: " << rule_id << " [" << category << "]"
        << " | Target: " << matched_field
        << " | Snippet: \"" << matched_snippet << "\""
        << " | Info: " << description;
    return oss.str();
}

std::string Inspector::targetFieldToString(TargetField target) {
    switch (target) {
        case TargetField::ANY:    return "ANY";
        case TargetField::URI:    return "URI";
        case TargetField::HEADER: return "HEADER";
        case TargetField::BODY:   return "BODY";
        case TargetField::DNS:    return "DNS";
        default:                  return "UNKNOWN";
    }
}

TargetField Inspector::stringToTargetField(const std::string& str) {
    if (str == "URI") return TargetField::URI;
    if (str == "HEADER") return TargetField::HEADER;
    if (str == "BODY") return TargetField::BODY;
    if (str == "DNS") return TargetField::DNS;
    return TargetField::ANY;
}

std::string Inspector::ruleActionToString(RuleAction action) {
    switch (action) {
        case RuleAction::ALLOW: return "ALLOW";
        case RuleAction::ALERT: return "ALERT";
        case RuleAction::DROP:  return "DROP";
        default:                return "ALLOW";
    }
}

RuleAction Inspector::stringToRuleAction(const std::string& str) {
    if (str == "DROP") return RuleAction::DROP;
    if (str == "ALERT") return RuleAction::ALERT;
    return RuleAction::ALLOW;
}

} // namespace firewall

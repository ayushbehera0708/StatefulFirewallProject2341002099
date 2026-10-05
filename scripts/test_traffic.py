#!/usr/bin/env python3
"""
Stateful Application-Layer Firewall & Intrusion Filter - Test Traffic Generator
Author: Ayush Behera

Sends representative benign and malicious traffic vectors to test the firewall:
1. Benign HTTP GET request
2. SQL Injection (UNION SELECT, Boolean tautology, Time-based blind)
3. Cross-Site Scripting (XSS inline script, event handlers)
4. Path Traversal & LFI (/etc/passwd, directory traversal)
5. Remote Code Execution (Command chaining, reverse shell patterns)
6. Malicious Scanner User-Agents (sqlmap, nikto)
7. DNS queries (Normal and suspicious high-entropy queries)
"""

import sys
import socket
import time
import argparse
import urllib.request
import urllib.error

def send_raw_http(host, port, raw_request):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((host, port))
        s.sendall(raw_request.encode('utf-8'))
        response = s.recv(4096)
        s.close()
        return True, response.decode('utf-8', errors='ignore')
    except socket.timeout:
        return False, "TIMEOUT (Packet likely dropped by firewall)"
    except ConnectionResetError:
        return False, "RESET (Connection reset by peer/firewall)"
    except Exception as e:
        return False, str(e)

def run_tests(host, port):
    print(f"[*] Dispatching test traffic against target {host}:{port}...\n")

    test_cases = [
        {
            "name": "Benign HTTP Request",
            "expect": "ALLOW",
            "payload": f"GET /index.html HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        },
        {
            "name": "SQL Injection: UNION SELECT",
            "expect": "DROP",
            "payload": f"GET /search?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1\r\nHost: {host}\r\n\r\n"
        },
        {
            "name": "SQL Injection: Boolean Tautology (' OR '1'='1)",
            "expect": "DROP",
            "payload": f"POST /login HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 29\r\n\r\nuser=' OR '1'='1&pass=secret"
        },
        {
            "name": "Cross-Site Scripting: <script> Tag",
            "expect": "DROP",
            "payload": f"GET /profile?name=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1\r\nHost: {host}\r\n\r\n"
        },
        {
            "name": "Cross-Site Scripting: Event Handler onerror",
            "expect": "DROP",
            "payload": f"GET /img?src=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1\r\nHost: {host}\r\n\r\n"
        },
        {
            "name": "Path Traversal: /etc/passwd",
            "expect": "DROP",
            "payload": f"GET /download?file=../../../../etc/passwd HTTP/1.1\r\nHost: {host}\r\n\r\n"
        },
        {
            "name": "Command Injection / RCE: ; cat /etc/passwd",
            "expect": "DROP",
            "payload": f"GET /exec?cmd=127.0.0.1;%20cat%20/etc/passwd HTTP/1.1\r\nHost: {host}\r\n\r\n"
        },
        {
            "name": "Malicious Scanner User-Agent: sqlmap",
            "expect": "DROP",
            "payload": f"GET /api/v1 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sqlmap/1.7#stable\r\n\r\n"
        }
    ]

    for idx, tc in enumerate(test_cases, 1):
        print(f"[{idx}/{len(test_cases)}] Testing: {tc['name']} (Expected: {tc['expect']})")
        success, info = send_raw_http(host, port, tc["payload"])
        if success:
            print(f"    -> Response: Received {len(info)} bytes")
        else:
            print(f"    -> Blocked/Timeout: {info}")
        time.sleep(0.5)

    print("\n[*] Test sequence complete. Check firewall.log for intrusion records.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firewall Intrusion Test Traffic Generator")
    parser.add_argument("--host", default="127.0.0.1", help="Target server host")
    parser.add_argument("--port", type=int, default=80, help="Target server port")
    args = parser.parse_args()

    run_tests(args.host, args.port)

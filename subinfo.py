#!/usr/bin/env python3
"""
subinfo
Advanced .onion virtual service discovery tool
Author: You
Purpose: Academic & Research Use
"""

import requests
import argparse
import hashlib
import json
import time
from datetime import datetime

# =========================
# TOR CONFIGURATION
# =========================
TOR_PROXY = "socks5h://127.0.0.1:9050"

PROXIES = {
    "http": TOR_PROXY,
    "https": TOR_PROXY
}

BASE_HEADERS = {
    "User-Agent": "subinfo/1.0 (Research Tool)"
}

# =========================
# TOR SESSION
# =========================
def create_tor_session():
    session = requests.Session()
    session.proxies.update(PROXIES)
    session.headers.update(BASE_HEADERS)
    return session

# =========================
# VIRTUAL HOST ENUMERATION
# =========================
def enumerate_services(session, onion, words, delay):
    results = []

    print("\n[+] Enumerating virtual services...\n")

    for word in words:
        virtual_host = f"{word}.{onion}"
        headers = {"Host": virtual_host}

        try:
            r = session.head(
                f"http://{onion}",
                headers=headers,
                timeout=20,
                allow_redirects=False
            )

            if r.status_code in [200, 301, 302, 401, 403]:
                print(f"[FOUND] {virtual_host} ({r.status_code})")
                results.append({
                    "service": virtual_host,
                    "status": r.status_code,
                    "headers": dict(r.headers)
                })

        except requests.RequestException:
            pass

        time.sleep(delay)

    return results

# =========================
# FINGERPRINTING
# =========================
def fingerprint(session, onion, host):
    headers = {"Host": host}

    try:
        r = session.get(
            f"http://{onion}",
            headers=headers,
            timeout=25
        )

        content = r.text
        hashval = hashlib.sha256(content.encode()).hexdigest()

        title = "N/A"
        if "<title>" in content.lower():
            try:
                title = content.split("<title>")[1].split("</title>")[0]
            except:
                pass

        return {
            "title": title,
            "length": len(content),
            "hash": hashval
        }

    except requests.RequestException:
        return None

# =========================
# REPORT GENERATION
# =========================
def generate_report(onion, data):
    report = {
        "tool": "subinfo",
        "target": onion,
        "scan_time": datetime.utcnow().isoformat(),
        "results": data
    }

    filename = f"subinfo_report_{int(time.time())}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n[+] Report saved as {filename}")

# =========================
# MAIN FUNCTION
# =========================
def main():
    parser = argparse.ArgumentParser(
        description="subinfo - .onion Virtual Service Discovery Tool"
    )

    parser.add_argument("-t", "--target", required=True, help="Target .onion address")
    parser.add_argument("-d", "--delay", type=float, default=3, help="Delay between requests")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")

    args = parser.parse_args()

    default_words = [
        "admin","mail","blog","dev","test",
        "secure","internal","hidden","panel",
        "dashboard","staff","backup"
    ]

    if args.wordlist:
        with open(args.wordlist, "r") as f:
            words = [line.strip() for line in f if line.strip()]
    else:
        words = default_words

    session = create_tor_session()

    findings = enumerate_services(
        session,
        args.target,
        words,
        args.delay
    )

    print("\n[+] Fingerprinting discovered services...\n")

    for item in findings:
        item["fingerprint"] = fingerprint(
            session,
            args.target,
            item["service"]
        )

    generate_report(args.target, findings)

    print("\n[+] subinfo scan completed")

# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    main()

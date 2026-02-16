import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import datetime



# 1) CRAWLER
def crawl_website(start_url, max_pages=30):
    visited = set()
    to_visit = [start_url]

    domain = urlparse(start_url).netloc

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)

        if url in visited:
            continue

        try:
            response = requests.get(url, timeout=10)
            visited.add(url)

            soup = BeautifulSoup(response.text, "html.parser")

            for link_tag in soup.find_all("a", href=True):
                link = link_tag["href"]
                full_url = urljoin(url, link)

                # Only crawl links in the same domain
                if urlparse(full_url).netloc == domain:
                    if full_url not in visited and full_url not in to_visit:
                        to_visit.append(full_url)

        except:
            continue

    return list(visited)



# 2) SECURITY HEADERS CHECKER

def check_security_headers(url):
    important_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    results = {}

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        for h in important_headers:
            results[h] = headers.get(h, "MISSING")

    except Exception as e:
        results["error"] = str(e)

    return results


# 3) BASIC SQLi + XSS TESTS

def test_basic_payloads(url):
    payloads = {
        "SQL Injection": "' OR '1'='1",
        "XSS": "<script>alert(1)</script>"
    }

    findings = []

    for attack_type, payload in payloads.items():
        try:
            # Add payload to URL as a query parameter
            test_url = url + ("&" if "?" in url else "?") + "q=" + payload

            response = requests.get(test_url, timeout=10)

            # Very basic detection
            if attack_type == "SQL Injection":
                errors = ["sql", "mysql", "syntax", "warning", "database", "pdo"]
                if any(err in response.text.lower() for err in errors):
                    findings.append(f"[POSSIBLE SQLi] {test_url}")

            if attack_type == "XSS":
                if payload.lower() in response.text.lower():
                    findings.append(f"[POSSIBLE XSS] {test_url}")

        except:
            continue

    return findings



# 4) REPORT GENERATOR

def save_report(target, crawled_links, header_report, vuln_report):
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_report_{now}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("INTERNcred - Web Application Security Scanner Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Date: {now}\n\n")

        f.write("1) Crawled Pages\n")
        f.write("-" * 30 + "\n")
        for link in crawled_links:
            f.write(link + "\n")

        f.write("\n2) Security Headers Check\n")
        f.write("-" * 30 + "\n")
        for page, headers in header_report.items():
            f.write(f"\nPage: {page}\n")
            for h, v in headers.items():
                f.write(f"  {h}: {v}\n")

        f.write("\n3) Vulnerability Payload Tests (Basic)\n")
        f.write("-" * 30 + "\n")
        if vuln_report:
            for finding in vuln_report:
                f.write(finding + "\n")
        else:
            f.write("No obvious SQLi/XSS indicators found.\n")

    return filename


# MAIN PROGRAM

def main():
    print("\n=== Interncred Task 1: Web Security Scanner ===\n")
    target = input("Enter website URL (example: https://example.com): ").strip()

    print("\n[1/3] Crawling website...")
    links = crawl_website(target, max_pages=20)
    print(f"Found {len(links)} pages.\n")

    print("[2/3] Checking security headers...")
    header_report = {}
    for link in links:
        header_report[link] = check_security_headers(link)

    print("[3/3] Running basic SQLi/XSS tests...")
    vuln_report = []
    for link in links:
        vuln_report.extend(test_basic_payloads(link))

    print("\nSaving report...")
    report_file = save_report(target, links, header_report, vuln_report)

    print("\n Scan complete!")
    print(f" Report saved as: {report_file}")
    print("\nNOTE: Only scan websites you own or legal test sites.\n")


if __name__ == "__main__":
    main()

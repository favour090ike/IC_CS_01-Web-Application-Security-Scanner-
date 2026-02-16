# IC_CS_01-Web-Application-Security-Scanner-
A Python-based web application security scanner that crawls target URLs, checks security headers, and tests for basic SQLi/XSS vulnerabilities.
Interncred Task 1 – Web Application Security Scanner (IC_CS_01)

A Python-based Web Application Security Scanner built for the Interncred Cybersecurity Internship program.
This tool crawls a target website, checks for missing security headers, and performs basic SQL Injection and XSS payload testing.

Features

Website Crawling

Automatically collects internal links from the target domain

Security Headers Check

Detects missing headers such as:

Content-Security-Policy (CSP)

Strict-Transport-Security (HSTS)

X-Frame-Options

X-Content-Type-Options

Referrer-Policy

Permissions-Policy

Basic Vulnerability Testing

Tests for possible:

SQL Injection indicators (error-based)

Reflected XSS indicators

Report Generation

Generates a scan report after completion

Tech Stack

Python 3

Requests

BeautifulSoup4

How to Run
1. Clone the repository
git clone https://github.com/YOUR_USERNAME/IC_CS_01.git
cd IC_CS_01

2. Install requirements
pip install -r requirements.txt

3. Run the scanner
python scanner.py

4. Enter a target URL

Example:

https://example.com

Recommended Legal Test Sites

Use only websites you own or have permission to scan.

Recommended test website:

http://testphp.vulnweb.com
 (intentionally vulnerable demo site)

Project Output

The tool displays:

Crawled pages list

Security header status (present/missing)

Possible SQLi / XSS findings

Scan report saved locally

Disclaimer

This project is created for educational and internship purposes only.
Do not scan websites you do not own or have explicit permission to test.

Future Improvements

Add severity levels (High / Medium / Low)

Add form detection and testing

Improve crawling depth and filtering

Export report in HTML and JSON

Add multithreading for faster scanning

Author

Your Name Here
Interncred Cybersecurity Internship Candidate

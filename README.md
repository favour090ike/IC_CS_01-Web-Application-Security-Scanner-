# Interncred Task 1 – Web Application Security Scanner (IC_CS_01)

A Python-based Web Application Security Scanner .  
This tool crawls a target website, checks for missing security headers, and performs basic SQL Injection and XSS payload testing.

---

## Features

- **Website Crawling**
  - Automatically collects internal links from the target domain

- **Security Headers Check**
  - Detects missing headers such as:
    - Content-Security-Policy (CSP)
    - Strict-Transport-Security (HSTS)
    - X-Frame-Options
    - X-Content-Type-Options
    - Referrer-Policy
    - Permissions-Policy

- **Basic Vulnerability Testing**
  - Tests for possible:
    - SQL Injection indicators (error-based)
    - Reflected XSS indicators

- **Report Generation**
  - Generates a scan report after completion

---

## Tech Stack

- Python 3
- Requests
- BeautifulSoup4

---



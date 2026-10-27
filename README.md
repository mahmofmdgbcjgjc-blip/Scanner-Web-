Rush Squad Scanner PRO

A lightweight Python tool for website security configuration checks.

Features

- HTTP security headers analysis
- Cookie security attribute checks
- CORS configuration checks
- HTTP redirect inspection
- Robots.txt and Sitemap.xml checks
- Colored terminal interface
- JSON report generation
- Request limits and path exclusions

Requirements

- Python 3
- "requests"
- "rich"

Installation

pip install requests rich

Usage

python scanner.py

Run with a specific target:

python scanner.py --url https://example.com

Save a report:

python scanner.py --url https://example.com --report report.json

Community

Join the official Discord server for support and updates:

https://discord.gg/eDDWHfYfFN

Disclaimer

For authorized security testing only. Use this tool only on websites you own or have explicit permission to assess. Findings require manual verification.

Credits

Developed by Rush Squad.

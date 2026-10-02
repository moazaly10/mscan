# mscan - Lightweight Network Vulnerability Scanner

A fast, multithreaded network vulnerability scanner built with Python. `mscan` is designed to rapidly discover open ports, perform banner grabbing, and match running services against a local vulnerability database.

## Features
- **High Performance:** Utilizes `concurrent.futures` for multithreaded port scanning (I/O bound optimization).
- **Banner Grabbing:** Interacts with open ports (e.g., HTTP, SSH) to extract service versions.
- **Vulnerability Engine:** Cross-references extracted banners with known CVEs to detect potential security flaws.

## Tech Stack
- **Language:** Python 3
- **Core Libraries:** `socket`, `argparse`, `concurrent.futures`

## Usage
Run the scanner via the command line interface:
```bash
python mscan.py -t scanme.nmap.org -p 1-100 --threads 50
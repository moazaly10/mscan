import socket
import argparse
import concurrent.futures

VULN_DB = {
    "OpenSSH_6.6.1p1": "CVE-2015-5600 (MaxAuthTries bypass - User Enumeration)",
    "vsFTPd 2.3.4": "CVE-2011-2523 (Backdoor Command Execution)",
    "Apache/2.2.14": "CVE-2011-3192 (Denial of Service)",
    "FreeFTPd 1.0.10": "CVE-2013-4776 (Authentication Bypass)"
}

def grab_banner(s, port):
    try:
        if port in [80, 443, 8080]:
            s.send(b"HEAD / HTTP/1.1\r\n\r\n")
        
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        
        if banner:
            return banner.split('\n')[0].strip()
        return None
    except Exception:
        return None

def check_vuln(banner):
    if not banner:
        return None
    
    for vulnerable_version, cve_info in VULN_DB.items():
        if vulnerable_version in banner:
            return cve_info
            
    return None

def scan_port(target):
    ip, port = target
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0) 
    
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner(s, port)
            
            if banner:
                print(f"[+] OPEN: Port {port} on {ip} | Banner: {banner}")
                
                vuln_info = check_vuln(banner)
                if vuln_info:
                    print(f"    [!] VULNERABILITY FOUND: {vuln_info}")
            else:
                print(f"[+] OPEN: Port {port} on {ip}")
    except Exception:
        pass
    finally:
        s.close()

def main():
    parser = argparse.ArgumentParser(description="mscan - Lightweight Network Vulnerability Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--ports", default="1-100", help="Port range to scan")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads")
    
    args = parser.parse_args()
    target_ip = args.target
    start_port, end_port = map(int, args.ports.split('-'))
    
    print(f"--- Starting mscan on target: {target_ip} ---")
    print(f"--- Scanning ports {start_port} to {end_port} with {args.threads} threads ---")
    
    targets = [(target_ip, port) for port in range(start_port, end_port + 1)]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(scan_port, targets)
        
    print("--- mscan finished ---")

if __name__ == "__main__":
    main()
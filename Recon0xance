import os
import subprocess
import socket
from colorama import Fore, Style, init

GREEN = "\033[32m"

banner = f"""
  {GREEN}

 ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █ ▒██   ██▒ ▄▄▄       ███▄    █  ▄████▄  ▓█████ 
▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▒▒ █ █ ▒░▒████▄     ██ ▀█   █ ▒██▀ ▀█  ▓█   ▀ 
▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒░░  █   ░▒██  ▀█▄  ▓██  ▀█ ██▒▒▓█    ▄ ▒███   
▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒ ░ █ █ ▒ ░██▄▄▄▄██ ▓██▒  ▐▌██▒▒▓▓▄ ▄██▒▒▓█  ▄ 
░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░▒██▒ ▒██▒ ▓█   ▓██▒▒██░   ▓██░▒ ▓███▀ ░░▒████▒
░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒▒ ░ ░▓ ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ░▒ ▒  ░░░ ▒░ ░
  ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░░░   ░▒ ░  ▒   ▒▒ ░░ ░░   ░ ▒░  ░  ▒    ░ ░  ░
  ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░  ░    ░    ░   ▒      ░   ░ ░ ░           ░   
   ░        ░  ░░ ░          ░ ░           ░  ░    ░        ░  ░         ░ ░ ░         ░  ░
"""

print(banner)

# Initialize colorama for Windows compatibility (also works on other OS)
init(autoreset=True)

def create_results_dir():
    """Create Results directory structure if it doesn't exist."""
    base_dir = "Results"
    sub_dirs = ["WhatWeb_Results", "Nmap_Results", "Wafw00f_Results", 
                "SSLScan_Results", "Feroxbuster_Results"]
    
    for sub_dir in sub_dirs:
        path = os.path.join(base_dir, sub_dir)
        os.makedirs(path, exist_ok=True)

def resolve_ip_or_fqdn(target):
    """Resolve FQDN to IP if necessary."""
    try:
        ip = socket.gethostbyname(target)
        print(Fore.BLUE + f"[+] Resolved {target} to {ip}")
        return ip
    except socket.gaierror:
        print(Fore.BLUE + f"[-] Unable to resolve {target}")
        return None

def run_command(command, output_file):
    """Execute a shell command and write its output to a file."""
    try:
        print(Fore.BLUE + f"[+] Running: {' '.join(command)}")
        with open(output_file, 'w') as f:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            f.write(result.stdout + result.stderr)
    except Exception as e:
        print(Fore.BLUE + f"[-] Error executing command: {e}")

def run_whatweb(target):
    """Run WhatWeb scan."""
    output_file = "Results/WhatWeb_Results/whatweb_result.txt"
    run_command(["whatweb", target], output_file)

def run_nslookup(target):
    """Run nslookup if the target is a domain."""
    output_file = "Results/WhatWeb_Results/nslookup_result.txt"
    run_command(["nslookup", target], output_file)

def run_nmap(ip_or_fqdn):
    """Run Nmap scan."""
    output_file = "Results/Nmap_Results/nmap_result.txt"
    run_command(["nmap", "-sV", "-Pn", "-sC", "-O", ip_or_fqdn], output_file)

def run_wafw00f(target):
    """Run wafw00f scan."""
    output_file = "Results/Wafw00f_Results/wafw00f_result.txt"
    run_command(["wafw00f", target], output_file)

def run_sslscan(ip_or_fqdn):
    """Run SSLScan."""
    output_file = "Results/SSLScan_Results/sslscan_result.txt"
    run_command(["sslscan", ip_or_fqdn], output_file)

def run_feroxbuster(ip_or_fqdn):
    """Run Feroxbuster scan."""
    output_file = "Results/Feroxbuster_Results/feroxbuster_result.txt"
    run_command(["feroxbuster", "-u", f"http://{ip_or_fqdn}"], output_file)

def main():
    print(Fore.YELLOW + "Enter an IP address or FQDN: ", end="")
    target = input().strip()
    create_results_dir()

    if target.startswith("http"):
        # Extract domain from URL
        target = target.split("//")[-1]

    if not target.replace(".", "").isdigit():  # Assume it's a FQDN
        ip = resolve_ip_or_fqdn(target)
        if ip:
            run_whatweb(target)
            run_nslookup(target)
            run_wafw00f(target)
            run_sslscan(ip)
        else:
            print(Fore.BLUE + "Exiting. Unable to resolve target.")
            return
    else:
        ip = target  # If it's an IP address
        run_sslscan(ip)  # Only SSLScan can run with IPs

    # Perform the other scans
    run_nmap(ip)
    run_feroxbuster(ip)

    print(Fore.YELLOW + "[+] All Scans Completed. Please navigate to the 'Results' directory for review.")

if __name__ == "__main__":
    main()

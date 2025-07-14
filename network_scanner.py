import csv
import subprocess
import platform
import socket
import os
import sys
from datetime import datetime
from ipaddress import ip_network, ip_interface
import psutil

def get_local_subnet():
    # Use psutil to get network interfaces and their IPs
    interfaces = psutil.net_if_addrs()
    for iface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                # Found the first non-loopback interface
                subnet = ip_interface(f"{addr.address}/{addr.netmask}").network
                print(f"[*] Detected subnet: {subnet}")
                return subnet
    print("[-] Could not detect local subnet.")
    sys.exit(1)

def ping_ip(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    result = subprocess.run(["ping", param, "1", str(ip)],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            universal_newlines=True)
    return result.returncode == 0, result.stdout

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except:
        return "-"

def get_mac_address(ip):
    if platform.system().lower() == "windows":
        arp_cmd = ["arp", "-a", str(ip)]
        output = subprocess.check_output(arp_cmd, universal_newlines=True)
        for line in output.splitlines():
            if str(ip) in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
    else:
        try:
            output = subprocess.check_output(["arp", "-n", str(ip)], universal_newlines=True)
            for line in output.splitlines():
                if str(ip) in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
        except:
            pass
    return "-"

def run_scan(mode):
    subnet = get_local_subnet()
    output_file = "scan_results.csv"

    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        headers = ["IP Address", "Status", "Response Time (ms)", "Timestamp"]
        if mode == 2:
            headers += ["Hostname", "MAC Address"]
        writer.writerow(headers)

        for ip in subnet.hosts():
            reachable, output = ping_ip(ip)
            status = "Reachable" if reachable else "Unreachable"
            response_time = "-"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if reachable:
                for line in output.splitlines():
                    if "time=" in line:
                        try:
                            response_time = line.split("time=")[1].split("ms")[0].strip()
                        except:
                            response_time = "-"
                        break
                hostname = get_hostname(ip) if mode == 2 else "-"
                mac = get_mac_address(ip) if mode == 2 else "-"
                row = [str(ip), status, response_time, timestamp]
                if mode == 2:
                    row += [hostname, mac]
                writer.writerow(row)
                print(f"[+] {ip} reachable | {response_time} ms" + (f" | {hostname} | {mac}" if mode == 2 else ""))
            else:
                # Optionally skip logging unreachable
                pass

    print(f"\n[*] Scan complete. Results saved to {output_file}")

def menu():
    print("\n==== Network Scanner ====")
    print("1. IP sniff only")
    print("2. Full scan (IP, Hostname, MAC)")
    print("3. Exit")
    choice = input("Choose an option: ")
    if choice == "1":
        run_scan(mode=1)
    elif choice == "2":
        run_scan(mode=2)
    elif choice == "3":
        print("Exiting.")
        sys.exit(0)
    else:
        print("Invalid choice.")
        menu()

if __name__ == "__main__":
    try:
        import psutil
    except ImportError:
        print("This script requires the 'psutil' module. Install it with:")
        print("pip install psutil")
        sys.exit(1)

    menu()

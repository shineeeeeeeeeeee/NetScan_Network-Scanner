# for coomad-line arguments and exiting
import sys
# for networking interface and ip oprations
import socket
# for ip network calculations
import ipaddress
# for parallel thread execution
import concurrent.futures
# for detecting operation system
import platform
# for running os commands
import subprocess
# for regular expressions
import re
# for possible future os operations
import os

# =================================================================================================================
def print_app_name():
    print(r"""
   ____  _     _             
  / ___|| |__ (_)_ __   ___  
  \___ \| '_ \| | '_ \ / _ \ 
   ___) | | | | | | | |  __/ 
  |____/|_| |_|_|_| |_|\___| 
Welcome to NetScan, a network scanner brought to you by >>> Shine Suri <<<                                        
          """)
# =================================================================================================================
    

# =================================================================================================================

# Replace your existing get_local_ip_and_mask() with this improved version:

def get_local_ip_and_mask():
    """
    Return (ip, mask) where mask is dotted decimal (e.g. '255.255.255.0').
    Prefer non-loopback private addresses (192.168.*, 10.*, 172.16-31.*).
    Fall back to first non-loopback, then finally 127.0.0.1.
    """
    system = platform.system().lower()

    # Helper to convert cidr -> dotted mask
    def cidr_to_mask(cidr):
        return socket.inet_ntoa(((0xffffffff << (32 - cidr)) & 0xffffffff).to_bytes(4, "big"))

    # 1) Try `ip addr show` (Linux) or `ifconfig` parsing (macOS/Linux)
    try:
        if system == "linux":
            out = subprocess.check_output(["ip", "addr", "show"], text=True, encoding="utf-8")
            # collect all inet entries
            candidates = re.findall(r"inet\s+([\d.]+)/(\d+)", out)
            prefs = []  # list of (ip,mask)
            for ip, cidr in candidates:
                cidr = int(cidr)
                mask = cidr_to_mask(cidr)
                prefs.append((ip, mask))
            # prefer private non-loopback
            for ip, mask in prefs:
                if not ip.startswith("127.") and (
                    ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
                ):
                    return ip, mask
            for ip, mask in prefs:
                if not ip.startswith("127."):
                    return ip, mask
    except Exception:
        pass

    # 2) Try ifconfig (macOS / fallback)
    try:
        out = subprocess.check_output(["ifconfig"], text=True, encoding="utf-8")
        candidates = re.findall(r"inet\s+([\d.]+).*?netmask\s+(0x[\da-fA-F]+|[\d.]+)", out, re.S)
        prefs = []
        for ip, mask in candidates:
            if mask.startswith("0x") or mask.startswith("0X"):
                mask = socket.inet_ntoa(int(mask, 16).to_bytes(4, "big"))
            prefs.append((ip, mask))
        for ip, mask in prefs:
            if not ip.startswith("127.") and (
                ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
            ):
                return ip, mask
        for ip, mask in prefs:
            if not ip.startswith("127."):
                return ip, mask
    except Exception:
        pass

    # 3) Windows ipconfig
    if system == "windows":
        try:
            out = subprocess.check_output(["ipconfig"], text=True, encoding="utf-8")
            ip_match = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", out)
            mask_match = re.search(r"Subnet Mask[.\s]*:\s*([\d.]+)", out)
            if ip_match and mask_match:
                ip = ip_match.group(1)
                mask = mask_match.group(1)
                if not ip.startswith("127."):
                    return ip, mask
        except Exception:
            pass

    # 4) Fallback: socket trick to get outbound interface IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        try:
            s.close()
        except Exception:
            pass

    # If we got a non-loopback IP here return it, otherwise loopback with default /24
    if not ip.startswith("127."):
        return ip, "255.255.255.0"
    return "127.0.0.1", "255.0.0.0"   # keep /8 for loopback but we will handle this later

# =================================================================================================================


# =================================================================================================================
def mask_to_cidr(mask):
    """
    Converts a dotted-decimal subnet mask (e.g., 255.255.255.0) to CIDR notation (e.g., 24).
    """
    return sum(bin(int(x)).count('1') for x in mask.split('.'))
# =================================================================================================================


# =================================================================================================================
# Replace your parse_network() with this safer version:

def parse_network(arg=None):
    """
    Parses the network argument and returns an ipaddress.ip_network object.
    If no arg, auto-detect local network but avoid scanning loopback or extremely large networks.
    """
    if not arg:
        ip, mask = get_local_ip_and_mask()
        cidr = mask_to_cidr(mask)
        net = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)

        # Safety: don't scan loopback or huge networks automatically.
        if net.is_loopback:
            # if only loopback found, avoid scanning 127.0.0.0/8 — fall back to /24 around 127.0.0.1
            print("Auto-detected loopback interface (127.x.x.x). No active network interface found.")
            print("Refusing to scan 127.0.0.0/8 automatically. Use an explicit network argument (e.g., 192.168.1.0/24).")
            raise ValueError("No usable non-loopback interface detected.")
        if net.num_addresses > 4096:
            # shrink to /24 around detected IP to avoid scanning a /8 by mistake
            print(f"Auto-detected network {net} is very large ({net.num_addresses} addresses).")
            print(f"Automatically shrinking scan to /24 around {ip} to avoid long scans.")
            return ipaddress.ip_network(f"{ip}/24", strict=False)
        return net

    # If argument provided, accept the user value as before
    if '/' in arg:
        return ipaddress.ip_network(arg, strict=False)
    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '/24', strict=False)
    else:
        raise ValueError("Invalid network format")

# =================================================================================================================

# =================================================================================================================
def ping(ip):
    """
    Pings a single IP address.
    Returns the IP if online (responds to ping), otherwise None.
    """
    ip = str(ip)                                                               # Ensure IP is string
    system = platform.system().lower()                                         # Detect OS
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]                            # Windows: 1 ping, 1s timeout
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]                               # Unix: 1 ping, 1s timeout
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if re.search(r"ttl", result.stdout, re.IGNORECASE):                    # "ttl" in output = host responded
            return ip
    except subprocess.TimeoutExpired:
        return None                                                            # Timed out, host not online
    except Exception:
        return None                                                            # Other error, treat as offline
# =================================================================================================================


# =================================================================================================================
def scan_network(network):
    """
    Scans all hosts in the given network in parallel.
    Returns a list of online hosts.
    """
    print(f"Scanning network: {network}")                                      # Inform user what is being scanned
    online = []                                                                # List to store online hosts
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:   # Use 100 threads
            futures = {executor.submit(ping, ip): ip for ip in network.hosts()}   # Submit ping jobs
            for future in concurrent.futures.as_completed(futures):                # As each finishes
                try:
                    result = future.result()                                       # Get result
                    if result:
                        online.append(result)                                      # Add if online
                except Exception:
                    continue                                                       # Ignore errors
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Showing results so far...")         # Handle Ctrl+C gracefully
    return online
# =================================================================================================================


# =================================================================================================================
def show_help():
    """
    Prints usage and help information.
    """
    print(
        "Usage: netscan [network]\n"
        "Scan a network for online devices.\n\n"
        "Options:\n"
        "  -h, --help     Show this help message\n"
        "Examples:\n"
        "  netscan                 # Scan current local network\n"
        "  netscan 192.168.1.0     # Scan 192.168.1.0/24\n"
        "  netscan 192.168.1       # Scan 192.168.1.0/24\n"
        "  netscan 192.168.1.0/24  # Scan 192.168.1.0/24"
    )
# =================================================================================================================


# =================================================================================================================
# MAIN
# =================================================================================================================
# Small change in main(): catch the particular ValueError thrown when only loopback found and exit cleanly.

def main():
    print_app_name()
    args = sys.argv[1:]
    if not args:
        try:
            network = parse_network()
        except ValueError as e:
            print(f"Error: {e}")
            show_help()
            return
    elif args[0] in ['-h', '--help']:
        show_help()
        return
    elif len(args) == 1:
        try:
            network = parse_network(args[0])
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return
    elif len(args) >= 1:
        try:
            network = parse_network(" ".join(args))  # join multiple args into one string
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return
    else:
        show_help()
        return

    try:
        online_hosts = scan_network(network)
        print("\nOnline hosts:")
        for host in sorted(online_hosts, key=lambda x: tuple(map(int, x.split('.')))):
            print(host)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")


if __name__ == "__main__":
    main()
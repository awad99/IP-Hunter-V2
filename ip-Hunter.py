import subprocess
import socket
import os
import sys
from colored import fg,bg
import time
import ipinfo
import joblib
from train import predict_best_exploit

white = fg(15)
aqua = fg(14)
green = fg(10)
pink = fg(201)
yellow = fg(11)
black_bg = bg(16)
light_purp = fg(54)
red = fg(1)
light_purp = fg(93)
black = fg(16)

msg = r"""
  _____   _____
 |_   _| |  __ \
   | |   | |__) |
   | |   |  ___/
  _| |_  | |
 |_____| |_|
          _    _                   _
         | |  | |                 | |
         | |__| |  _   _   _ __   | |_    ___   _ __
         |  __  | | | | | | '_ \  | __|  / _ \ | '__|
         | |  | | | |_| | | | | | | |_  |  __/ | |
         |_|  |_|  \__,_| |_| |_|  \__|  \___| |_|
"""

def typewriter(msg):
    for chart in msg:
        sys.stdout.write(chart)
        sys.stdout.flush()
        if chart != "\n":
            time.sleep(0)
        else:
            time.sleep(0.10)
typewriter(msg)

print(yellow+"=" * 50)
print(light_purp + "Made it By Omar-KL And add ML By Awadh")
print(light_purp + "Instagram: @1_k1e And @i3.kv")
print(light_purp + "Youtube: https://www.youtube.com/@magician-teq")
print(light_purp + "Don't use it for Illegal Purposes.. ")
print(yellow+"=" * 50)


print(aqua + "[1] " + white + "IP Information.")
print(aqua+"[2] " + white + "IP Scan For Vulnerabilities.")
print(yellow+"="*50)
choice = input(aqua + "[+] " + white + "Enter your choice: ")
filename = "output.txt"


def get_ip_info(ip, access_token):
    handler = ipinfo.getHandler(access_token)
    details = handler.getDetails(ip)

    print(yellow + "=" * 50)
    print(aqua + "Decimal: ", pink + details.ip, end="\n")
    print(aqua + "City: ", pink + details.city, end="\n")
    print(aqua + "State/Region: ", pink + details.region, end="\n")
    print(aqua + "Country: ", pink + details.country_name, end="\n")
    print(aqua + "timezone: ", pink + details.timezone, end="\n")
    print(aqua + "Assignment: ", pink + details.org, end="\n")

    print(yellow + "=" * 50)
    print("")
    with open("output.txt", "a") as file:
        file.write("Decimal: " + details.ip + "\n")
        file.write("City: " + details.city + "\n")
        file.write("State/Region: " + details.region + "\n")
        file.write("Country: " + details.country_name + "\n")
        file.write("timezone: " + details.timezone + "\n")
        file.write("Assignment: " + details.org + "\n")
        file.write("=" * 50 + "\n")

if choice == "1":
    choice = input(aqua+"[+] " +white+ "Do you want to get Information one IP or multiple IPs? (1/m): ")
    if choice == '1':
        try:
            print(red + " NOTE: " + white + "To get a Token you have to create an Account at ipinfo.io")
            access_token = input(aqua+"[*] " +white + 'Enter Your Token: ')
            ip = input(aqua+ "[*] " +white + "Enter Target IP Address: ")
            get_ip_info(ip, access_token)

        except Exception as e:
            print(yellow + "=" * 50)
            print(pink + "Error: ", e)
            print(yellow + "=" * 50)
    elif choice == 'm':
        try:
            print(red + " NOTE: " + white + "To get a Token you have to create an Account at ipinfo.io")
            access_token = input(aqua+"[*] " +white + 'Enter Your Token: ')
            handler = ipinfo.getHandler(access_token)

            # Ask for file path
            ip_file = input(aqua+"[*] " +white+ "Enter file path containing IPs: ")

            if not os.path.isfile(ip_file):
                print(pink + f"[!] File not found: {ip_file}")
            else:
                with open(ip_file, "r") as f:
                    ip_list = [line.strip() for line in f if line.strip()]

                for ip in ip_list:
                    try:
                        get_ip_info(ip, access_token)
                    
                    except Exception as inner_e:
                        print(pink + f"[!] Could not fetch info for {ip}: {inner_e}")

        except Exception as e:
            print(yellow + "=" * 50)
            print(pink + "Error: ", e)
            print(yellow + "=" * 50)

        
elif choice == "2":
    try:
        
        def parse_nmap_output(ip, nmap_output, ports_list):

                # Default values
                scan_row = {
                    "open_port_count": 0,
                    "filtered_port_count": 0,
                    "closed_port_count": 0,
                    "tcpwrapped_count": 0,
                    "total_vulnerabilities": 0,
                    "exploit_risk_score": 0,
                    "has_high_severity_vuln": 0,
                    "geographic_risk": 0,
                    "http_ports_open": 0,
                    "ssh_ftp_ports_open": 0,
                    "mail_ports_open": 0,
                    "database_ports_open": 0,
                    "remote_access_ports_open": 0,
                    "is_open": 1,
                    "is_common_vulnerable_port": 0,
                    "port": str(ports_list[0]),
                    "port_status": "open",
                    "os_linux": "0",
                    "os_windows": "0",
                }

                lines = nmap_output.splitlines()
                for line in lines:
                    if "/tcp" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_info, status, service = parts[:3]
                            port_number = port_info.split("/")[0]
                            scan_row["open_port_count"] += 1 if status.lower() == "open" else 0
                            scan_row["port"] = port_number
                            scan_row["port_status"] = status
                            if service.lower() in ["http", "https"]:
                                scan_row["http_ports_open"] += 1
                            elif service.lower() in ["ssh", "ftp"]:
                                scan_row["ssh_ftp_ports_open"] += 1
                            elif service.lower() in ["smtp", "pop3", "imap"]:
                                scan_row["mail_ports_open"] += 1
                            elif service.lower() in ["mysql", "mssql", "oracle"]:
                                scan_row["database_ports_open"] += 1
                            elif service.lower() in ["telnet", "rlogin", "rdp"]:
                                scan_row["remote_access_ports_open"] += 1

                    if "OS details:" in line or "Running:" in line:
                        if "Linux" in line:
                            scan_row["os_linux"] = "1"
                        elif "Windows" in line:
                            scan_row["os_windows"] = "1"

                # You can adjust other fields like exploit_risk_score based on vulnerabilities found
                scan_row["total_vulnerabilities"] = sum([scan_row["http_ports_open"],
                                                        scan_row["ssh_ftp_ports_open"],
                                                        scan_row["mail_ports_open"],
                                                        scan_row["database_ports_open"],
                                                        scan_row["remote_access_ports_open"]])
                scan_row["exploit_risk_score"] = scan_row["total_vulnerabilities"] * 50  # simple heuristic
                return scan_row

        def scan_ip(ip, ports_list):
            try:
                socket.inet_aton(ip)
                # First command: "nmap [ip] -O"
                nmap_os_command = f"nmap {ip} -p {ports} -O"
                os_info_proc = subprocess.run(nmap_os_command, shell=True, stdout=subprocess.PIPE)
                os_info = os_info_proc.stdout.decode('utf-8')

                # Second command: "sudo nmap -sV --script=nmap-vulners"
                nmap_exploits_command = f"nmap -sV -p {ports} --script=vulners {ip}"
                exploits_proc = subprocess.run(nmap_exploits_command, shell=True, stdout=subprocess.PIPE)
                exploits_output = exploits_proc.stdout.decode('utf-8')       # keep raw string
                exploits_lines = exploits_output.splitlines()                # make list for parsing
                limited_exploits = exploits_lines[:30]

                # Print the output of both commands
                print(pink + "=" * 100)
                print(white + "OS Information:")
                print(pink + "=" * 100)
                print(aqua + os_info)

                # --- Extract keywords ---
                keywords = []
                for line in exploits_lines:
                    if "CVE-" in line:
                        for part in line.split():
                            if part.startswith("CVE-"):
                                keywords.append(part)
                    elif "nginx" in line.lower() or "apache" in line.lower():
                        keywords.append("nginx")
                
                # --- Extract keywords ---
                keywords = []
                searchsploit_results = {}  # store each keyword's output
                for line in exploits_lines:
                    if "CVE-" in line:
                        for part in line.split():
                            if part.startswith("CVE-"):
                                keywords.append(part)
                    elif "nginx" in line.lower() or "apache" in line.lower():
                        keywords.append("nginx")

                # --- Run Searchsploit for each keyword ---
                for key in keywords:
                    print(f"[+] Searching exploits for {key}...")
                    searchsploit_command = f"searchsploit {key}"
                    result = subprocess.run(searchsploit_command, shell=True, stdout=subprocess.PIPE)
                    output = result.stdout.decode('utf-8')
                    searchsploit_results[key] = output  # save output in dictionary

                    # Print first 30 lines only
                    for line in output.splitlines()[:30]:
                        print(line)

                
                    os_info_proc = subprocess.run(nmap_os_command, shell=True, stdout=subprocess.PIPE)
                    os_info = os_info_proc.stdout.decode('utf-8')

                    nmap_exploits_proc = subprocess.run(nmap_exploits_command, shell=True, stdout=subprocess.PIPE)
                    nmap_exploits_output = nmap_exploits_proc.stdout.decode('utf-8')

                    # Parse dynamic scan_row from Nmap output
                    scan_row = parse_nmap_output(ip, nmap_exploits_output, ports_list)


                    best_exploit = predict_best_exploit(scan_row)
                    print(f"[+] Suggested best exploit: {best_exploit}")
                                    
                # --- Write results to file ---
                if not os.path.exists(filename):
                    with open(filename, "w") as f:
                        f.write(light_purp + "This is a new file:\n")
                        f.write(os_info + "\n\n")
                        f.write("Top vulnerabilities found by Nmap:\n")
                        for exploit in limited_exploits:
                            print(aqua + exploit)
                            f.write(exploit + "\n")

                        # Write Searchsploit results for all keywords
                        for key, output in searchsploit_results.items():
                            f.write(f"\nSearchsploit results for {key}:\n")
                            f.write(output + "\n")
                            f.write("-" * 80 + "\n")

                else:
                    with open(filename, "a") as f:
                        f.write("\n" + os_info + "\n\n")
                        f.write("Top vulnerabilities found by Nmap:\n")
                        for exploit in limited_exploits:
                            print(aqua + exploit)
                            f.write(exploit + "\n")

                        # Append Searchsploit results
                        for key, output in searchsploit_results.items():
                            f.write(f"\nSearchsploit results for {key}:\n")
                            f.write(output + "\n")
                            f.write("-" * 80 + "\n")

                    print(pink + "=" * 100)
                    print(white + "Vulnerabilities:")
                    print(pink + "=" * 100)

                print(f"[+] Scan complete. Results saved to {filename}")


                
            except socket.error:
                print(red+"Invalid IP Address..")
                exit()

        # Ask the user whether they want to scan one IP or multiple IPs
        choice = input(aqua+"[+] " +white+ "Do you want to scan one IP or multiple IPs? (1/m): ")

        if choice == '1':
            def get_ports_list(ports_input):
                try:
                    if '-' in ports_input:
                        start, end = map(int, ports_input.split('-'))
                        return list(range(start, end + 1))
                    else:
                        return [int(ports_input)]
                except ValueError:
                    return []
            ports = input(aqua+"[+] " +white+ "Enter the Ports to scan (e.g. 80 or 1-100): ")
            ports_list = get_ports_list(ports)
            if not ports_list:
                print(red+"Invalid ports format, try again..")
                exit()
            ip = input(aqua+"[+] " +white+ "Enter the IP address to scan: ")
            msg1=(red+"[*] Working On It...")
            def typewriter(msg1):
                for chart in msg1:
                    sys.stdout.write(chart)
                    sys.stdout.flush()
                    if chart != "\n":
                        time.sleep(0.050)
                    else:
                        time.sleep(0.5)
            typewriter(msg1)
            print(" ")
            scan_ip(ip, ports_list)
         


        elif choice == 'm':
            def get_ports_list(ports_input):
                try:
                    if '-' in ports_input:
                        start, end = map(int, ports_input.split('-'))
                        return list(range(start, end + 1))
                    else:
                        return [int(ports_input)]
                except ValueError:
                    return []
            ports = input(aqua+"[+] " +white+ "Enter the Ports to scan (e.g. 80 or 1-100): ")
            ports_list = get_ports_list(ports)
            if not ports_list:
                print(red+"Invalid ports format, try again..")

            file_path = input(aqua+"[+] " +white+ "Enter the path of the file containing the IP addresses: ")
            try:
                with open(file_path, 'r') as f:
                    ips = f.readlines()
                for ip in ips:
                    scan_ip(ip.strip(), ports_list)
            except FileNotFoundError:
                print(red+"File Not Found, Please Try Again...")
        else:
            print(red+"Invalid choice, try again.")
    except Exception as e:
        print("Error: ", e)


else:
    print(red + "Invalid choice, try again.")



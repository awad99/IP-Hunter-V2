import re
import pandas as pd

def parse_network_scan_data(file_content):
    """
    Parse network scan data and extract relevant information for exploit analysis.
    """
    results = {}
    current_ip = None
    lines = file_content.strip().split('\n')

    for i, line in enumerate(lines):
        line = line.strip()

        # Extract IP address
        if line.startswith("Decimal:"):
            ip_match = re.search(r"Decimal:\s+([\d.]+)", line)
            if ip_match:
                current_ip = ip_match.group(1)
                results[current_ip] = init_ip_record()

        # Nmap IP block
        elif line.startswith("Nmap scan report for"):
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                current_ip = ip_match.group(1)
                if current_ip not in results:
                    results[current_ip] = init_ip_record()

        # Port info
        elif current_ip and re.match(r"^\d+/tcp\s+", line):
            parts = line.split()
            if len(parts) >= 3:
                port_num = parts[0].split("/")[0]
                status = parts[1]
                service = " ".join(parts[2:]) if len(parts) > 2 else "unknown"

                results[current_ip]["ports"].append({
                    "port": port_num,
                    "status": status,
                    "service": service
                })

                # Count port states
                if status == "open":
                    results[current_ip]["open_port_count"] += 1
                elif status == "filtered":
                    results[current_ip]["filtered_port_count"] += 1
                elif status == "closed":
                    results[current_ip]["closed_port_count"] += 1

                if "tcpwrapped" in service.lower():
                    results[current_ip]["tcpwrapped_count"] += 1

        # OS guesses
        elif current_ip and "Aggressive OS guesses:" in line:
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("No exact OS matches"):
                guess = lines[j].strip()
                if guess and not guess.startswith("OS CPE:") and not guess.startswith("Network Distance"):
                    results[current_ip]["os_guesses"].append(guess)
                j += 1
                if j >= len(lines) or lines[j].strip() == "":
                    break

        # Vulnerability data
        elif current_ip and "vulners:" in line:
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith("|"):
                vuln_line = lines[j].strip().replace("|", "").strip()
                if "CVE-" in vuln_line or "EXPLOIT" in vuln_line:
                    results[current_ip]["vulnerabilities"].append(vuln_line)
                j += 1

    # Calculate exploit risk score
    for ip, data in results.items():
        data["exploit_risk_score"] = calculate_risk_score(data)

    return results


def create_csv_for_ml(results, output_file="exploit_analysis.csv"):
    csv_data = []

    common_ports = {
        "http_ports": ["80", "8080", "443", "8443"],
        "ssh_ftp_ports": ["21", "22"],
        "mail_ports": ["25", "110", "143", "993", "995"],
        "database_ports": ["3306", "5432", "1433", "27017"],
        "remote_access_ports": ["23", "3389", "5900"]
    }

    # Predefined OS keywords for one-hot encoding
    os_keywords = ["linux", "windows", "oracle", "qemu", "virtualbox"]
    # Predefined service keywords for one-hot encoding
    service_keywords = ["nginx", "ssh", "smtp", "ftp", "http", "mysql", "postgres"]

    for ip, data in results.items():
        base = {
            "ip": ip,
            "open_port_count": data["open_port_count"],
            "filtered_port_count": data["filtered_port_count"],
            "closed_port_count": data["closed_port_count"],
            "tcpwrapped_count": data["tcpwrapped_count"],
            "total_vulnerabilities": len(data["vulnerabilities"]),
            "exploit_risk_score": data["exploit_risk_score"],
            "has_high_severity_vuln": 0,
            "has_exploit_available": 0,
            "geographic_risk": 1 if any(c in data.get("country", "") for c in ["CN", "RU", "KP", "IR"]) else 0,
        }

        # Initialize OS keyword flags
        os_info_str = "; ".join(data["os_guesses"][:3]).lower()
        for key in os_keywords:
            base[f"os_{key}"] = 1 if key in os_info_str else 0

        # Initialize service keyword flags
        services_concat = " ".join(p["service"].lower() for p in data["ports"])
        for key in service_keywords:
            base[f"svc_{key}"] = 1 if key in services_concat else 0

        # Vuln severity / exploit availability flags
        if any("10.0" in v or "9." in v for v in data["vulnerabilities"]):
            base["has_high_severity_vuln"] = 1
        if any("EXPLOIT" in v.upper() for v in data["vulnerabilities"]):
            base["has_exploit_available"] = 1

        # Initialize port category counts
        for cat in common_ports:
            base[f"{cat}_open"] = 0

        # Count open ports by category
        for p in data["ports"]:
            if p["status"] == "open":
                for cat, ports in common_ports.items():
                    if p["port"] in ports:
                        base[f"{cat}_open"] += 1

        # Per-port records
        if data["ports"]:
            for p in data["ports"]:
                row = base.copy()
                row.update({
                    "port": p["port"],
                    "port_status": p["status"],
                    "is_open": 1 if p["status"] == "open" else 0,
                    "is_common_vulnerable_port": 1 if p["port"] in ["21", "23", "80", "135", "139", "445"] else 0,
                    "exploit_label": base["has_exploit_available"]
                })
                csv_data.append(row)
        else:
            row = base.copy()
            row.update({
                "port": "None",
                "port_status": "None",
                "is_open": 0,
                "is_common_vulnerable_port": 0,
                "exploit_label": base["has_exploit_available"]
            })
            csv_data.append(row)

    df = pd.DataFrame(csv_data)

    # Remove non-numeric columns ('ip' is usually dropped or encoded separately)
    # If you need IP in model, map it to integer using hash or simple indexing
    df.drop(columns=["ip"], inplace=True, errors="ignore")

    # Sort dataset for readability (not needed for ML)
    df.sort_values(by=["exploit_risk_score", "open_port_count"], ascending=[False, False], inplace=True)

    df.to_csv(output_file, index=False)
    return df

def init_ip_record():
    """Initialize a new IP record with default values."""
    return {
        "ports": [],
        "open_port_count": 0,
        "filtered_port_count": 0,
        "closed_port_count": 0,
        "tcpwrapped_count": 0,
        "os_guesses": [],
        "vulnerabilities": [],
        "country": "",        # placeholder if you later want to set this
        "exploit_risk_score": 0
    }

def calculate_risk_score(data):
    """Calculate a simple exploit risk score based on open ports and vulnerabilities."""
    score = 0
    score += data["open_port_count"] * 2
    score += len(data["vulnerabilities"]) * 5
    if any("10.0" in v or "9." in v for v in data["vulnerabilities"]):
        score += 10  # extra weight for high severity vulns
    if any("EXPLOIT" in v.upper() for v in data["vulnerabilities"]):
        score += 20  # extra weight if an exploit is available
    return score

if __name__ == "__main__":
    with open("output.txt", "r", encoding="utf-8") as f:
        content = f.read()
    parsed = parse_network_scan_data(content)
    df = create_csv_for_ml(parsed, output_file="info.csv")
    if df is not None:
        print(f"[+] CSV file created successfully: info.csv")
        print(f"[+] Rows written: {len(df)}")
    else:
        print("[!] No data parsed. CSV not created.")

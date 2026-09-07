import csv
from pathlib import Path
from datetime import datetime
DATA_FILE = Path(__file__).parent.parent / "data" / "network_logs.csv"
REPORT_FILE = Path(__file__).parent.parent / "security_report.txt"

failed_attempts = {}
suspicious_connections = {}
total_connections = 0

suspicious_ports = {
    "21": "FTP",
    "22": "SSH"
}

with open(DATA_FILE, "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        total_connections += 1

        if row["status"] == "Failed":
            ip = row["ip_address"]

            if ip not in failed_attempts:
                failed_attempts[ip] = 0

            failed_attempts[ip] += 1

            if row["port"] in suspicious_ports:
                key = (ip, row["port"])

                if key not in suspicious_connections:
                    suspicious_connections[key] = 0

                suspicious_connections[key] += 1

print("Security Analysis")
print("-----------------")

for ip, attempts in failed_attempts.items():
    print(ip, ":", attempts, "failed attempts")

    if attempts >= 3:
        print("🔴 HIGH SEVERITY:", ip)
        print("   Possible brute-force activity")

print()
print("Security Alerts")
print("---------------")

for (ip, port), attempts in suspicious_connections.items():
    print("⚠️ MEDIUM SEVERITY")
    print("   Suspicious port:", port, "(" + suspicious_ports[port] + ")")
    print("   IP:", ip)
    print("   Attempts:", attempts)
    print()

report_file = open(REPORT_FILE, "w")

report_file.write("NETWORK SECURITY REPORT\n")
report_file.write("======================\n")
report_file.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
report_file.write(f"Connections analyzed: {total_connections}\n\n")

report_file.write("Risk Summary\n")
report_file.write("------------\n")

high_risk = 0
medium_risk = len(suspicious_connections)

for ip, attempts in failed_attempts.items():
    if attempts >= 3:
        high_risk += 1

report_file.write(f"High severity alerts: {high_risk}\n")
report_file.write(f"Medium severity alerts: {medium_risk}\n\n")

report_file.write("Failed Connections\n")
report_file.write("------------------\n")

for ip, attempts in failed_attempts.items():
    report_file.write(f"{ip}: {attempts} failed attempts\n")

report_file.write("\nSecurity Alerts\n")
report_file.write("---------------\n")

for (ip, port), attempts in suspicious_connections.items():
    report_file.write(
        f"MEDIUM SEVERITY - Suspicious port {port} "
        f"({suspicious_ports[port]}) from {ip} - "
        f"{attempts} attempts\n"
    )

report_file.close()

print()
print("✅ Security report created: security_report.txt")
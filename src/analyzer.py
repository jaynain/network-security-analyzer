import csv
from pathlib import Path
DATA_FILE = Path(__file__).parent.parent / "data" / "network_logs.csv"

failed_attempts = {}
suspicious_connections = {}

suspicious_ports = {
    "21": "FTP",
    "22": "SSH"
}

with open(DATA_FILE, "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
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
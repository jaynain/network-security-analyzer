import csv
from pathlib import Path
from sklearn.ensemble import IsolationForest

DATA_FILE = Path(__file__).parent.parent / "data" / "network_logs.csv"
REPORT_FILE = Path(__file__).parent.parent / "security_report.txt"

features = []
records = []
failed_attempts = {}

# First pass: count failed attempts per IP
with open(DATA_FILE, "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        if row["status"] == "Failed":
            ip = row["ip_address"]

            if ip not in failed_attempts:
                failed_attempts[ip] = 0

            failed_attempts[ip] += 1

# Second pass: create ML features
with open(DATA_FILE, "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        ip = row["ip_address"]
        port = int(row["port"])

        if row["status"] == "Failed":
            failed = 1
        else:
            failed = 0

        if str(port) in ["21", "22"]:
            suspicious = 1
        else:
            suspicious = 0

        features.append([
            port,
            failed,
            suspicious,
            failed_attempts.get(ip, 0)
        ])

        records.append(row)

print("ML Features:")
print(features)

model = IsolationForest(
    contamination=0.10,
    random_state=42
)

predictions = model.fit_predict(features)
scores = model.decision_function(features)

print("ML Predictions:")
print(predictions)

print()
print("ML Anomaly Detection")
print("--------------------")

ml_anomalies = []

for record, prediction, score in zip(records, predictions, scores):
    if prediction == -1:
        ml_anomalies.append((record, score))

        print("🚨 ANOMALY DETECTED")
        print("   Anomaly score:", round(score, 4))
        print("   IP:", record["ip_address"])
        print("   Port:", record["port"])
        print("   Protocol:", record["protocol"])
        print("   Status:", record["status"])

        if record["status"] == "Failed":
            print("   Reason: Failed connection")

        if record["port"] in ["21", "22"]:
            print("   Reason: Connection uses a suspicious port")

        print()

# Add ML results to the existing security report
report_file = open(REPORT_FILE, "a")

report_file.write("\nML Anomaly Detection\n")
report_file.write("--------------------\n")

if len(ml_anomalies) == 0:
    report_file.write("No anomalies detected.\n")
else:
    report_file.write(
        f"ML detected {len(ml_anomalies)} anomalous connection(s).\n\n"
    )

    for record, score in ml_anomalies:
        report_file.write(
            f"ANOMALY - IP: {record['ip_address']}, "
            f"Port: {record['port']}, "
            f"Protocol: {record['protocol']}, "
            f"Status: {record['status']}\n"
        )

        report_file.write(
            f"Anomaly score: {score:.4f}\n"
        )

        if record["status"] == "Failed":
            report_file.write("Reason: Failed connection\n")

        if record["port"] in ["21", "22"]:
            report_file.write(
                "Reason: Connection uses a suspicious port\n"
            )

        report_file.write("\n")

report_file.close()

print("✅ ML results added to security_report.txt")
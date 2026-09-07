import csv
from pathlib import Path
from sklearn.ensemble import IsolationForest

DATA_FILE = Path(__file__).parent.parent / "data" / "network_logs.csv"
REPORT_FILE = Path(__file__).parent.parent / "security_report.txt"

features = []
records = []

with open(DATA_FILE, "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        port = int(row["port"])

        if row["status"] == "Failed":
            failed = 1
        else:
            failed = 0

        if str(port) in ["21", "22"]:
            suspicious = 1
        else:
            suspicious = 0

        features.append([port, failed, suspicious])
        records.append(row)

print("ML Features:")
print(features)

model = IsolationForest(
    contamination=0.25,
    random_state=42
)

predictions = model.fit_predict(features)

print("ML Predictions:")
print(predictions)

print()
print("ML Anomaly Detection")
print("--------------------")

ml_anomalies = []

for record, prediction in zip(records, predictions):
    if prediction == -1:
        ml_anomalies.append(record)

        print("🚨 ANOMALY DETECTED")
        print("   IP:", record["ip_address"])
        print("   Port:", record["port"])
        print("   Protocol:", record["protocol"])
        print("   Status:", record["status"])

        if record["status"] == "Failed":
            print("   Reason: Failed connection")

        if record["port"] in ["21", "22"]:
            print("   Reason: Connection uses a suspicious port")

        print()

report_file = open(REPORT_FILE, "w")

report_file.write("\nML Anomaly Detection\n")
report_file.write("--------------------\n")

if len(ml_anomalies) == 0:
    report_file.write("No anomalies detected.\n")
else:
    report_file.write(
        f"ML detected {len(ml_anomalies)} anomalous connection(s).\n\n"
    )

    for record in ml_anomalies:
        report_file.write(
            f"ANOMALY - IP: {record['ip_address']}, "
            f"Port: {record['port']}, "
            f"Protocol: {record['protocol']}, "
            f"Status: {record['status']}\n"
        )

report_file.close()

print("✅ ML results added to security_report.txt")
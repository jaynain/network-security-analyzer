import csv
from pathlib import Path
import matplotlib.pyplot as plt

DATA_FILE = Path(__file__).parent.parent / "data" / "network_logs.csv"

successful = 0
failed = 0

with open(DATA_FILE, "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        if row["status"] == "Success":
            successful += 1
        elif row["status"] == "Failed":
            failed += 1

labels = ["Successful", "Failed"]
values = [successful, failed]

plt.bar(labels, values)

plt.title("Network Connection Status")
plt.xlabel("Connection Status")
plt.ylabel("Number of Connections")

plt.tight_layout()
plt.savefig("network_connection_status.png")
plt.show()

print("✅ Visualization created: network_connection_status.png")
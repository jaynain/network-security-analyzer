import subprocess
from pathlib import Path

print("================================")
print("   NETWORK SECURITY ANALYZER")
print("================================")
print()

REPORT_FILE = Path("security_report.txt")
REPORT_FILE.write_text("")

print("Running rule-based security analysis...")
subprocess.run(["python", "src/analyzer.py"])

print()
print("Running machine learning analysis...")
subprocess.run(["python", "src/ml_detector.py"])

print()
print("================================")
print("        ANALYSIS COMPLETE")
print("================================")
print()
print("The full security report has been generated.")
print(f"Report file: {REPORT_FILE}")
print()
print("✅ Security analysis completed successfully.")

print()
print("Creating network connection visualization...")
subprocess.run(["python", "src/visualizer.py"])
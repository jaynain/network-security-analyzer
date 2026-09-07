Network Security Analyzer

A Python-based cybersecurity project that analyzes network connection logs, identifies suspicious activity using rule-based detection, and uses machine learning to detect unusual network behavior.

Features

* Analyzes network connection logs from a CSV file
* Detects repeated failed connection attempts
* Identifies connections using suspicious ports such as FTP (21) and SSH (22)
* Assigns severity levels to suspicious activity
* Uses Isolation Forest for unsupervised anomaly detection
* Uses failed attempts per IP as a behavioral ML feature
* Generates an automated security report
* Records the report generation timestamp and number of connections analyzed

How It Works

The analyzer uses two approaches:

1. Rule-Based Detection

The program checks network logs for predefined security indicators, including:

* Multiple failed connection attempts from the same IP
* Connections using suspicious ports
* Potential brute-force activity

2. Machine Learning Detection

The project uses the Isolation Forest algorithm from scikit-learn to identify connections that appear unusual compared with the rest of the dataset.

The ML model uses network behavior such as:

* Port number
* Connection status
* Suspicious-port indicator
* Number of failed attempts from the IP address

Project Structure

network-security-analyzer/
├── data/
│   └── network_logs.csv
├── src/
│   ├── analyzer.py
│   ├── ml_detector.py
│   └── main.py
├── security_report.txt
├── requirements.txt
└── README.md

Technologies

* Python
* CSV data processing
* scikit-learn
* Isolation Forest
* Git & GitHub

Running the Project

From the project root:

python src/main.py

The program performs the rule-based and machine-learning analysis and generates:

security_report.txt

Example

The analyzer can identify activity such as repeated failed SSH connections:

🔴 HIGH SEVERITY
Possible brute-force activity

The ML detector can also identify unusual network connections:

🚨 ANOMALY DETECTED
Reason: Failed connection

Project Goal

This project was created as a hands-on introduction to combining Python, cybersecurity concepts, and machine learning to analyze network activity.

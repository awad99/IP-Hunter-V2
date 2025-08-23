import csv
import numpy as np
from sklearn import preprocessing, linear_model

# Containers
ports, services, oss = [], [], []
features, y = [], []

# Read the CSV generated earlier
with open("info.csv", "r", encoding="utf-8") as f:
    reader = csv.reader(f)
    header = next(reader)

    for row in reader:
        # Skip rows that don't have proper numeric data
        if not row[4].isdigit():
            continue

        # --- Numeric feature extraction ---
        open_port_count = int(row[4])
        filtered_port_count = int(row[5])
        closed_port_count = int(row[6])
        tcpwrapped_count = int(row[7])
        total_vulnerabilities = int(row[8])
        exploit_risk_score = int(row[9]) if row[9].isdigit() else 0
        os_info = row[10] if row[10] else "unknown"
        http_ports_open = int(row[11])
        ssh_ftp_ports_open = int(row[12])
        mail_ports_open = int(row[13])
        database_ports_open = int(row[14])
        remote_access_ports_open = int(row[15])
        has_web_service = int(row[16])
        has_ssh = int(row[17])
        has_database = int(row[18])
        has_high_severity_vuln = int(row[19])
        has_exploit_available = int(row[20])
        geographic_risk = int(row[21]) if row[21].isdigit() else 0

        # --- Categorical fields ---
        port = row[22] if row[22] else "none"
        service = row[24] if row[24] else "none"
        is_open = int(row[25])
        is_common_vulnerable_port = int(row[26])

        ports.append(port)
        services.append(service)
        oss.append(os_info)

        # Target label: 1 if exploit available, else 0
        y.append(has_exploit_available)

        # Build feature vector (numeric only for now)
        features.append([
            open_port_count, filtered_port_count, closed_port_count,
            tcpwrapped_count, total_vulnerabilities, exploit_risk_score,
            http_ports_open, ssh_ftp_ports_open, mail_ports_open,
            database_ports_open, remote_access_ports_open,
            has_web_service, has_ssh, has_database,
            has_high_severity_vuln, geographic_risk,
            is_open, is_common_vulnerable_port
        ])

# --- Encode categorical fields ---
port_encoder = preprocessing.LabelEncoder()
service_encoder = preprocessing.LabelEncoder()
os_encoder = preprocessing.LabelEncoder()

ports_encoded = port_encoder.fit_transform(ports)
services_encoded = service_encoder.fit_transform(services)
oss_encoded = os_encoder.fit_transform(oss)

# Append categorical encodings to each feature row
for i in range(len(features)):
    features[i].append(ports_encoded[i])
    features[i].append(services_encoded[i])
    features[i].append(oss_encoded[i])

# Convert to numpy arrays
X = np.array(features, dtype=float)
y = np.array(y, dtype=int)  # must be int for bincount and logistic regression

print("Unique labels in y:", np.unique(y))
print("Label distribution:", np.bincount(y))

# Train logistic regression
logr = linear_model.LogisticRegression(
    max_iter=1000,
    class_weight='balanced',  # handles class imbalance automatically
)
logr.fit(X, y)

# Test prediction on first row
example = X[0].reshape(1, -1)
prediction = logr.predict(example)
print("Prediction for first row (1 = exploit likely):", prediction[0])

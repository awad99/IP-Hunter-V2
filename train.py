# train.py
import csv
import numpy as np
from sklearn import preprocessing, linear_model
from sklearn.multiclass import OneVsRestClassifier
import joblib

features, exploit_labels = [], []
ports, services, oss = [], [], []

# Load CSV
with open("info.csv", "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if not row["exploit_label"]:
            continue
        feat = [
            int(row["open_port_count"]),
            int(row["filtered_port_count"]),
            int(row["closed_port_count"]),
            int(row["tcpwrapped_count"]),
            int(row["total_vulnerabilities"]),
            int(row["exploit_risk_score"]),
            int(row["http_ports_open"]),
            int(row["ssh_ftp_ports_open"]),
            int(row["mail_ports_open"]),
            int(row["database_ports_open"]),
            int(row["remote_access_ports_open"]),
            int(row["has_high_severity_vuln"]),
            int(row["geographic_risk"]),
            int(row["is_open"]),
            int(row["is_common_vulnerable_port"]),
        ]
        port = row["port"] or "none"
        service = row["port_status"] or "none"
        os_info = "linux" if row["os_linux"]=="1" else "windows" if row["os_windows"]=="1" else "unknown"

        ports.append(port)
        services.append(service)
        oss.append(os_info)
        features.append(feat)
        exploit_labels.append(row["exploit_label"])

# Encode categorical features
port_enc = preprocessing.LabelEncoder().fit(ports)
svc_enc = preprocessing.LabelEncoder().fit(services)
os_enc = preprocessing.LabelEncoder().fit(oss)

for i in range(len(features)):
    features[i].append(port_enc.transform([ports[i]])[0])
    features[i].append(svc_enc.transform([services[i]])[0])
    features[i].append(os_enc.transform([oss[i]])[0])

X = np.array(features, dtype=float)
y = np.array(exploit_labels)
label_enc = preprocessing.LabelEncoder()
y_encoded = label_enc.fit_transform(y)

# Use OneVsRestClassifier to avoid multi_class deprecation warning
clf = OneVsRestClassifier(
    linear_model.LogisticRegression(max_iter=1000, class_weight="balanced", solver="liblinear")
)
clf.fit(X, y_encoded)

# Save model and encoders
joblib.dump(clf, "exploit_model.pkl")
joblib.dump(port_enc, "port_enc.pkl")
joblib.dump(svc_enc, "svc_enc.pkl")
joblib.dump(os_enc, "os_enc.pkl")
joblib.dump(label_enc, "label_enc.pkl")

# Prediction function
def predict_best_exploit(scan_row):
    feat = [
        int(scan_row.get("open_port_count", 0)),
        int(scan_row.get("filtered_port_count", 0)),
        int(scan_row.get("closed_port_count", 0)),
        int(scan_row.get("tcpwrapped_count", 0)),
        int(scan_row.get("total_vulnerabilities", 0)),
        int(scan_row.get("exploit_risk_score", 0)),
        int(scan_row.get("http_ports_open", 0)),
        int(scan_row.get("ssh_ftp_ports_open", 0)),
        int(scan_row.get("mail_ports_open", 0)),
        int(scan_row.get("database_ports_open", 0)),
        int(scan_row.get("remote_access_ports_open", 0)),
        int(scan_row.get("has_high_severity_vuln", 0)),
        int(scan_row.get("geographic_risk", 0)),
        int(scan_row.get("is_open", 1)),
        int(scan_row.get("is_common_vulnerable_port", 0)),
    ]

    port_str = scan_row.get("port", "none")
    service_str = scan_row.get("port_status", "none")
    os_str = "linux" if scan_row.get("os_linux")=="1" else "windows" if scan_row.get("os_windows")=="1" else "unknown"

    feat.append(port_enc.transform([port_str])[0])
    feat.append(svc_enc.transform([service_str])[0])
    feat.append(os_enc.transform([os_str])[0])

    X_new = np.array([feat], dtype=float)
    pred_class = clf.predict(X_new)[0]
    best_exploit = label_enc.inverse_transform([pred_class])[0]
    return best_exploit

from enum import Enum

# defining enum
class AlertType(Enum):
    LOGIN_FAILURE = "login_failure"
    LOGIN_SUCCESS = "login_success"
    FILE_HASH_DETECTED = "file_hash_detected"
    DNS_QUERY = "dns_query"
    PORT_SCAN = "port_scan"

    # add the event types that are in alerts.txt
    PASSWORD_RESET = "password_reset"
    LOGOUT = "logout"
    QUARANTINE_TRIGGERED = "quarantine_triggered"
    MALWARE_ALERT = "malware_alert"
    SCAN_COMPLETED = "scan_completed"
    HTTP_REQUEST = "http_request"
    LOGIN_ATTEMPT = "login_attempt"

# Read and Parse FIle
with open("alerts.txt", "r", encoding="utf-8") as f:
    lines = f.read().splitlines()

print(f"Loaded {len(lines)} alerts.")

# convert string into enum values
records = []
for line in lines:
    # skip header row (your header is event_date,event_type,...)
    if line.startswith("event_date"):
        continue

    date, alert_type_str, asset, indicator = line.strip().split(",")

    alert_type = AlertType(alert_type_str)
    records.append((date, alert_type, asset, indicator))

print(records[0])

# Turn each record into an object
class Alert:
    def __init__(self, date, alert_type, asset, indicator):
        self.date = date
        self.alert_type = alert_type
        self.asset = asset
        self.indicator = indicator

    # Method that returns a severity string (now with enum comparisons)
    def severity(self):
        if self.alert_type == AlertType.FILE_HASH_DETECTED:
            return "HIGH"
        elif self.alert_type in [AlertType.PORT_SCAN, AlertType.DNS_QUERY]:
            return "MEDIUM"
        else:
            return "LOW"

# Convert reecords into alert objects
alerts = []
for date, alert_type, asset, indicator in records:
    alerts.append(Alert(date, alert_type, asset, indicator))

print(alerts[0].alert_type, alerts[0].severity())

# Printing Summary report
high = 0
medium = 0
low = 0

for a in alerts:
    sev = a.severity()
    if sev == "HIGH":
        high += 1
    elif sev == "MEDIUM":
        medium += 1
    else:
        low += 1

print("\n=== Summary ===")
print(f"HIGH: {high}")
print(f"MEDIUM: {medium}")
print(f"LOW: {low}")


# Checkpoint test
# AlertType.FILE_HASH_DETECTED expected
print(AlertType.FILE_HASH_DETECTED)
# file_hash_detected expected
print(AlertType.FILE_HASH_DETECTED.value)
# True or False expected
print(alerts[0].alert_type == AlertType.LOGIN_FAILURE)

with open("incident_summary.txt", "w", encoding="utf-8") as out:
    out.write("Incident Triage Summary\n")
    out.write("======================\n")
    out.write(f"Total alerts: {len(alerts)}\n")
    out.write(f"HIGH: {high}\n")
    out.write(f"MEDIUM: {medium}\n")
    out.write(f"LOW: {low}\n")


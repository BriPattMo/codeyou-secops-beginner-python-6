# Read and Parse FIle

with open("alerts.txt", "r", encoding="utf-8") as f:
    lines = f.read().splitlines()

print(f"Loaded {len(lines)} alerts.")

# Parse each line into parts
records = []
for line in lines:
    date, alert_type, asset, indicator = line.split(",")
    records.append((date, alert_type, asset, indicator))

print(records[0])

# Turn each record into an object
class Alert:
    def __init__(self, date, alert_type, asset, indicator):
        self.date = date
        self.alert_type = alert_type
        self.asset = asset
        self.indicator = indicator

# Method that returns a severity string
    def severity(self):
        if self.alert_type == "file_hash_detected":
            return "HIGH"
        elif self.alert_type in ["port_scan", "dns_query"]:
            return "MEDIUM"
        else:
            return "LOW"

# Checkpoint test
some_alert = Alert("2024-01-01", "file_hash_detected", "test-laptop", "abc123")
print(some_alert.severity())

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
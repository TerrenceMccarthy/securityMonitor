import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

raw_data_folder = Path("raw_data")
raw_data_folder.mkdir(exist_ok=True)

departments = ["Finance", "HR", "Engineering", "Sales", "IT", "Legal"]
operating_systems = ["Windows 10", "Windows 11", "macOS", "Linux"]
event_types = ["Failed Login", "Successful Login", "Malware Alert", "Policy Violation", "Password Reset"]
severity_levels = ["Low", "Medium", "High", "Critical"]

employees = []
devices = []
security_events = []

for i in range(1, 51):
    employee_id = f"EMP{i:03}"
    department = random.choice(departments)

    employees.append({
        "employee_id": employee_id,
        "employee_name": f"Employee {i}",
        "department": department
    })

    device_id = f"LAPTOP--{i:03}"
    risk_score = random.randint(1, 100)

    devices.append({
        "device_id": device_id,
        "employee_id": employee_id,
        "os": random.choice(operating_systems),
        "compliant": random.choice([True, False]),
        "risk_score": risk_score
    })

    for _ in range(random.randint(3,10)):
        event_time = datetime.now() - timedelta(days=random.randint(0,30))

        security_events.append({
            "event_id": f"EVT{len(security_events) + 1:04}",
            "device_id": device_id,
            "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": random.choice(event_types),
            "severity": random.choice(severity_levels)
        })

def write_csv(file_name, rows):
    file_path = raw_data_folder / file_name

    with open(file_path, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames = rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

write_csv("employees.csv", employees)
write_csv("devices.csv", devices)
write_csv("security_events.csv", security_events)

print("Fake data generated successfully.")
print("Files Created: ")
print("raw_data/employees.csv")
print("raw_data/devices.csv")
print("raw_data/security_events.csv")


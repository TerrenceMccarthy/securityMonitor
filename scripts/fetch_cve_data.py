import csv 
import json
import requests
from pathlib import Path

# create a reference to the raw_data folder
# this is where we will save API outputs
raw_data_folder = Path("raw_data")

# create the folder if it does not already exist
raw_data_folder.mkdir(exist_ok=True)

# National vulnerability database (NVD) API endpoint
# this API provides real-world CVE vulnerability data
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Query parameters for the API request
# we are requesting : 
# - 25 results
# vulnerabilities related to microsoft windows
params = {
    "resultsPerPage": 25,
    "keywordSearch": "Microsoft Windows"
}

# send get request to the API
response = requests.get(url, params=params, timeout=30)

# Raise an error if request failed
response.raise_for_status()

# convert API response JSON into python dictionary
data = response.json()

# save the full raw API response 
# This simulates storing raw enterprise telmetry/log data
with open("raw_data/cve_raw.json", "w", encoding="utf-8") as file:
    json.dump(data, file, indent=4)

# list that will hold cleaned vulnerability records
rows = []

# loop through each vulnerability returned by the API
for item in data.get("vulnerabilities", []):
    # extract nested CVE object
    cve = item.get("cve", {})

    # basic CVE metadata
    cve_id = cve.get("id", "")
    published = cve.get("published", "")
    last_modified = cve.get("lastModified", "")
    status = cve.get("vulnStatus", "")

    # extract english vulnerability descriptions
    description = ""

    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # default severity values
    severity = "UNKNOWN"
    base_score = ""

    # CVSS metrics contain severity scoring information
    metrics = cve.get("metrics", {})

    # CVSS v3.1 severity extraction
    if "cvssMetricV31" in metrics: 
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
        base_score = cvss_data.get("baseScore", "")
    # CVSS v3.0 fallback
    elif "cvssMetricV30" in metrics:
        cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
        base_score = cvss_data.get("baseScore", "")
    # CVSS v2 fall back
    elif "cvssMetricV2" in metrics:
        cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
        base_score = cvss_data.get("baseScore", "")

    # store cleaned vulnerability record
    rows.append({
        "cve_id": cve_id,
        "published": published,
        "last_modified": last_modified,
        "status": status,
        "severity": severity,
        "base_score": base_score,
        "description": description
    })

# save cleaned vulnerability data to csv
# this file will later be processed by pyspark and power BI
with open ("raw_data/cve_vulnerabilities.csv", "w", newline="", encoding="utf-8")as file:
    # CSV column names
    fieldnames = [
        "cve_id",
        "published",
        "last_modified",
        "status",
        "severity",
        "base_score",
        "description"
    ]

    # create csv writer object
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    # write csv header row
    writer.writeheader()
    # write all vulnerability rows
    writer.writerows(rows)

# success messages
print("CVE data detched successfully.")
print("Files created: ")
print("raw_data/cve_raw.json")
print("raw_data/cve_vulnerabilities.csv")
print(f"Total CVEs saved: {len(rows)}")


import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, avg, when

os.environ["HADOOP_HOME"] = "C:\\hadoop"
os.environ["hadoop.home.dir"] = "C:\\hadoop"

# windows hadoop configuration 
spark = SparkSession.builder \
    .appName("ProcessSecurityData") \
    .config("spark.hadoop.io.native.lib.available", "false") \
    .getOrCreate()

# load raw csv files
employees_df = spark.read.csv("raw_data/employees.csv", header=True, inferSchema=True)
devices_df = spark.read.csv("raw_data/devices.csv", header=True, inferSchema=True)
events_df = spark.read.csv("raw_data/security_events.csv", header=True, inferSchema=True)
cve_df = spark.read.csv("raw_data/cve_vulnerabilities.csv", header=True, inferSchema=True)

# join devices with employees
device_employee_df = devices_df.join(employees_df, on="employee_id", how="inner")

# filter high reisk devices
high_risk_devices = device_employee_df.filter(col("risk_score") >= 80)

# department risk summary
department_risk_summary = device_employee_df.groupBy("department").agg(
    count("device_id").alias("total_devices"),
    avg("risk_score").alias("average_risk_score")
)

# failed login summary
failed_login_summary = events_df.filter(col("event_type") == "Failed Login") \
.groupBy("device_id") \
.agg(count("event_id").alias("failed_login_count"))

# add risk category column
device_risk_with_category = device_employee_df.withColumn(
    "risk_category",
    when(col("risk_score") >= 80, "High")
    .when(col("risk_score") >= 50, "Medium")
    .otherwise("Low")
)

cve_severity_summary = cve_df.groupBy(
    "severity"
).agg(
    count("cve_id").alias("total_vulnerabilities"),
    avg("base_score").alias("average_base_score")
)

# save processed datasets
# Convert Spark DataFrames to pandas and save as CSV files

high_risk_devices.toPandas().to_csv(
    "processed_data/high_risk_devices.csv",
    index=False
)

department_risk_summary.toPandas().to_csv(
    "processed_data/department_risk_summary.csv",
    index=False
)

failed_login_summary.toPandas().to_csv(
    "processed_data/failed_login_summary.csv",
    index=False
)

device_risk_with_category.toPandas().to_csv(
    "processed_data/device_risk_with_category.csv",
    index=False
)

cve_severity_summary.toPandas().to_csv(
    "processed_data/cve_severity_summary.csv",
    index=False
)

# stop spark
spark.stop()

print("Security data processed successfully.")
print("Processed files created in processed_data folder.")
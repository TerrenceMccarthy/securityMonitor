import pandas as pd 
import requests 
from pyspark.sql import SparkSession


print("Python setup works")

spark = SparkSession.builder.appName("EndpointSecurityPipeline").getOrCreate()
print("PySpark setup works")

spark.stop()



#!/usr/bin/env python3
import os, csv, yaml
from dotenv import load_dotenv

def main(): 
  print("Hello world!")
  nessus_ouput_csv = './samples/Nessus-Scan.csv'
  affected_services = extractAffectedServices(nessus_ouput_csv)
  print(affected_services)

def extractAffectedServices(input):
  affected_services = []
  with open(input) as csvfile:
      reader = csv.DictReader(csvfile)
      for row in reader:
        # service in 127.0.0.1:3128
        service = "{}:{}".format(row['Host'],row['Port'])
        # avoid adding duplicate
        if service not in affected_services:    
          affected_services.append(service)
  return affected_services

# execute run time
main()

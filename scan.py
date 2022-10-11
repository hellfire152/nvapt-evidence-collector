#!/usr/bin/env python3
import os, csv, yaml
from dotenv import load_dotenv

def main(): 
  print("Hello world!")
  nessus_ouput_csv = './samples/Nessus-Scan.csv'
  print(getAffectedServices(nessus_ouput_csv))

def getAffectedServices(input):
  unique_services = getUniqueServices(input)
  return checkTls(unique_services, input)

def checkTls(services, input):
  for i in range(len(services)): 
    host, port, cipher = services[i].split(':')
    with open(input) as csvfile:
      reader = csv.DictReader(csvfile)
      for row in reader:
        if row['Host'] == host and row['Port'] == port and cipher == 'no':
          # TLSv1.2 is enabled and the server supports at least one cipher.'
          if 'cipher' in row['Plugin Output']:
            services[i] = services[i].replace('no', 'yes')
  return services

def getUniqueServices(input):
  unique_services = []
  with open(input) as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
      # service in 127.0.0.1:3128:no
      service = "{}:{}:no".format(row['Host'],row['Port'])
      # avoid adding duplicate
      if service not in unique_services:    
        unique_services.append(service)
  return unique_services

# execute run time
main()

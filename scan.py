#!/usr/bin/env python3
import os, sys, csv, yaml
from dotenv import load_dotenv

def main():
  load_dotenv() 
  checkRunTimeInputs(sys.argv)
  services = getAffectedServices(sys.argv[1])
  commands = getCommands(str(os.environ.get('COMMANDS_FILE')))
  print(services, '\n', commands)

# other functions
def checkRunTimeInputs(input): 
  if len(input) != 2 :
    print('[-] ERROR: Missing input on Nessus CSV report.')
    print('e.g. scan.py ./samples/Nessus-Scan.csv')
    sys.exit()
  checkFileExists(sys.argv[1])

def checkFileExists(file, exit=True):
	check = True
	if os.path.exists(file) == False: 
		print("[-] ERROR: {} cannot be found".format(file))
		check = False
		if exit:
			sys.exit()
	return check

def getCommands(yaml_file):
	checkFileExists(yaml_file)
	# loading scan setup vars from the supplied yaml file.
	app_yaml_inputs = ""	
	with open(yaml_file, 'r') as stream:
		app_yaml_inputs = yaml.safe_load(stream)
	return app_yaml_inputs

# for reading nessus csv report and extract affected services, protocol:host:port:isTls
# e.g. # ['tcp:127.0.0.1:3128:no', 'tcp:127.0.0.1:8834:yes']
def getAffectedServices(input):
  unique_services = getUniqueServices(input)
  return checkTls(unique_services, input)

def checkTls(services, input):
  for i in range(len(services)): 
    protocol, host, port, cipher = services[i].split(':')
    with open(input) as csvfile:
      reader = csv.DictReader(csvfile)
      for row in reader:
        if row['Protocol'] == protocol and row['Host'] == host and row['Port'] == port and cipher == 'no':
          # TLSv1.2 is enabled and the server supports at least one cipher.'
          if 'cipher' in row['Plugin Output']:
            services[i] = services[i].replace('no', 'yes')
  # ['tcp:127.0.0.1:3128:no', 'tcp:127.0.0.1:8834:yes']
  return services

def getUniqueServices(input):
  unique_services = []
  with open(input) as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
      service = ''
      if str(row['Port']) != '0':
        # service in tcp:127.0.0.1:3128:no
        service = "{}:{}:{}:no".format(row['Protocol'],row['Host'],row['Port'])
        # avoid adding duplicate
        if service not in unique_services:    
          unique_services.append(service)
  # ['tcp:127.0.0.1:3128:', 'tcp:127.0.0.1:8834:']
  return unique_services

# execute run time
main()

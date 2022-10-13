#!/usr/bin/env python3
import os, sys, csv, yaml, socket
from dotenv import load_dotenv

def main():
  load_dotenv() 
  checkRunTimeInputs(sys.argv)
  services = getAffectedServices(sys.argv[1])
  commands = getCommands(str(os.environ.get('COMMANDS_FILE')))
  outputs_folder = os.path.dirname(sys.argv[1]) # e.g. ./samples

  vulns_scan(services, commands, outputs_folder)
  # print(services, '\n', commands)
  # print(checkOpenPort('127.0.0.1', 80))

def vulns_scan(affected_services, commands, folder): 
  for service in affected_services: 
    protocol, host, port, cipher = service.split(':')
    # print(protocol, host, port, cipher)
    updated_cmds = []
    # extract commands for TCP services 
    if str(protocol).lower() == 'tcp':
      # check whether the affected tcp service is open port
      if (checkOpenPort(host, port)):
        print("[+] TCP: '{}:{}:{}' reachable!".format(protocol, host, port))
        # extract TCP commands when affected service port and commands' port match
        for cmd_port in commands['TCP']:
          if int(cmd_port) == int(port): 
            updated_cmds = replaceIdentifiers(commands['TCP'][int(cmd_port)], host, port, folder)
          # print(len(updated_cmds))
          runCommands(updated_cmds)
        # extract TLS commands when affected service is found with ssl/tls
        if (cipher == 'yes'):
          for cmd in commands['TLS']:
            updated_cmds = replaceIdentifiers(commands['TLS'], host, port, folder)
          # print(len(updated_cmds))
          runCommands(updated_cmds)
      else:
        print("[-] ERROR: '{}:{}:{}' unreachable".format(protocol, host, port))
    # rest are UDP
    else:
      print("[+] UCP: '{}:{}:{}'".format(protocol, host, port)) 
      for cmd_port in commands['UDP']:
        if int(cmd_port) == int(port): 
          updated_cmds = replaceIdentifiers(commands['UDP'][int(cmd_port)], host, port, folder)
      # print(len(updated_cmds))
      runCommands(updated_cmds)

# other functions
def checkRunTimeInputs(input): 
  if len(input) != 2 :
    print('[-] ERROR: Missing input on Nessus CSV report.')
    print('e.g. bash scan.sh ./samples/Nessus-Scan.csv')
    print('e.g. python3 scan.py ./samples/Nessus-Scan.csv')
    sys.exit()
  checkFileExists(sys.argv[1])

def checkFileExists(file, exit=True):
	check = True
	if os.path.exists(file) == False: 
		print("[-] ERROR: {} cannot be found".format(file))
		check = False
		if exit: sys.exit() 
	return check

def checkOpenPort(host, port):
  a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  location = (str(host), int(port))
  result_of_check = a_socket.connect_ex(location)
  if result_of_check == 0:
    return True
  else:
    return False

def getCommands(yaml_file):
	checkFileExists(yaml_file)
	# loading scan setup vars from the supplied yaml file.
	app_yaml_inputs = ""	
	with open(yaml_file, 'r') as stream:
		app_yaml_inputs = yaml.safe_load(stream)
	return app_yaml_inputs

def replaceIdentifiers(commands, host, port, folder):
  updated_commands = []
  for command in commands: 
    temp_cmd = command.replace("{%HOST%}", host)
    temp_cmd = temp_cmd.replace("{%PORT%}", port)
    temp_cmd = temp_cmd.replace("{%FOLDER%}", folder)
    updated_commands.append(temp_cmd)
  return updated_commands

def runCommands(commands):
  for cmd in commands:
    print("[!] Running command: '{}'".format(cmd)) 
    os.system(cmd) # nosec B605

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

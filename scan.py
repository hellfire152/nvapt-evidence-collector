#!/usr/bin/env python3
import os, sys, csv, yaml, socket, subprocess
from dotenv import load_dotenv

# replace ./samples/Nessus-Scan.csv to ./samples/Nessus-Scan.output
input_file = str(sys.argv[1])
output_file = input_file.replace('.csv', '.output')
f = open(output_file,'w')

def main():
  load_dotenv()
  checkRunTimeInputs(sys.argv)
  services = getAffectedServices(sys.argv[1])

  printWithOutput("[+] '{}' unique services found!".format(len(services)))
  printWithOutput('protocol:host:port:isTls:isWeb') # print header row
  for service in services:
    printWithOutput(service)

  commands = getCommands(str(os.environ.get('COMMANDS_FILE')))
  outputs_folder = os.path.dirname(sys.argv[1]) # e.g. ./samples

  getLocalSetups()
  vulnsScan(services, commands, outputs_folder)
  f.close()

def printWithOutput(message):
  print(message)
  f.write(message + '\n')

def getLocalSetups():
  # get local ip and setups
  printWithOutput('\n### Local Setups\n')
  printWithOutput((subprocess.check_output("ifconfig")).decode('utf-8'))
  printWithOutput((subprocess.check_output("route")).decode('utf-8'))
  printWithOutput('###\n\n')

def vulnsScan(affected_services, commands, folder):
  for service in affected_services:
    protocol, host, port, cipher, web = service.split(':')
    # printWithOutput(protocol, host, port, cipher, web)
    updated_cmds = []
    # extract commands for TCP services
    if str(protocol).lower() == 'tcp':
      # check whether the affected tcp service is open port
      if (checkOpenPort(host, port)):
        printWithOutput("[+] TCP: '{}:{}:{}' reachable!".format(protocol, host, port))
        # extract TCP commands when affected service port and commands' port match
        for cmd_port in commands['TCP']:
          if int(cmd_port) == int(port):
            updated_cmds = replaceIdentifiers(commands['TCP'][int(cmd_port)], host, port, folder)
          # printWithOutput(len(updated_cmds))
          runCommands(updated_cmds)
        # extract TLS commands when affected service is found with ssl/tls
        if (cipher == 'yes'):
          for cmd in commands['TLS']:
            updated_cmds = replaceIdentifiers(commands['TLS'], host, port, folder)
          # printWithOutput(len(updated_cmds))
          runCommands(updated_cmds)
        # extract WEB commands when affected service is found to be web server
        if (web == 'yes'):
          for cmd in commands['WEB']:
            updated_cmds = replaceIdentifiers(commands['WEB'], host, port, folder)
            if (cipher == 'yes'):
              # replace 'http' -> 'https' when service found with cipher
              updated_cmds = [s.replace('http', 'https') for s in updated_cmds]
            #printWithOutput(len(updated_cmds))
          runCommands(updated_cmds)
      else:
        printWithOutput("[-] ERROR: '{}:{}:{}' unreachable".format(protocol, host, port))
    # rest are UDP
    else:
      printWithOutput("[+] UCP: '{}:{}:{}'".format(protocol, host, port))
      for cmd_port in commands['UDP']:
        if int(cmd_port) == int(port):
          updated_cmds = replaceIdentifiers(commands['UDP'][int(cmd_port)], host, port, folder)
      # printWithOutput(len(updated_cmds))
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
		printWithOutput("[-] ERROR: {} cannot be found".format(file))
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
    printWithOutput("[!] Running command: '{}'".format(cmd))
    os.system(cmd)

# for reading nessus csv report and extract affected services, protocol:host:port:isTls:isWeb
# e.g. # ['tcp:127.0.0.1:3128:no', 'tcp:127.0.0.1:8834:yes']
def getAffectedServices(input):
  unique_services = getUniqueServices(input)
  unique_services = checkTls(unique_services, input)
  return checkWebServer(unique_services, input)

def checkWebServer(services, input):
  for i in range(len(services)):
    protocol, host, port, cipher, web = services[i].split(':')
    with open(input) as csvfile:
      reader = csv.DictReader(csvfile)
      for row in reader:
        if row['Protocol'] == protocol and row['Host'] == host and row['Port'] == port and web == 'no':
          # TLSv1.2 is enabled and the server supports at least one cipher.'
          if 'The remote web server type is' in row['Plugin Output']:
            # web = yes
            services[i] = "{}:{}:{}:{}:yes".format(protocol, host, port, cipher)
  # ['tcp:127.0.0.1:3128:no:yes', 'tcp:127.0.0.1:8834:yes:yes']
  return services

def checkTls(services, input):
  for i in range(len(services)):
    protocol, host, port, cipher, web = services[i].split(':')
    with open(input) as csvfile:
      reader = csv.DictReader(csvfile)
      for row in reader:
        if row['Protocol'] == protocol and row['Host'] == host and row['Port'] == port and cipher == 'no':
          # TLSv1.2 is enabled and the server supports at least one cipher.'
          if 'cipher' in row['Plugin Output']:
            # ciper = yes
            services[i] = "{}:{}:{}:yes:{}".format(protocol, host, port, web)
  # ['tcp:127.0.0.1:3128:no:no', 'tcp:127.0.0.1:8834:yes:no']
  return services

def getUniqueServices(input):
  unique_services = []
  with open(input) as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
      service = ''
      if str(row['Port']) != '0':
        # service in tcp:127.0.0.1:3128:no:no (protocol:host:port:isTls:isWeb)
        service = "{}:{}:{}:no:no".format(row['Protocol'],row['Host'],row['Port'])
        # avoid adding duplicate
        if service not in unique_services:
          unique_services.append(service)
  # ['tcp:127.0.0.1:3128:', 'tcp:127.0.0.1:8834:']
  return unique_services

# execute run time
main()

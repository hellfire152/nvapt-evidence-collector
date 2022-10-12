# nvapt-evidence-collector
This python tool runs designated commands against affected services. It is meant to be run in Kali Linux. 

## Prerequisite
The following packages need to be installed in Kali Linux
```
apt install python3.10-venv
```

## How to run
1. Setup the environment with `bash setup.sh`
1. Run the scan with the selected Nessus CSV report, `bash scan.sh ./sample/Nessus-CSV-Output.csv`.
    * The commands' output can be found in the same directory where the Nessus CSV report lies, e.g. `./sample/*.txt`. 

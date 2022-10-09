#!/bin/bash

echo 'Activating virtualenv'
source venv/bin/activate

# start zap scan
python3 scan.py

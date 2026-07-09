#!/bin/bash
# Double-click this on the Mac to start the HaiveControl hub.
cd "$(dirname "$0")"
python3 -m pip install --quiet -r requirements.txt
exec python3 hub.py

@echo off
REM Build HaiveControl.exe (run once on the Windows machine)
pip install -r requirements.txt pyinstaller
pyinstaller --onefile --name HaiveControl ^
  --hidden-import zeroconf._utils.ipaddress ^
  --hidden-import zeroconf._handlers.answers ^
  server.py
echo.
echo Done. The single-file exe is in  dist\HaiveControl.exe

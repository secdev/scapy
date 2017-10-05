@echo off
set PYTHONPATH=%cd%
set PYTHONDONTWRITEBYTECODE=True
"C:\Program Files (x86)\Python3\python.exe" -m scapy.__init__ %*
if errorlevel 1 (
   PAUSE
)

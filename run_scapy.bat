@echo off
set PYTHONPATH=%cd% 
python -m scapy.__init__
if errorlevel 1 (
   PAUSE
)

@echo off
call run_scapy_py2.bat --nopause
if errorlevel 1 (
   call run_scapy_py3.bat --nopause
)
if errorlevel 1 (
   PAUSE
)
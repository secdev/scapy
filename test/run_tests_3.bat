@echo off
set MYDIR=%cd%\..
set PYTHONPATH=%MYDIR%
if [%1]==[] (
  D:\Programms\Python3\python.exe "%MYDIR%\scapy\tools\UTscapy.py" -t regression.uts -K mock_read_routes6_bsd -K automaton -f html -o scapy_regression3_test_%date:~6,4%_%date:~3,2%_%date:~0,2%.html
) else (
  D:\Programms\Python3\python.exe "%MYDIR%\scapy\tools\UTscapy.py" %@
)
PAUSE

@echo off
set MYDIR=%cd%\..
set PYTHONPATH=%MYDIR%
if [%1]==[] (
  python "%MYDIR%\scapy\tools\UTscapy.py" -t regression.uts -K automaton -f html -o scapy_regression_test_%date:~6,4%_%date:~3,2%_%date:~0,2%.html
) else (
  python "%MYDIR%\scapy\tools\UTscapy.py" %@
)
PAUSE

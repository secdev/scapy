@echo off
set MYDIR=%cd%\..
set PYTHONPATH=%MYDIR%
if [%1]==[] (
  python %MYDIR%\scapy\tools\UTscapy.py -t regression.uts -f html -o scapy_regression_test_%DATE%.html
) else (
  python %MYDIR%\scapy\tools\UTscapy.py %1 %2 %3 %4 %5 %6 %7 %8 %9
)

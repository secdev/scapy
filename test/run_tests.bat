@echo off
title UTscapy
set MYDIR=%cd%\..
set PYTHONPATH=%MYDIR%
if [%1]==[] (
  SET date=%DATE%
  python %MYDIR%\scapy\tools\UTscapy.py -t regression.uts -K automaton -K mock_read_routes6_bsd -f html -o scapy_regression_test_%date:~6,4%_%date:~3,2%_%date:~0,2%.html
) else (
  python %MYDIR%\scapy\tools\UTscapy.py %1 %2 %3 %4 %5 %6 %7 %8 %9
)
if errorlevel 1 (
   PAUSE
)

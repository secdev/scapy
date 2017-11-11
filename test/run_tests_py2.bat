@echo off
title UTscapy - All tests - PY2
set MYDIR=%cd%\..
set PYTHONPATH=%MYDIR%
if [%1]==[] (
  python "%MYDIR%\scapy\tools\UTscapy.py" -c configs\\windows2.utsc -T bpf.uts -T linux.uts -o scapy_regression_test_%date:~6,4%_%date:~3,2%_%date:~0,2%.html
) else (
  python "%MYDIR%\scapy\tools\UTscapy.py" %@
)
PAUSE
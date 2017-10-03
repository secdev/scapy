@echo off
title UTscapy - All tests - PY3
set MYDIR=%cd%\..
set PYTHONPATH=%MYDIR%
set PYTHONDONTWRITEBYTECODE=True
if [%1]==[] (
  python3 "%MYDIR%\scapy\tools\UTscapy.py" -c configs\\windows2.utsc -T bpf.uts -T linux.uts -o scapy_py3_regression_test_%date:~6,4%_%date:~3,2%_%date:~0,2%.html
) else (
  python3 "%MYDIR%\scapy\tools\UTscapy.py" %@
)
PAUSE
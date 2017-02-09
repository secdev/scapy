@echo off
set MYDIR=%cd%\..
set PYTHONPATH=%MYDIR%
python "%MYDIR%\scapy\tools\UTscapy.py" -t tls/tests_tls_netaccess.uts -f html -o scapy_tls_test_%date:~6,4%_%date:~3,2%_%date:~0,2%.html
PAUSE

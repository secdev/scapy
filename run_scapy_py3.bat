@echo off
set PYTHONPATH=%~dp0
set PYTHONDONTWRITEBYTECODE=True
if "%1"=="--nopause" (
  set nopause="True"
  python3 -m scapy
) else (
  set nopause="False"
  python3 -m scapy %*
)
if %errorlevel%==1 if NOT "%nopause%"=="True" (
   PAUSE
)

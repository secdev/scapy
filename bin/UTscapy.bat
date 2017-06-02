@echo off
REM Use Python to run the UTscapy script from the current directory, passing all parameters
title UTscapy
python "%~dp0\UTscapy" %*

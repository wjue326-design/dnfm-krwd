@echo off
chcp 65001 >nul
set PY=C:\Users\WANG\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe
"%PY%" -X utf8 "%~dp0dnfm_kit.py" %*
pause

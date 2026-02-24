@echo off
setlocal
echo ========================================
echo Starting Intrusion Detection Dashboard
echo ========================================
echo.
echo Dashboard will be available at:
echo   Local: http://localhost:14094
echo   Remote: http://YOUR_IP_ADDRESS:14094
echo.
echo Press Ctrl+C to stop the server
echo.

:: Check if venv exists
if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found. Please run: python -m venv venv
    pause
    exit /b 1
)

:: Run using the virtual environment's python
".\venv\Scripts\python.exe" app.py
pause

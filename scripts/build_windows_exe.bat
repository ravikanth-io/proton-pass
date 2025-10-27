@echo off
REM Build SmartPass CLI and GUI executables using PyInstaller (cmd-friendly)
REM Usage: run from project root with venv activated

REM Activate venv if needed (adjust path if different)
call "%~dp0\..\venv\Scripts\activate.bat"

REM ensure pyinstaller installed
pip install --quiet pyinstaller

REM cleanup previous builds
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del /q SmartPass.spec 2>nul
del /q SmartPassGUI.spec 2>nul

REM Build CLI exe (console)
echo Building CLI exe...
pyinstaller --onefile --name SmartPass smartpass\cli.py
IF %ERRORLEVEL% NEQ 0 (
  echo PyInstaller CLI build failed with exit code %ERRORLEVEL%.
  pause
  exit /b %ERRORLEVEL%
)

REM Build GUI exe collecting PySide6
echo Building GUI exe (may take longer)...
pyinstaller --onefile --name SmartPassGUI --collect-all PySide6 smartpass\gui.py
IF %ERRORLEVEL% NEQ 0 (
  echo PyInstaller GUI build failed with exit code %ERRORLEVEL%.
  pause
  exit /b %ERRORLEVEL%
)

echo Build completed. Check dist\SmartPass.exe and dist\SmartPassGUI.exe
pause

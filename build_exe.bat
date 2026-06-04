@echo off
setlocal

echo =============================================================
echo  EML Analyzer -- Standalone EXE Builder
echo =============================================================
echo.

echo [1/3] Installing / upgrading build tool...
pip install --quiet --upgrade pyinstaller
if errorlevel 1 (
    echo ERROR: pip install pyinstaller failed.
    pause & exit /b 1
)

echo [2/3] Installing all runtime dependencies...
pip install --quiet --upgrade requests "extract-msg>=0.48" "oletools>=0.60.2" "olefile>=0.47" "pdfid>=1.0.0" "pillow>=10.2.0" "pyzbar>=0.1.9" "pymupdf>=1.24.0"
REM peepdf-3 has an optional heavy C++ dependency (STPyV8); install without it
pip install --quiet --upgrade --no-deps "peepdf-3>=0.4.2"
if errorlevel 1 (
    echo WARNING: Some optional packages failed to install.
    echo          The exe will still be built — features requiring them will show status=missing.
)

echo [3/3] Building single-file exe...
pyinstaller eml_analyzer.spec --clean --noconfirm
if errorlevel 1 (
    echo ERROR: PyInstaller build failed.
    pause & exit /b 1
)

echo.
echo =============================================================
echo  BUILD COMPLETE
echo  Output: dist\eml-analyzer.exe
echo =============================================================
echo.
echo  HOW TO DEPLOY:
echo  1. Copy  dist\eml-analyzer.exe  to any folder
echo  2. Copy  .env.example           to that same folder
echo  3. Rename .env.example to .env and fill in your API keys
echo  4. Run:  eml-analyzer.exe -f email.eml
echo     Or:   eml-analyzer.exe -d C:\Cases\emails --recursive
echo.
echo  The exe reads .env from the same folder it lives in,
echo  regardless of which directory you run it from.
echo =============================================================
echo.
pause

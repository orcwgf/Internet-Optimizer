@echo off
setlocal
set "ROOT=%~dp0"
set "DIST=%ROOT%dist"

call "%ROOT%build.bat"
if errorlevel 1 (
  echo [NetPilot] Build failed; nothing packaged.
  exit /b 1
)

if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%\NetPilot"
copy /y "%ROOT%build\bin\netpilot.exe" "%DIST%\NetPilot\NetPilot.exe" >nul
copy /y "%ROOT%README.md" "%DIST%\NetPilot\README.md" >nul

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Compress-Archive -Path '%DIST%\NetPilot\*' -DestinationPath '%DIST%\NetPilot.zip' -Force"

if errorlevel 1 (
  echo [NetPilot] Could not create the zip. The folder is ready at:
  echo            %DIST%\NetPilot
  exit /b 1
)

echo.
echo [NetPilot] Portable package ready:
echo            %DIST%\NetPilot.zip
echo [NetPilot] Send the zip. Your friend unzips it and runs NetPilot.exe.
endlocal

@echo off
setlocal enabledelayedexpansion
set "ROOT=%~dp0"
set "BUILD=%ROOT%build"

set "VSPATH="
for %%p in (
  "%ProgramFiles%\Microsoft Visual Studio\2022\Community"
  "%ProgramFiles%\Microsoft Visual Studio\2022\Professional"
  "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise"
  "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools"
  "%ProgramFiles%\Microsoft Visual Studio\18\Community"
  "%ProgramFiles%\Microsoft Visual Studio\18\Professional"
  "%ProgramFiles%\Microsoft Visual Studio\18\Enterprise"
  "%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools"
) do (
  if not defined VSPATH if exist "%%~p\VC\Auxiliary\Build\vcvars64.bat" set "VSPATH=%%~p"
)
if not defined VSPATH (
  echo [NetPilot] Could not find Visual Studio C++ build tools.
  echo            Install "Desktop development with C++" and try again.
  exit /b 1
)

set "CMAKE=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not exist "%CMAKE%" set "CMAKE=cmake"

call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul
if errorlevel 1 (
  echo [NetPilot] Failed to initialise the MSVC environment.
  exit /b 1
)

rem Visual Studio ships Ninja with its CMake tools; do not require a
rem separate Ninja install on the build machine.
set "PATH=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"

echo [NetPilot] Configuring...
"%CMAKE%" -S "%ROOT%." -B "%BUILD%" -G Ninja -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1

echo [NetPilot] Building...
"%CMAKE%" --build "%BUILD%"
if errorlevel 1 exit /b 1

echo [NetPilot] Testing...
ctest --test-dir "%BUILD%" --output-on-failure
if errorlevel 1 exit /b 1

echo.
echo [NetPilot] Built: %BUILD%\bin\netpilot.exe
echo [NetPilot] Run:   "%BUILD%\bin\netpilot.exe"
echo [NetPilot] Snapshot without the UI: "%BUILD%\bin\netpilot.exe" --dump
echo [NetPilot] Portable zip for a friend: .\package.bat
endlocal

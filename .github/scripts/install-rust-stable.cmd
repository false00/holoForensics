@echo off
setlocal

set "CARGO_BIN=%USERPROFILE%\.cargo\bin"
set "RUSTUP_EXE=%CARGO_BIN%\rustup.exe"
set "RUSTUP_INIT=%RUNNER_TEMP%\rustup-init.exe"

if not exist "%RUSTUP_EXE%" (
  echo.
  echo ==> Downloading rustup-init.exe
  powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $env:RUNNER_TEMP\rustup-init.exe"
  if errorlevel 1 exit /b 1

  echo.
  echo ==> Installing rustup and the stable toolchain
  "%RUSTUP_INIT%" -y --profile minimal --default-toolchain stable
  if errorlevel 1 exit /b 1
)

echo.
echo ==> Ensuring stable Rust toolchain is installed
"%RUSTUP_EXE%" set profile minimal
if errorlevel 1 exit /b 1

"%RUSTUP_EXE%" toolchain install stable
if errorlevel 1 exit /b 1

"%RUSTUP_EXE%" default stable
if errorlevel 1 exit /b 1

>> "%GITHUB_PATH%" echo %CARGO_BIN%
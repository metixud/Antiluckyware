@echo off
setlocal EnableDelayedExpansion

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo run as admin
    pause
    exit /b
)

set HOSTS=%SystemRoot%\System32\drivers\etc\hosts

if not exist "%HOSTS%" (
    echo hosts not found
    pause
    exit /b
)

set DOMAINS=^
i-like.boats ^
devruntime.cy ^
zetolacs-cloud.top ^
devruntime.cy ^
frozi.cc ^
exo-api.tf ^
nuzzyservices.com ^
darkside.cy ^
balista.lol ^
phobos.top ^
phobosransom.com ^
pee-files.nl ^
vcc-library.uk ^
luckyware.co ^
luckyware.cc ^
dhszo.darkside.cy ^
risesmp.net ^
luckystrike.pw ^
luckyware.pw ^
krispykreme.top ^
vcc-redistrbutable.help ^
i-slept-with-ur.mom

set IPS=^
91.92.243.218 ^
188.114.96.11

set OK=0
set SKIP=0
set FW=0

for %%D in (%DOMAINS%) do (
    findstr /i "%%D" "%HOSTS%" >nul
    if errorlevel 1 (
        echo 0.0.0.0 %%D>>"%HOSTS%"
        if not errorlevel 1 (
            set /a OK+=1
        )
    ) else (
        set /a SKIP+=1
    )
)

for %%I in (%IPS%) do (
    netsh advfirewall firewall show rule name="BLOCK_%%I" >nul 2>&1
    if errorlevel 1 (
        netsh advfirewall firewall add rule name="BLOCK_%%I" dir=out action=block remoteip=%%I >nul
        if not errorlevel 1 (
            set /a FW+=1
        )
    )
)

ipconfig /flushdns >nul

echo added hosts : %OK%
echo skipped hosts : %SKIP%
echo firewall rules : %FW%
pause
endlocal

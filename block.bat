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
    echo where is the host file dawn
    pause
    exit /b 1
)

netsh advfirewall show allprofiles >nul 2>&1
if %errorlevel% neq 0 (
    echo firewall not available
    pause
    exit /b 1
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
91.92.243.218 ^
dhszo.darkside.cy ^
188.114.96.11 ^
risesmp.net ^
luckystrike.pw ^
luckyware.pw ^
krispykreme.top ^
vcc-redistrbutable.help ^
i-slept-with-ur.mom

set OK=0
set SKIP=0
set FWOK=0
set FWSKIP=0

for %%D in (%DOMAINS%) do (
    findstr /i "%%D" "%HOSTS%" >nul
    if errorlevel 1 (
        echo 0.0.0.0 %%D>>"%HOSTS%"
        if errorlevel 1 (
            echo can't add : %%D
        ) else (
            echo good : %%D
            set /a OK+=1
        )
    ) else (
        echo already good : %%D
        set /a SKIP+=1
    )

    echo %%D | find "." >nul
    if not errorlevel 1 (
        netsh advfirewall firewall show rule name="BLOCK_%%D" >nul 2>&1
        if errorlevel 1 (
            netsh advfirewall firewall add rule name="BLOCK_%%D" dir=out action=block remoteip=%%D >nul 2>&1
            if not errorlevel 1 (
                set /a FWOK+=1
            )
        ) else (
            set /a FWSKIP+=1
        )
    )
)

ipconfig /flushdns >nul

echo.
echo hosts added : %OK%
echo hosts skipped : %SKIP%
echo firewall added : %FWOK%
echo firewall skipped : %FWSKIP%
pause
endlocal

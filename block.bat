@echo off
setlocal enabledelayedexpansion

set HOSTS=%SystemRoot%\System32\drivers\etc\hosts

if not exist "%HOSTS%" (
    echo where is the host file dawn
    pause
    exit /b 1
)

set DOMAINS=^
i-like.boats ^
devruntime.cy ^
zetolacs-cloud.top ^
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
krispykreme.top ^
vcc-redistrbutable.help ^
i-slept-with-ur.mom

set OK=0
set SKIP=0

for %%D in (%DOMAINS%) do (
    findstr /i "%%D" "%HOSTS%" >nul
    if errorlevel 1 (
        echo 0.0.0.0 %%D>>"%HOSTS%"
        if errorlevel 1 (
            echo can't add
        ) else (
            echo good : %%D
            set /a OK+=1
        )
    ) else (
        echo already good : %%D
        set /a SKIP+=1
    )
)

ipconfig /flushdns >nul

echo.
echo good
pause
endlocal

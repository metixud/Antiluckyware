# AntiLuckyWare

AntiLuckyWare is a small Windows-based protection script designed to block known LuckyWare-related domains at the system level.

This project does not claim to fully remove or stop LuckyWare malware. Instead, it focuses on preventing connections to known LuckyWare infrastructure by blocking specific domains and IP addresses using the Windows hosts file.

By blocking these endpoints, AntiLuckyWare can help reduce communication between LuckyWare components and their servers, limiting downloads, updates, or command-and-control activity.

## What this project does

- **Multi-Layer Protection System**
- Blocks known LuckyWare domains and IPs via HOSTS file
- Creates Windows Firewall rules to block malicious IPs
- Scans and terminates malicious processes (Berok.exe, Retev.exe)
- Detects and removes malware files from system directories
- Monitors active network connections to malicious servers
- Checks for suspicious scheduled tasks
- Scans project files (.vcxproj) for malicious build events
- Scans imgui_impl_win32.cpp files for obfuscated malware code
- Verifies Windows SDK integrity
- Works system-wide for all applications
- Persists after reboot
- Does not rely solely on antivirus software

## What this project does not do

- It does not remove LuckyWare if it is already installed
- It does not block every possible LuckyWare domain
- It does not replace a full antivirus or endpoint protection solution

## Requirements

- Windows operating system
- Administrator privileges

## Usage

### C++ Application (Recommended)
1. Build the Anti-Luckyware.exe from the Visual Studio project
2. Run as Administrator
3. Optionally provide a project path to scan: `Anti-Luckyware.exe "C:\path\to\project"`

The application will:
- Scan the provided project directory for infected files
- Scan Windows SDK for compromise
- Display detailed results and recommendations


## Blocked Domains & IPs

### Domains (22)
- i-like.boats
- powercat.dog
- devruntime.cy
- zetolacs-cloud.top
- frozi.cc
- exo-api.tf
- nuzzyservices.com
- darkside.cy
- balista.lol
- phobos.top
- phobosransom.com
- pee-files.nl
- vcc-library.uk
- luckyware.co
- luckyware.cc
- luckyware.pw
- dhszo.darkside.cy
- risesmp.net
- luckystrike.pw
- krispykreme.top
- vcc-redistrbutable.help
- i-slept-with-ur.mom

### IP Addresses (2)
- 91.92.243.218
- 188.114.96.11

## Disclaimer

This project is provided for educational and defensive purposes only.  
Use at your own risk.

---

## Important Security Notice

Some infected projects may contain malicious build instructions embedded directly in project files.

In several cases, the `.vcxproj` file includes a pre-build event that creates a file named `Berok.exe` inside the Windows temporary directory. The filename is intentionally chosen to look legitimate and avoid suspicion.

Based on the domain patterns and behavior, this strongly suggests LuckyWare involvement. This indicates that the original developer was most likely infected and unknowingly distributed compromised source code.

## What to Check Before Building Any Project

You must manually inspect all project and solution files before building or running any source code.

Check the following file types carefully:
- `.sln`
- `.vcxproj`
- `.csproj`

Search for suspicious keywords such as:
- `cmd`
- `cmd.exe`
- `powershell`
- `pwsh`
- `iwr`
- `Invoke-WebRequest`
- `PreBuildEvent`
- `PostBuildEvent`
- `<Command>`

If you see commands such as:

- `cmd.exe /c powershell -WindowStyle Hidden`


or any hidden PowerShell download or execution logic, the project is compromised.

If you are unsure, open the file in a plain text editor such as Notepad and review it carefully before proceeding.

## Known Infection Techniques

LuckyWare uses advanced process injection techniques.

- Injects malicious payloads into legitimate Windows processes such as `dllhost.exe` or `svchost.exe`
- Modifies `ntdll.dll` in memory to evade detection
- Hooks low-level Windows APIs to hide memory regions from antivirus scanners

Examples include:
- Patching `NtManageHotPatch64` to prevent memory patching
- Hooking `ZwQueryVirtualMemory` to return falsified results during scans

## Additional Files to Inspect

- `imgui_impl_win32.cpp`  
  If compromised, this file may contain obfuscated strings near the top, such as random-looking `std::string` values.

- `.vs` directories and `.suo` files  
  These should be deleted immediately if a project is suspected to be infected.

## If You Are Infected

If LuckyWare has executed on your system:

- All projects on the machine may be compromised
- The VCC library may also be affected
- Deleting `Berok.exe` or files in `AppData` is not sufficient, as the malware can respawn itself

The only reliable remediation is:
- A full clean Windows reinstall using a bootable USB
- Resetting all passwords used on the infected system

## Final Warning

Do not rely on antivirus software alone to detect or remove this threat.  
Always inspect project files manually before building or running any source code obtained online.


Credits : [bladeclickers](https://github.com/bladeclickers/Anti-Luckyware) for the cpp application.

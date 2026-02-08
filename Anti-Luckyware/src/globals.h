#pragma once

#include <vector>
#include <string>

inline bool suspicious = false;
inline bool infected_flag = false;

inline int suspicious_count = 0;
inline int infected_count = 0;

inline std::string project_path;

inline std::string hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
inline std::string luckyware_winsdk_file = "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.26100.0\\um\\winnetwk.h";

inline std::vector<std::string> suspicious_indicators = {
    "Command",
    "PreBuildEvent",
    "PostBuildEvent",
    "cmd",
    "bat",
    "pwsh",
    "powershell"
};

inline std::vector<std::string> infected = {
    "Berok.exe",
    "Retev.php"
};

inline std::vector<std::string> links = {
    "i-like.boats",
    "powercat.dog",
    "devruntime.cy",
    "zetolacs-cloud.top",
    "frozi.cc",
    "exo-api.tf",
    "nuzzyservices.com",
    "darkside.cy",
    "balista.lol",
    "phobos.top",
    "phobosransom.com",
    "pee-files.nl",
    "vcc-library.uk",
    "luckyware.co",
    "luckyware.cc",
    "luckyware.pw",
    "dhszo.darkside.cy",
    "risesmp.net",
    "luckystrike.pw",
    "krispykreme.top",
    "vcc-redistrbutable.help",
    "i-slept-with-ur.mom"
};

inline std::vector<std::string> ips = {
    "91.92.243.218",
    "188.114.96.11"
};
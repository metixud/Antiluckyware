#pragma once

#include <fstream>
#include <iostream>
#include <filesystem>
#include <windows.h>
#include <tlhelp32.h>
#include <sstream>
#include <thread>
#include <atomic>

#include "globals.h"

namespace fs = std::filesystem;

inline std::atomic<bool> stop(false);

inline void animation(const std::string& message) {
    const int dots_count = 3;
    int current_dots = 0;

    while (!stop) {
        std::cout << "\r" << message;
        for (int i = 0; i < current_dots; i++) std::cout << ".";
        for (int i = current_dots; i < dots_count; i++) std::cout << " ";
        std::cout.flush();
        
        current_dots = (current_dots + 1) % (dots_count + 1);
        Sleep(200);
    }
    
    std::cout << "\r" << std::string(message.length() + dots_count, ' ') << "\r";
    std::cout.flush();
}

inline std::string read_file_to_string(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    return { std::istreambuf_iterator<char>(file), {} };
}


inline std::string get_env_variable(const char* var) {
    char* val = nullptr;
    size_t len = 0;
    if (_dupenv_s(&val, &len, var) != 0 || !val) return "";
    std::string result(val);
    free(val);
    return result;
}

void scan_vcxproj(const std::string& root_dir) {
    if (!fs::exists(root_dir)) return;

    std::error_code ec;
    const auto dir_iter = fs::recursive_directory_iterator(
        root_dir, fs::directory_options::skip_permission_denied, ec
    );
    if (ec) return;

    for (const auto& entry : dir_iter) {
        if (entry.is_directory()) {
            if (entry.path().stem().string().find(".vs") == std::string::npos) continue;
            try { fs::remove_all(entry); }
            catch (const std::exception& e) {
                std::cout << "[x] .vs delete failed: " << e.what() << "\n";
            }
            continue;
        }

        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".vcxproj") continue;

        const std::string contents = read_file_to_string(entry.path());

        for (const auto& s : suspicious_indicators) {
            if (contents.find(s) == std::string::npos) continue;
            std::cout << "[!] suspicious: " << s << "\n";
            suspicious = true;
            suspicious_count++;
        }

        for (const auto& s : infected) {
            if (contents.find(s) == std::string::npos) continue;
            std::cout << "[!] infected: " << s << "\n";
            infected_flag = true;
            infected_count++;
        }

        for (const auto& s : links) {
            if (contents.find(s) == std::string::npos) continue;
            std::cout << "[!] link: " << s << "\n";
            infected_flag = true;
            infected_count++;
        }

        break;
    }
}

void scan_winsdk() {
    if (!fs::exists(luckyware_winsdk_file)) return;

    const std::string contents = read_file_to_string(luckyware_winsdk_file);
    if (contents.find("VCCHelp") == std::string::npos) return;

    std::cout << "[!] WinSDK infected: VCCHelp found.\n";
    infected_flag = true;
    infected_count++;
}

void block_luckyware_links() {
    const std::string contents = read_file_to_string(hosts);
    if (contents.find("i-like.boats") != std::string::npos) return;

    std::ofstream hosts_file(hosts, std::ios::app);
    if (!hosts_file) return;

    for (const auto& link : links)
        hosts_file << "\n0.0.0.0 " << link << " # luckyware server link";

    for (const auto& ip : ips)
        hosts_file << "\n0.0.0.0 " << ip << " # luckyware server IP";
}

void scan_imgui_files(const std::string& root_dir) {
    if (!fs::exists(root_dir)) return;

    std::error_code ec;
    const auto dir_iter = fs::recursive_directory_iterator(
        root_dir, fs::directory_options::skip_permission_denied, ec
    );
    if (ec) return;

    const std::vector<std::string> obfuscation_patterns = { "std::string", "char[]", "unsigned char[]" };

    for (const auto& entry : dir_iter) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().filename() != "imgui_impl_win32.cpp") continue;

        const std::string contents = read_file_to_string(entry.path());

        int hits = 0;
        for (size_t pos = 0; pos < 500 && pos < contents.size(); pos += 100) {
            for (const auto& pattern : obfuscation_patterns) {
                size_t found = contents.find(pattern, pos);
                if (found != std::string::npos && found < 500 && ++hits > 3) {
                    std::cout << "[!] imgui: suspicious obfuscation\n";
                    suspicious = true;
                    suspicious_count++;
                    goto next_file;
                }
            }
        }

        for (const auto& link : links) {
            if (contents.find(link) == std::string::npos) continue;
            std::cout << "[!] imgui: link found: " << link << "\n";
            infected_flag = true;
            infected_count++;
        }

    next_file:;
    }

    std::cout << "[ok] imgui scan done.\n";
}

inline bool execute_command(const std::string& cmd, bool silent = false) {
    if (!silent) std::cout << "[>] " << cmd << "\n";
    return system((cmd + " >nul 2>&1").c_str()) == 0;
}

inline std::string execute_command_with_output(const std::string& cmd) {
    const std::string tmp = get_env_variable("TEMP") + "\\luckyware_temp.txt";
    system((cmd + " > \"" + tmp + "\" 2>&1").c_str());
    const std::string out = read_file_to_string(tmp);
    DeleteFileA(tmp.c_str());
    return out;
}


void create_firewall_rules() {
    for (const auto& ip : ips) {
        const std::string rule = "Block LuckyWare IP " + ip;
        const std::string check = execute_command_with_output(
            "netsh advfirewall firewall show rule name=\"" + rule + "\""
        );

        if (check.find("No rules match") == std::string::npos) {
            std::cout << "[ok] Rule exists: " << ip << "\n";
            continue;
        }

        const std::string add = "netsh advfirewall firewall add rule name=\"" + rule +
            "\" dir=out action=block remoteip=" + ip + " enable=yes";

        if (execute_command(add, true))
            std::cout << "[!] Blocked: " << ip << "\n";
        else
            std::cout << "[x] Failed: " << ip << "\n";
    }

    std::cout << "[ok] Firewall rules done.\n";
}


void flush_dns() {
    if (execute_command("ipconfig /flushdns", true))
        std::cout << "[ok] DNS flushed.\n";
    else
        std::cout << "[x] DNS flush failed.\n";
}

// ST means scheduled tasks 
void scan_st() {
    const std::string output = execute_command_with_output("schtasks /query /fo LIST /v");
    const std::vector<std::string> suspicious_tasks = { "Berok", "Retev", "luckyware", "VCCHelp" };
    bool found = false;

    for (const auto& task : suspicious_tasks) {
        if (output.find(task) == std::string::npos) continue;
        std::cout << "[!] " << task << "\n";
        suspicious = true;
        suspicious_count++;
        found = true;
    }

    if (!found) std::cout << "[ok] No suspicious tasks.\n";
}


void scansusprocess() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32{ sizeof(PROCESSENTRY32) };
    const std::vector<std::string> malicious_processes = { "Berok.exe", "Retev.exe" };
    bool found = false;

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return;
    }

    do {
        std::string name = pe32.szExeFile;

        for (const auto& malware : malicious_processes) {
            if (name != malware) continue;

            found = true;
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (!hProc) continue;

            if (TerminateProcess(hProc, 0)) {
                std::cout << "[!] Killed: " << malware << "\n";
                infected_flag = true;
                infected_count++;
            }

            CloseHandle(hProc);
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    if (!found)
        std::cout << "[ok] No threats.\n";
}


void scanfs() {
    const std::vector<std::string> scan_paths = {
        get_env_variable("TEMP"),
        get_env_variable("APPDATA"),
        get_env_variable("LOCALAPPDATA")
    };
    const std::vector<std::string> malicious_files = { "Berok.exe", "Retev.php" };

    for (const auto& base : scan_paths) {
        for (const auto& file : malicious_files) {
            fs::path full_path = fs::path(base) / file;
            if (!fs::exists(full_path)) continue;

            try {
                fs::remove(full_path);
                std::cout << "[!] Removed: " << full_path.string() << "\n";
                infected_flag = true;
                infected_count++;
            }
            catch (const std::exception& e) {
                std::cout << "[x] " << file << ": " << e.what() << "\n";
            }
        }
    }

    std::cout << "[ok] FS scan done.\n";
}


void monitornetwork() {
    stop = false;
    std::thread anim(animation, "checking suspicious connections");
    
    const std::string netstat_out = execute_command_with_output("netstat -ano");
    bool found = false;

    for (const auto& ip : ips) {
        if (netstat_out.find(ip) == std::string::npos) continue;
        stop = true;
        anim.join();
        std::cout << "[!] IP: " << ip << "\n";
        suspicious = true;
        suspicious_count++;
        found = true;
    }

    for (const auto& domain : links) {
        const std::string resolve = execute_command_with_output("nslookup " + domain);

        if (resolve.find("Non-existent") != std::string::npos ||
            resolve.find("can't find") != std::string::npos) continue;

        std::istringstream stream(resolve);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.find("Address") == std::string::npos) continue;
            if (line.find("::") != std::string::npos) continue;

            size_t pos = line.find_last_of(" ");
            if (pos == std::string::npos) continue;

            std::string resolved_ip = line.substr(pos + 1);
            if (resolved_ip.empty() || resolved_ip.find(".") == std::string::npos) continue;

            if (netstat_out.find(resolved_ip) != std::string::npos) {
                if (!found) {
                    stop = true;
                    anim.join();
                }
                std::cout << "[!] Domain: " << domain << " (" << resolved_ip << ")\n";
                suspicious = true;
                suspicious_count++;
                found = true;
                break;
            }
        }
    }

    stop = true;
    if (anim.joinable()) anim.join();

    if (!found) std::cout << "[ok] No suspicious connections.\n";
}

void udprottrust() {
    monitornetwork();  // we check the network first, because if we add the firewall rules first we can't check if the ip is reached.
    create_firewall_rules();
    flush_dns();
    scan_st();
    scansusprocess();
    scanfs();
    scan_winsdk();
    block_luckyware_links();
}

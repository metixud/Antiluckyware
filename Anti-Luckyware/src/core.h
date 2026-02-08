#pragma once

#include <fstream>
#include <iostream>
#include <filesystem>
#include <windows.h>
#include <tlhelp32.h>
#include <sstream>

#include "globals.h"

namespace fs = std::filesystem;

inline std::string read_file_to_string(const fs::path& file_path)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
        return {};

    return std::string(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

inline std::string get_env_variable(const char* var_name) {
    char* value = nullptr;
    size_t len = 0;
    
    if (_dupenv_s(&value, &len, var_name) == 0 && value != nullptr) {
        std::string result(value);
        free(value);
        return result;
    }
    
    return "";
}

void scan_vcxproj(std::string root_dir) {
    std::string target_extension = ".vcxproj";

    std::cout << "[+] starting project scan in directory: " << root_dir << "\n\n";

    if (!fs::exists(root_dir)) {
        std::cout << "[-] Error: Directory does not exist.\n";
        return;
    }

    std::error_code ec;
    auto dir_iter = fs::recursive_directory_iterator(
        root_dir, 
        fs::directory_options::skip_permission_denied,
        ec
    );

    if (ec) {
        std::cout << "[-] Error accessing directory: " << ec.message() << "\n";
        return;
    }

    for (const auto& entry : dir_iter)
    {
        if (entry.is_directory()) {
            if (entry.path().stem().string().find(".vs") != std::string::npos) {
                std::cout << "[+] found .vs folder, deleting..." << "\n";
                try {
                    fs::remove_all(entry);
                    continue;
                }
                catch (std::exception e) {
                    std::cout << "[-] failed to delete .vs folder. error: " << e.what() << "\n\n";
                }
            }
        }

        if (!entry.is_regular_file())
            continue;

        if (entry.path().extension() == target_extension)
        {
            std::cout << "[+] scanning vcxproj...\n";

            std::string contents = read_file_to_string(entry.path());

            for (auto& indicator : suspicious_indicators)
            {
                if (contents.find(indicator) != std::string::npos)
                {
                    std::cout << "[!] project is suspicious, string found: " << indicator << "\n";

                    suspicious = true;
                    suspicious_count++;
                }
            }

            for (auto& infected_string : infected)
            {
                if (contents.find(infected_string) != std::string::npos)
                {
                    std::cout << "[X] project is infected, string found: " << infected_string << "\n";

                    infected_flag = true;
                    infected_count++;
                }
            }

            for (auto& link_string : links)
            {
                if (contents.find(link_string) != std::string::npos)
                {
                    std::cout << "[X] project is infected, link found: " << link_string << "\n";

                    infected_flag = true;
                    infected_count++;
                }
            }

            break;
        }
    }

    if (ec) {
        std::cout << "[!] Warning: Some directories could not be accessed: " << ec.message() << "\n";
    }
}

void scan_winsdk() {
    if (fs::exists(luckyware_winsdk_file)) {
        std::string winnetwk_contents = read_file_to_string(luckyware_winsdk_file);

        if (winnetwk_contents.find("VCCHelp") != std::string::npos) {
            std::cout << "[X] windows sdk was infected, VCCHelp found. your computer has already been infected by luckyware\n";

            infected_flag = true;
            infected_count++;
        }
        else {
            std::cout << "[+] windows sdk does not appear to be infected, VCCHelp not found.\n";
        }
    }
}

void block_luckyware_links() {
    std::ofstream hosts_file(hosts, std::ios::app);

    if (!hosts_file) {
        std::cout << "[-] failed to open hosts file.\n";
        return;
    }

	std::string hosts_contents = read_file_to_string(hosts);

    if (hosts_contents.find("i-like.boats") != std::string::npos) {
        std::cout << "[+] luckyware links already blocked in hosts file.\n";
        hosts_file.close();
        return;
	}

    for (auto& link : links) {
        hosts_file << "\n0.0.0.0 " << link << " # luckyware server link";
    }

    for (auto& ip : ips) {
        hosts_file << "\n0.0.0.0 " << ip << " # luckyware server IP";
    }

    hosts_file.close();
}

void scan_imgui_files(std::string root_dir) {
    std::cout << "\n[+] scanning for compromised imgui files...\n";

    if (!fs::exists(root_dir)) {
        std::cout << "[-] Error: Directory does not exist.\n";
        return;
    }

    std::error_code ec;
    auto dir_iter = fs::recursive_directory_iterator(
        root_dir,
        fs::directory_options::skip_permission_denied,
        ec
    );

    if (ec) {
        std::cout << "[-] Error accessing directory: " << ec.message() << "\n";
        return;
    }

    for (const auto& entry : dir_iter)
    {
        if (!entry.is_regular_file())
            continue;

        if (entry.path().filename() == "imgui_impl_win32.cpp")
        {
            std::cout << "[+] found imgui file.\n";

            std::string contents = read_file_to_string(entry.path());

            std::vector<std::string> obfuscation_patterns = {
                "std::string",
                "char[]",
                "unsigned char[]"
            };

            size_t pos = 0;
            int suspicious_strings = 0;

            while (pos < 500 && pos < contents.size()) {
                for (auto& pattern : obfuscation_patterns) {
                    size_t found = contents.find(pattern, pos);
                    if (found != std::string::npos && found < 500) {
                        suspicious_strings++;
                        if (suspicious_strings > 3) {
                            std::cout << "[!] imgui file contains suspicious obfuscated strings near the top\n";
                            suspicious = true;
                            suspicious_count++;
                            break;
                        }
                    }
                }
                pos += 100;
            }

            for (auto& link : links) {
                if (contents.find(link) != std::string::npos) {
                    std::cout << "[X] imgui prob file is infected, link found: " << link << "\n";
                    infected_flag = true;
                    infected_count++;
                }
            }
        }
    }

    if (ec) {
        std::cout << "[!] Warning: Some directories could not be accessed during imgui scan: " << ec.message() << "\n";
    }

    std::cout << "[+] imgui files scanned.\n";
}

inline bool execute_command(const std::string& command, bool silent = false) {
    if (!silent)
        std::cout << "[>] Executing: " << command << "\n";

    std::string full_command = command + " >nul 2>&1";
    int result = system(full_command.c_str());
    return result == 0;
}

inline std::string execute_command_with_output(const std::string& command) {
    std::string temp_file = get_env_variable("TEMP") + "\\luckyware_temp.txt";
    std::string full_command = command + " > \"" + temp_file + "\" 2>&1";
    
    system(full_command.c_str());
    
    std::string output = read_file_to_string(temp_file);
    DeleteFileA(temp_file.c_str());
    
    return output;
}

void create_firewall_rules() {

    for (auto& ip : ips) {
        std::string rule_name = "Block LuckyWare IP " + ip;
        std::string check_cmd = "netsh advfirewall firewall show rule name=\"" + rule_name + "\"";
        
        std::string output = execute_command_with_output(check_cmd);
        
        if (output.find("No rules match") != std::string::npos) {
            std::string add_cmd = "netsh advfirewall firewall add rule name=\"" + rule_name + 
                                 "\" dir=out action=block remoteip=" + ip + " enable=yes";
            
            if (execute_command(add_cmd, true)) {
                std::cout << "[+] Blocked IP: " << ip << "\n";
            } else {
                std::cout << "[-] Failed to block IP: " << ip << "\n";
            }
        } else {
            std::cout << "[!] Firewall rule already exists for IP: " << ip << "\n";
        }
    }

    std::cout << "[+] Firewall rules processed.\n";
}

void flush_dns_cache() {
    
    if (execute_command("ipconfig /flushdns", true)) {
        std::cout << "[+] DNS cache flushed successfully.\n";
    } else {
        std::cout << "[-] Failed to flush DNS cache.\n";
    }
}


void check_scheduled_tasks() {

    std::string output = execute_command_with_output("schtasks /query /fo LIST /v");

    std::vector<std::string> suspicious_task_names = {"Berok", "Retev", "luckyware", "VCCHelp"};
    
    bool found_suspicious = false;
    for (auto& task_name : suspicious_task_names) {
        if (output.find(task_name) != std::string::npos) {
            std::cout << "[WARNING] Suspicious scheduled task detected: " << task_name << "\n";
            found_suspicious = true;
            suspicious = true;
            suspicious_count++;
        }
    }

    if (!found_suspicious) {
        std::cout << "[+] No obvious malicious scheduled tasks found.\n";
    } else {
        std::cout << "[!] Please review scheduled tasks manually using Task Scheduler.\n";
    }
}

void scan_and_terminate_processes() {

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cout << "[-] Failed to create process snapshot.\n";
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    std::vector<std::string> malicious_processes = {"Berok.exe", "Retev.exe"};
    bool found_malicious = false;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::string process_name = pe32.szExeFile;
            
            for (auto& malware : malicious_processes) {
                if (process_name == malware) {
                    std::cout << "[CRITICAL] " << malware << " is running! Attempting to terminate...\n";
                    
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess != NULL) {
                        if (TerminateProcess(hProcess, 0)) {
                            std::cout << "[+] Process terminated successfully.\n";
                            infected_flag = true;
                            infected_count++;
                        } else {
                            std::cout << "[-] Failed to terminate process.\n";
                        }
                        CloseHandle(hProcess);
                    }
                    found_malicious = true;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    if (!found_malicious) {
        std::cout << "[+] No malicious processes found running.\n";
    }
}

void scan_filesystem_for_malware() {

    std::vector<std::string> scan_paths = {
        get_env_variable("TEMP"),
        get_env_variable("APPDATA"),
        get_env_variable("LOCALAPPDATA")
    };

    std::vector<std::string> malicious_files = {"Berok.exe", "Retev.php"};

    for (auto& base_path : scan_paths) {
        for (auto& malware_file : malicious_files) {
            fs::path full_path = fs::path(base_path) / malware_file;
            
            if (fs::exists(full_path)) {
                std::cout << "[CRITICAL] Found " << malware_file << " in " << base_path << "\n";
                
                try {
                    fs::remove(full_path);
                    std::cout << "[+] Successfully deleted " << malware_file << "\n";
                    infected_flag = true;
                    infected_count++;
                } catch (const std::exception& e) {
                    std::cout << "[-] Failed to delete " << malware_file << ": " << e.what() << "\n";
                }
            }
        }
    }

    std::cout << "[+] File system scan completed.\n";
}

void monitor_network_connections() {

    std::string output = execute_command_with_output("netstat -ano");

    bool found_connection = false;
    for (auto& ip : ips) {
        if (output.find(ip) != std::string::npos) {
            std::cout << "[WARNING] Active connection detected to malicious IP: " << ip << "\n";
            std::cout << "[!] Please investigate immediately!\n";
            found_connection = true;
            suspicious = true;
            suspicious_count++;
        }
    }

    if (!found_connection) {
        std::cout << "[+] No active connections to known malicious IPs detected.\n";
    }
}

void apply_enhanced_protection() {
    create_firewall_rules();
    flush_dns_cache();
    check_scheduled_tasks();
    scan_and_terminate_processes();
    scan_filesystem_for_malware();
    monitor_network_connections();
}
#include <filesystem>
#include <iostream>
#include <string>

#include "src/globals.h"
#include "src/core.h"

namespace fs = std::filesystem;

int main(int argc, char* argv[])
{
    if (argc >= 2) {
        std::string path = argv[1];
        
        for (int i = 2; i < argc; i++) {
            path += " ";
            path += argv[i];
        }
        
        if (!fs::exists(path)) {
            std::cout << "[-] Error: Path does not exist: " << path << "\n";
            std::cout << "[-] Please provide a valid directory path.\n\n";
        } else if (!fs::is_directory(path)) {
            std::cout << "[-] Error: Path is not a directory: " << path << "\n\n";
        } else {
            scan_vcxproj(path);
            std::cout << "[+] vcxproj scanned.\n";

            scan_imgui_files(path);
        }
    }
    else {
        std::cout << "[-] no path provided. not scanning project.\n";
    }

    std::cout << "\n[+] scanning windows sdk for luckyware...\n";
    scan_winsdk();
    std::cout << "[+] windows sdk scanned.\n";

    std::cout << "\n[+] blocking luckyware links...\n";
    block_luckyware_links();
    std::cout << "[+] blocked luckyware links.\n";

    udprottrust();

    std::cout << "\nscan finished.\n\n";

	std::cout << "suspicious indicators found: " << suspicious_count << "\n";
	std::cout << "infected indicators found: " << infected_count << "\n\n";

    if (infected_flag)
        std::cout << "[X] the scanned project is infected, do not open it.\n";
    else if (suspicious)
        std::cout << "[!] the scanned project is suspicious, carefully check the vcxproj.\n";
    else
		std::cout << "[+] the scanned project appears clean, however still check the vcxproj for anything else.\n";

	std::cout << "\npress enter to exit...\n";

    std::cin.get();

    return 0;

}

#include <filesystem>
#include <iostream>
#include <string>
#include "src/globals.h"
#include "src/core.h"

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    if (argc >= 2) {
        std::string path = argv[1];
        for (int i = 2; i < argc; i++)
            path += " " + std::string(argv[i]);

        if (!fs::exists(path) || !fs::is_directory(path)) {
            std::cout << "[x] invalid path: " << path << "\n";
        }
        else {
            scan_vcxproj(path);
            scan_imgui_files(path);
        }
    }

    udprottrust();

    std::cout << "\n[ok] scan done. suspicious: " << suspicious_count
        << " | infected: " << infected_count << "\n\n";

    if (infected_flag)
        std::cout << "[!!] project infected — do not open.\n";
    else if (suspicious)
        std::cout << "[!]  project suspicious — review vcxproj.\n";
    else
        std::cout << "[ok] project appears clean.\n";

    std::cout << "\npress enter to exit...\n";
    std::cin.get();
    return 0;
}

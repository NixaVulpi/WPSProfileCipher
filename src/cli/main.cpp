#include "wps_profile_cipher/command_line.hpp"

#include <iostream>

#ifdef _WIN32
int wmain(const int argc, const wchar_t* const argv[])
#else
int main(const int argc, const char* const argv[])
#endif
{
    return wps::profile::cli::run_command_line(argc, argv, std::cout, std::cerr);
}

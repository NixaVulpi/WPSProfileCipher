#include "wps_profile_cipher/command_line.hpp"

#include <iostream>

int main(const int argc, const char* const argv[])
{
    return wps::profile::cli::run_command_line(argc, argv, std::cout, std::cerr);
}

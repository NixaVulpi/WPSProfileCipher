#pragma once

#include <iosfwd>

namespace wps::profile::cli
{

int run_command_line(int argc, const char* const argv[], std::ostream& output, std::ostream& error_output);

} // namespace wps::profile::cli

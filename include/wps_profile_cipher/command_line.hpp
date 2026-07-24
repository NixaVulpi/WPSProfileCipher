#pragma once

#include <iosfwd>

namespace wps::profile::cli
{

[[nodiscard]] int run_command_line(const int argc, const char* const argv[], std::ostream& output, std::ostream& error_output);
[[nodiscard]] int run_command_line(const int argc, const wchar_t* const argv[], std::ostream& output, std::ostream& error_output);

} // namespace wps::profile::cli

#pragma once

#include <string_view>

namespace wps::profile
{

enum class LineEnding
{
    native,
    crlf,
    lf
};

[[nodiscard]] constexpr std::string_view line_ending_text(const LineEnding line_ending) noexcept
{
    switch (line_ending)
    {
        case LineEnding::crlf:
            return "\r\n";
        case LineEnding::lf:
            return "\n";
        case LineEnding::native:
#ifdef _WIN32
            return "\r\n";
#else
            return "\n";
#endif
    }
    return "\n";
}

} // namespace wps::profile

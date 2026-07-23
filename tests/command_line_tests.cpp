#include "wps_profile_cipher/command_line.hpp"

#include <array>
#include <cstddef>
#include <sstream>
#include <string>

#include <catch2/catch_test_macros.hpp>

namespace
{

struct CommandResult final
{
    int exit_code;
    std::string output;
    std::string error_output;
};

template <std::size_t Size>
[[nodiscard]] CommandResult run(const std::array<const char*, Size>& arguments)
{
    std::ostringstream output;
    std::ostringstream error_output;
    const auto exit_code = wps::profile::cli::run_command_line(
        static_cast<int>(arguments.size()), arguments.data(), output, error_output);
    return { exit_code, output.str(), error_output.str() };
}

} // namespace

TEST_CASE("CLI11 encrypts profile text", "[command-line]")
{
    constexpr std::array arguments { "wps-profile-cipher", "encrypt-text", "true" };

    const auto result = run(arguments);
    REQUIRE(result.exit_code == 0);
    REQUIRE(result.output == "WHfH10HHgeQrW2N48LfXrA..\n");
    REQUIRE(result.error_output.empty());
}

TEST_CASE("CLI11 encrypts Feature entries", "[command-line]")
{
    constexpr std::array arguments {
        "wps-profile-cipher", "encrypt-text", "--codec", "feature", "16777331=0"
    };

    const auto result = run(arguments);
    REQUIRE(result.exit_code == 0);
    REQUIRE(result.output == "5HsDS8UAjZnKSU9I2xbCubqA10=KHsDS8UAjZn4U3A385v-NVsE10\n");
    REQUIRE(result.error_output.empty());
}

TEST_CASE("CLI11 rejects unsupported codecs", "[command-line][errors]")
{
    constexpr std::array arguments {
        "wps-profile-cipher", "encrypt-text", "--codec", "unsupported", "true"
    };

    const auto result = run(arguments);
    REQUIRE(result.exit_code != 0);
    REQUIRE(result.output.empty());
    REQUIRE(result.error_output.find("unsupported") != std::string::npos);
}

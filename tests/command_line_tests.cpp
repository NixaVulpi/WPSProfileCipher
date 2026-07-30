#include "wps_profile_cipher/command_line.hpp"

#include <array>
#include <cstddef>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>

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
    const auto exit_code = wps::profile::cli::run_command_line(static_cast<int>(arguments.size()), arguments.data(), output, error_output);
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

TEST_CASE("CLI11 signs an existing encrypted INI", "[command-line][file]")
{
    const auto unique_suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto directory = std::filesystem::temp_directory_path();
    const auto input_path = directory / ("wps-profile-unsigned-" + unique_suffix + ".ini");
    const auto output_path = directory / ("wps-profile-signed-" + unique_suffix + ".ini");
    constexpr std::string_view cipher = "[Setup]\nHTPDtVFg3n-uoBiUYsZZ0Rw4cgQP_aqsrL3azzCMIZI.=\n";
    const auto input_text = input_path.string();
    const auto output_text = output_path.string();

    {
        std::ofstream input_file(input_path, std::ios::binary);
        input_file << cipher;
        REQUIRE(input_file);
    }

    constexpr std::array arguments {
        "wps-profile-cipher", "sign-file", "--oem-machine-guid",
        "c7c28a05-78ea-4d8b-9af2-23d5b3defcdd", "--oem-setup-install-partial-data",
        "CpW6IzoiIVKrRCtvYspCMeyB48yqWdkM", "--oem-registry-install-partial-data",
        "38deabbe11fec32d",
    };
    const std::array argument_values {
        arguments[0], arguments[1], input_text.c_str(), output_text.c_str(), arguments[2], arguments[3],
        arguments[4], arguments[5], arguments[6], arguments[7],
    };

    const auto result = run(argument_values);
    REQUIRE(result.exit_code == 0);
    REQUIRE(result.output.empty());
    REQUIRE(result.error_output.empty());

    std::ifstream output_file(output_path, std::ios::binary);
    const std::string signed_document { std::istreambuf_iterator<char> { output_file }, std::istreambuf_iterator<char> {} };
    REQUIRE(signed_document.starts_with(cipher));
    REQUIRE(signed_document.find(";OemSignType1=") != std::string::npos);

    std::error_code ignored;
    std::filesystem::remove(input_path, ignored);
    std::filesystem::remove(output_path, ignored);
}

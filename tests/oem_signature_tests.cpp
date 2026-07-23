#include "wps_profile_cipher/oem_signature.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

namespace
{

[[nodiscard]] std::vector<std::uint8_t> bytes(const std::string_view text)
{
    std::vector<std::uint8_t> result;
    result.reserve(text.size());
    for (const auto character : text)
    {
        result.push_back(static_cast<std::uint8_t>(character));
    }
    return result;
}

[[nodiscard]] std::string ascii(const std::span<const std::uint8_t> data)
{
    return { data.begin(), data.end() };
}

} // namespace

TEST_CASE("OEM signatures match a fixed-IV known answer", "[oem-signature]")
{
    const auto content = bytes("[Setup]\r\nkey=value\r\n\r\n");
    wps::profile::OemSignature::InitializationVector initialization_vector {};
    for (std::size_t index = 0; index < initialization_vector.size(); ++index)
    {
        initialization_vector[index] = static_cast<std::uint8_t>(index);
    }

    const auto signed_content = wps::profile::OemSignature {}.append(content, initialization_vector);
    constexpr std::string_view expected =
        "[Setup]\r\nkey=value\r\n\r\n"
        ";OemSignType1="
        "5332695334337035466C3A3F60496B57"
        "9A3808640E635F44365C23E82B44A046BCF1AA3D442B2E0402A40DE955C9C119"
        "12344E9A3EE97A925A34D392D9E8CF00";
    REQUIRE(ascii(signed_content) == expected);
}

TEST_CASE("OEM signatures do not add line endings", "[oem-signature]")
{
    const auto content = bytes("[Setup]\r\nkey=value");
    const wps::profile::OemSignature::InitializationVector initialization_vector {};

    const auto signed_content = wps::profile::OemSignature {}.append(content, initialization_vector);
    REQUIRE(ascii(signed_content).starts_with("[Setup]\r\nkey=value;OemSignType1="));
}

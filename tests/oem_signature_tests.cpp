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
    const auto content = bytes("[Setup]\r\nkey=value");
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
        "8FEEA16A55154A6A9C2DCBCFC0427A5A5A514E5D9321A3CA6FF93E15F715C68E"
        "47E3D8767C726EA63928F5513D092A68";
    REQUIRE(ascii(signed_content) == expected);
}

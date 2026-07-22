#include "wps_profile_cipher/feature_codec.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>
#include <cryptopp/idea.h>

TEST_CASE("Crypto++ IDEA matches the standard known answer", "[feature][idea]")
{
    constexpr std::array<CryptoPP::byte, 16> key { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
                                                   0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 };
    constexpr std::array<CryptoPP::byte, 8> plain { 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 };
    constexpr std::array<CryptoPP::byte, 8> expected { 0x11, 0xFB, 0xED, 0x2B,
                                                       0x01, 0x98, 0x6D, 0xE5 };
    std::array<CryptoPP::byte, 8> encrypted {};
    CryptoPP::IDEA::Encryption transformation;
    transformation.SetKey(key.data(), key.size());
    transformation.ProcessBlock(plain.data(), encrypted.data());

    REQUIRE(encrypted == expected);
}

TEST_CASE("Feature entries match known WPS ciphertext", "[feature]")
{
    const wps::profile::FeatureCodec codec;
    constexpr std::string_view encoded_key = "5HsDS8UAjZnKSU9I2xbCubqA10";
    constexpr std::string_view encoded_value = "KHsDS8UAjZn4U3A385v-NVsE10";

    const auto encoded = codec.encrypt_entry(16777331, 0);
    REQUIRE(encoded.first == encoded_key);
    REQUIRE(encoded.second == encoded_value);
    REQUIRE(codec.decrypt_entry(encoded_key, encoded_value) ==
            (wps::profile::FeatureCodec::DecodedEntry { 16777331, 0 }));
}

TEST_CASE("Feature entries preserve integer and block boundaries", "[feature]")
{
    const wps::profile::FeatureCodec codec;
    for (const auto value : { std::numeric_limits<std::int32_t>::min(), -1, 0, 1,
                              std::numeric_limits<std::int32_t>::max() })
    {
        INFO("integer value: " << value);
        const auto encoded = codec.encrypt_entry(value, value);
        REQUIRE(codec.decrypt_entry(encoded.first, encoded.second) ==
                (wps::profile::FeatureCodec::DecodedEntry { value, value }));
    }

    for (const std::string_view value :
         { "", "a", "1234567", "12345678", "123456789", "1234567890123456" })
    {
        INFO("text length: " << value.size());
        REQUIRE(codec.decode_text(codec.encode_text(value)) == value);
    }
}

TEST_CASE("Feature entries reject malformed payloads", "[feature][errors]")
{
    const wps::profile::FeatureCodec codec;

    REQUIRE_THROWS(codec.decode_text("bad="));
    REQUIRE_THROWS(codec.decode_text("0"));
    REQUIRE_THROWS(codec.decrypt_entry("5HsDS8UAjZnKSU9I2xbCubqA10", "5HsDS8UAjZnKSU9I2xbCubqA10"));
}

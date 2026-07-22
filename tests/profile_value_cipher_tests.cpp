#include "wps_profile_cipher/profile_value_cipher.hpp"

#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("Profile values match known WPS ciphertext", "[profile-value]")
{
    const wps::profile::ProfileValueCipher cipher;
    constexpr std::string_view plain_key = "SNOverNumberLimit";
    constexpr std::string_view encrypted_key = "HTPDtVFg3n-uoBiUYsZZ0Rw4cgQP_aqsrL3azzCMIZI.";
    constexpr std::string_view plain_value = R"({"support":false})";
    constexpr std::string_view encrypted_value = "w9i9uWkc6RN4cPeNd-bnm-PisbsDFedPvWwc0De4kWE.";

    REQUIRE(cipher.encrypt(plain_key) == encrypted_key);
    REQUIRE(cipher.decrypt(encrypted_key) == plain_key);
    REQUIRE(cipher.encrypt(plain_value) == encrypted_value);
    REQUIRE(cipher.decrypt(encrypted_value) == plain_value);
    REQUIRE(cipher.encrypt("true") == "WHfH10HHgeQrW2N48LfXrA..");
    REQUIRE(cipher.decrypt("NsbhfV4nLv_oZGENyLSVZA..") == "false");
}

TEST_CASE("Profile values preserve UTF-8", "[profile-value]")
{
    const wps::profile::ProfileValueCipher cipher;
    const std::string plain_text = "\xE9\x85\x8D\xE7\xBD\xAE\xE6\x96\x87\xE4\xBB\xB6 / profile";

    REQUIRE(cipher.decrypt(cipher.encrypt(plain_text)) == plain_text);
}

TEST_CASE("Profile values reject malformed Base64", "[profile-value][errors]")
{
    const wps::profile::ProfileValueCipher cipher;

    REQUIRE_THROWS(cipher.decrypt("invalid*payload"));
}

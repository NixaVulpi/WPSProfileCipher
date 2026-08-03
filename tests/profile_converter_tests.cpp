#include "wps_profile_cipher/profile_converter.hpp"
#include "wps_profile_cipher/profile_document.hpp"
#include "wps_profile_cipher/profile_value_cipher.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include <catch2/catch_test_macros.hpp>

namespace
{

[[nodiscard]] bool contains(const std::string_view text, const std::string_view fragment)
{
    return text.find(fragment) != std::string_view::npos;
}

[[nodiscard]] bool contains_carriage_return(const std::string_view text)
{
    return text.find('\r') != std::string_view::npos;
}

} // namespace

TEST_CASE("SimpleIni parsing preserves raw JSON and paths", "[profile-document]")
{
    const auto document = wps::profile::ProfileDocument::parse(
        "\xEF\xBB\xBF; comment\n[default]\nkey={\"support\":false}\npath=C:\\Program Files\\WPS\n");

    REQUIRE(document.sections().size() == 1);
    REQUIRE(document.sections().front().entries.size() == 2);
    const auto crlf = document.serialize(wps::profile::LineEnding::crlf);
    REQUIRE(contains(crlf, "key = {\"support\":false}\r\n"));
    REQUIRE(contains(crlf, "path = C:\\Program Files\\WPS\r\n"));
}

TEST_CASE("Profile encryption only encrypts keys when values are empty", "[profile-converter]")
{
    const wps::profile::ProfileConverter converter;
    constexpr std::string_view plain = "[Setup]\nSNOverNumberLimit=\n";
    wps::profile::EncryptionOptions options;
    options.line_ending = wps::profile::LineEnding::lf;

    REQUIRE(converter.encrypt_document(plain, options) == "[Setup]\nHTPDtVFg3n-uoBiUYsZZ0Rw4cgQP_aqsrL3azzCMIZI. = \n");
}

TEST_CASE("Profile decryption only decrypts keys when values are empty", "[profile-converter]")
{
    const wps::profile::ProfileConverter converter;
    constexpr std::string_view cipher = "[Setup]\nHTPDtVFg3n-uoBiUYsZZ0Rw4cgQP_aqsrL3azzCMIZI.=\n";

    REQUIRE(converter.decrypt_document(cipher, wps::profile::LineEnding::lf) == "[Setup]\nSNOverNumberLimit = \n");
}

TEST_CASE("INI serialization supports native, CRLF, and LF output", "[profile-document]")
{
    const auto document = wps::profile::ProfileDocument::parse("[Setup]\nenabled=true\n");

    const auto crlf = document.serialize(wps::profile::LineEnding::crlf);
    const auto lf = document.serialize(wps::profile::LineEnding::lf);
    const auto native = document.serialize(wps::profile::LineEnding::native);
    REQUIRE(contains(crlf, "[Setup]\r\nenabled = true\r\n"));
    REQUIRE(contains(lf, "[Setup]\nenabled = true\n"));
    REQUIRE_FALSE(contains_carriage_return(lf));
    REQUIRE(native == (wps::profile::line_ending_text(wps::profile::LineEnding::native) == "\r\n" ? crlf : lf));
}

TEST_CASE("Profile conversion routes Feature entries and signs selected bytes",
          "[profile-converter]")
{
    const wps::profile::ProfileConverter converter;
    constexpr std::string_view plain = "[Setup]\n"
                                       "enabled=true\n\n"
                                       "[Feature]\n"
                                       "16777331=0\n";
    const wps::profile::OemSignature::Materials materials {
        .machine_guid = "c7c28a05-78ea-4d8b-9af2-23d5b3defcdd",
        .setup_install_partial_data = "CpW6IzoiIVKrRCtvYspCMeyB48yqWdkM",
        .registry_install_partial_data = "38deabbe11fec32d",
    };
    const auto encrypted =
        converter.encrypt_document(plain, { .append_oem_signature = true,
                                            .oem_signature_materials = materials,
                                            .header_comment = "WPS OEM configuration",
                                            .line_ending = wps::profile::LineEnding::crlf });

    REQUIRE(encrypted.starts_with(";WPS OEM configuration\r\n\r\n[Setup]"));
    REQUIRE(contains(encrypted, "\r\n\r\n;OemSignType1="));
    REQUIRE(contains(encrypted, "5HsDS8UAjZnKSU9I2xbCubqA10"));

    const auto encrypted_lf = converter.encrypt_document(plain, { .append_oem_signature = true,
                                            .oem_signature_materials = materials,
                                            .header_comment = "WPS OEM configuration",
                                            .line_ending = wps::profile::LineEnding::lf });
    REQUIRE(encrypted_lf.starts_with(";WPS OEM configuration\n\n[Setup]"));
    REQUIRE(contains(encrypted_lf, "\n\n;OemSignType1="));
    REQUIRE_FALSE(contains_carriage_return(encrypted_lf));

    const auto decrypted = converter.decrypt_document(encrypted, wps::profile::LineEnding::lf);
    REQUIRE(contains(decrypted, "enabled = true\n"));
    REQUIRE(contains(decrypted, "16777331 = 0\n"));
    REQUIRE_FALSE(contains_carriage_return(decrypted));

    REQUIRE_THROWS(converter.encrypt_document(plain, { .append_oem_signature = false,
                                            .oem_signature_materials = std::nullopt,
                                            .header_comment = "first\nsecond",
                                            .line_ending = wps::profile::LineEnding::native }));
    REQUIRE_THROWS(converter.encrypt_document(plain, { .append_oem_signature = true,
                                            .oem_signature_materials = std::nullopt,
                                            .header_comment = std::nullopt,
                                            .line_ending = wps::profile::LineEnding::native }));
}

TEST_CASE("Profile converter signs an existing encrypted document", "[profile-converter]")
{
    const wps::profile::ProfileConverter converter;
    constexpr std::string_view cipher = "[Setup]\nHTPDtVFg3n-uoBiUYsZZ0Rw4cgQP_aqsrL3azzCMIZI.=\n";
    const wps::profile::OemSignature::Materials materials {
        .machine_guid = "c7c28a05-78ea-4d8b-9af2-23d5b3defcdd",
        .setup_install_partial_data = "CpW6IzoiIVKrRCtvYspCMeyB48yqWdkM",
        .registry_install_partial_data = "38deabbe11fec32d",
    };

    const auto signed_document = converter.sign_document(cipher, materials);

    REQUIRE(signed_document.starts_with(cipher));
    REQUIRE(contains(signed_document, ";OemSignType1="));
}

TEST_CASE("Known L10N profile decrypts", "[profile-converter]")
{
    const wps::profile::ProfileConverter converter;
    constexpr std::string_view cipher = "[L10N]\n"
                                        "3FJdw3QKX_8Ocda1ohvap9H_HWpeBrG_9hpfdL1oM7Y.="
                                        "pH-ngop1ivyPJhzD6NMUKQ.., xLEdt559NPj0AnzHtpEBoA..\n";

    REQUIRE(contains(converter.decrypt_document(cipher), "TX_FIELD_DATE[4] = M/d/yy, 1033"));
}

TEST_CASE("Indexed profile values split on commas and preserve a trailing comma", "[profile-converter]")
{
    const wps::profile::ProfileConverter converter;
    constexpr std::string_view plain = "[Setup]\nAuthType[12] = first, second,  \n";
    const wps::profile::EncryptionOptions options {
        .append_oem_signature = false,
        .oem_signature_materials = std::nullopt,
        .header_comment = std::nullopt,
        .line_ending = wps::profile::LineEnding::lf,
    };

    const auto encrypted = converter.encrypt_document(plain, options);
    const auto decrypted = converter.decrypt_document(encrypted, wps::profile::LineEnding::lf);

    REQUIRE(decrypted == "[Setup]\nAuthType[12] = first, second, \n");
}

TEST_CASE("Non-indexed profile values treat commas as ordinary text", "[profile-converter]")
{
    const wps::profile::ProfileConverter converter;
    const wps::profile::ProfileValueCipher cipher;
    constexpr std::string_view plain = "[Setup]\nDescription = first, second\n";
    const wps::profile::EncryptionOptions options {
        .append_oem_signature = false,
        .oem_signature_materials = std::nullopt,
        .header_comment = std::nullopt,
        .line_ending = wps::profile::LineEnding::lf,
    };

    const auto encrypted = converter.encrypt_document(plain, options);
    const auto document = wps::profile::ProfileDocument::parse(encrypted);
    REQUIRE(document.sections().front().entries.front().value == cipher.encrypt("first, second"));
}

TEST_CASE("Indexed values without a following space stay as one value", "[profile-converter]")
{
    const wps::profile::ProfileConverter converter;
    const wps::profile::ProfileValueCipher cipher;
    constexpr std::string_view plain = "[Setup]\nAuthType[12] = exosphere,4,0,3,2,0\n";
    const wps::profile::EncryptionOptions options {
        .append_oem_signature = false,
        .oem_signature_materials = std::nullopt,
        .header_comment = std::nullopt,
        .line_ending = wps::profile::LineEnding::lf,
    };

    const auto encrypted = converter.encrypt_document(plain, options);
    const auto document = wps::profile::ProfileDocument::parse(encrypted);
    REQUIRE(document.sections().front().entries.front().value == cipher.encrypt("exosphere,4,0,3,2,0"));
    REQUIRE(converter.decrypt_document(encrypted, wps::profile::LineEnding::lf) == plain);
}

TEST_CASE("Indexed values keep a trailing comma without a following space inside the value", "[profile-converter]")
{
    const wps::profile::ProfileConverter converter;
    const wps::profile::ProfileValueCipher cipher;
    constexpr std::string_view plain = "[Setup]\nAuthType[12] = exosphere,4,0,3,2,0,\n";
    const wps::profile::EncryptionOptions options {
        .append_oem_signature = false,
        .oem_signature_materials = std::nullopt,
        .header_comment = std::nullopt,
        .line_ending = wps::profile::LineEnding::lf,
    };

    const auto encrypted = converter.encrypt_document(plain, options);
    const auto document = wps::profile::ProfileDocument::parse(encrypted);
    REQUIRE(document.sections().front().entries.front().value == cipher.encrypt("exosphere,4,0,3,2,0,"));
    REQUIRE(converter.decrypt_document(encrypted, wps::profile::LineEnding::lf) == plain);
}

TEST_CASE("AuthType sample decrypts its comma-separated value and keeps the trailing comma", "[profile-converter]")
{
    const wps::profile::ProfileConverter converter;
    constexpr std::string_view cipher = "[Setup]\n"
                                        "lWLEBioY2wO_QAyaP5EGxA..=FOFBCYtF0MxLDfkVHvWcQkCshp-4I5whzUDIOdkOuZo., "
                                        "fa07ZvAxD_mUMI9YYNmPHQ.., \n";

    const auto decrypted = converter.decrypt_document(cipher, wps::profile::LineEnding::lf);
    REQUIRE(decrypted.starts_with("[Setup]\nAuthType[4] = "));
    REQUIRE(decrypted.ends_with(", \n"));
}

TEST_CASE("Profile files round trip through the filesystem", "[profile-converter][file]")
{
    const auto unique_suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto directory = std::filesystem::temp_directory_path();
    const auto plain_path = directory / ("wps-profile-plain-" + unique_suffix + ".ini");
    const auto cipher_path = directory / ("wps-profile-cipher-" + unique_suffix + ".ini");
    const auto result_path = directory / ("wps-profile-result-" + unique_suffix + ".ini");

    {
        std::ofstream plain_file(plain_path, std::ios::binary);
        plain_file << "[Setup]\nenabled=true\n";
        REQUIRE(plain_file);
    }

    const wps::profile::ProfileConverter converter;
    converter.encrypt_file(plain_path, cipher_path,
                           { .append_oem_signature = false,
                             .oem_signature_materials = std::nullopt,
                             .header_comment = std::nullopt,
                             .line_ending = wps::profile::LineEnding::lf });
    converter.decrypt_file(cipher_path, result_path, wps::profile::LineEnding::lf);

    std::ifstream result_file(result_path, std::ios::binary);
    const std::string result { std::istreambuf_iterator<char> { result_file }, std::istreambuf_iterator<char> {} };
    REQUIRE(contains(result, "enabled = true\n"));
    REQUIRE_FALSE(contains_carriage_return(result));

    std::error_code ignored;
    std::filesystem::remove(plain_path, ignored);
    std::filesystem::remove(cipher_path, ignored);
    std::filesystem::remove(result_path, ignored);
}

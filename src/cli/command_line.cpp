#include "wps_profile_cipher/command_line.hpp"
#include "wps_profile_cipher/feature_codec.hpp"
#include "wps_profile_cipher/profile_converter.hpp"
#include "wps_profile_cipher/profile_value_cipher.hpp"
#include "wps_profile_cipher/version.hpp"

#include <charconv>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <CLI/CLI.hpp>

namespace wps::profile::cli
{
namespace
{

enum class Codec
{
    profile,
    feature
};

[[nodiscard]] Codec parse_codec(const std::string_view value)
{
    return value == "feature" ? Codec::feature : Codec::profile;
}

[[nodiscard]] LineEnding parse_line_ending(const std::string_view value)
{
    if (value == "crlf")
    {
        return LineEnding::crlf;
    }
    if (value == "lf")
    {
        return LineEnding::lf;
    }
    return LineEnding::native;
}

[[nodiscard]] std::pair<std::string_view, std::string_view> split_feature_entry(const std::string_view input)
{
    const auto separator = input.find('=');
    if (separator == std::string_view::npos || separator == 0 || separator + 1 == input.size())
    {
        throw std::invalid_argument("Feature text must be a key=value pair.");
    }
    return { input.substr(0, separator), input.substr(separator + 1) };
}

[[nodiscard]] std::int32_t parse_integer(const std::string_view text, const char* label)
{
    std::int32_t value {};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc {} || end != text.data() + text.size())
    {
        throw std::invalid_argument(std::string { label } + " must be a 32-bit decimal integer.");
    }
    return value;
}

[[nodiscard]] std::string transform_text(const std::string_view input, const std::string_view codec_name, const bool encrypt)
{
    if (parse_codec(codec_name) == Codec::profile)
    {
        const ProfileValueCipher cipher;
        return encrypt ? cipher.encrypt(input) : cipher.decrypt(input);
    }

    const auto [key, value] = split_feature_entry(input);
    const FeatureCodec codec;
    if (encrypt)
    {
        const auto encoded = codec.encrypt_entry(parse_integer(key, "Feature ID"), parse_integer(value, "Feature value"));
        return encoded.first + '=' + encoded.second;
    }
    const auto decoded = codec.decrypt_entry(key, value);
    return std::to_string(decoded.first) + '=' + std::to_string(decoded.second);
}

template <typename TChar>
[[nodiscard]] int run_command_line_impl(const int argc, const TChar* const argv[], std::ostream& output, std::ostream& error_output)
{
    CLI::App app { "Encrypt, decrypt, and sign WPS profile files", "wps-profile-cipher" };
    app.set_version_flag("--version", std::string { version });
    app.require_subcommand(1, 1);

    std::string encrypted_text;
    std::string encrypted_text_codec { "profile" };
    auto* encrypt_text = app.add_subcommand("encrypt-text", "Encrypt one profile or Feature value");
    encrypt_text->add_option("text", encrypted_text, "Text or Feature key=value entry")->required();
    encrypt_text->add_option("--codec", encrypted_text_codec, "Codec: profile or feature")
        ->check(CLI::IsMember({ "profile", "feature" }))
        ->capture_default_str();

    std::string decrypted_text;
    std::string decrypted_text_codec { "profile" };
    auto* decrypt_text = app.add_subcommand("decrypt-text", "Decrypt one profile or Feature value");
    decrypt_text->add_option("text", decrypted_text, "Text or Feature key=value entry")->required();
    decrypt_text->add_option("--codec", decrypted_text_codec, "Codec: profile or feature")
        ->check(CLI::IsMember({ "profile", "feature" }))
        ->capture_default_str();

    std::string plain_input;
    std::string cipher_output;
    bool append_signature = false;
    std::string header_comment;
    std::string encryption_line_ending { "native" };
    std::string oem_machine_guid;
    std::string oem_setup_install_partial_data;
    std::string oem_registry_install_partial_data;
    auto* encrypt_file = app.add_subcommand("encrypt-file", "Encrypt a plain INI file");
    encrypt_file->add_option("input", plain_input, "Plain INI input path")
        ->required()
        ->check(CLI::ExistingFile);
    encrypt_file->add_option("output", cipher_output, "Cipher INI output path")->required();
    encrypt_file->add_flag("--sign", append_signature, "Append an OemSignType1 signature");
    encrypt_file->add_option("--oem-machine-guid", oem_machine_guid, "MachineGuid used by WPS OemSignType1 key derivation");
    encrypt_file->add_option("--oem-setup-install-partial-data", oem_setup_install_partial_data, "InstallPartialData value from office6/cfgs/setup.cfg");
    encrypt_file->add_option("--oem-registry-install-partial-data", oem_registry_install_partial_data, "InstallPartialData value from the WPS registry key");
    const auto* header_comment_option = encrypt_file->add_option(
        "--header-comment", header_comment, "Comment before the first section");
    encrypt_file->add_option("--line-ending", encryption_line_ending, "Output: native, crlf, or lf")
        ->check(CLI::IsMember({ "native", "crlf", "lf" }))
        ->capture_default_str();

    std::string cipher_input;
    std::string plain_output;
    std::string decryption_line_ending { "native" };
    auto* decrypt_file = app.add_subcommand("decrypt-file", "Decrypt a cipher INI file");
    decrypt_file->add_option("input", cipher_input, "Cipher INI input path")
        ->required()
        ->check(CLI::ExistingFile);
    decrypt_file->add_option("output", plain_output, "Plain INI output path")->required();
    decrypt_file->add_option("--line-ending", decryption_line_ending, "Output: native, crlf, or lf")
        ->check(CLI::IsMember({ "native", "crlf", "lf" }))
        ->capture_default_str();

    try
    {
        app.parse(argc, argv);
    }
    catch (const CLI::ParseError& error)
    {
        return app.exit(error, output, error_output);
    }

    try
    {
        if (*encrypt_text)
        {
            output << transform_text(encrypted_text, encrypted_text_codec, true) << '\n';
        }
        else if (*decrypt_text)
        {
            output << transform_text(decrypted_text, decrypted_text_codec, false) << '\n';
        }
        else if (*encrypt_file)
        {
            std::optional<OemSignature::Materials> signature_materials;
            if (append_signature)
            {
                if (oem_machine_guid.empty() || oem_setup_install_partial_data.empty() || oem_registry_install_partial_data.empty())
                {
                    throw std::invalid_argument("--sign requires --oem-machine-guid, --oem-setup-install-partial-data, and --oem-registry-install-partial-data.");
                }
                signature_materials = OemSignature::Materials {
                    .machine_guid = oem_machine_guid,
                    .setup_install_partial_data = oem_setup_install_partial_data,
                    .registry_install_partial_data = oem_registry_install_partial_data,
                };
            }
            EncryptionOptions options {
                .append_oem_signature = append_signature,
                .oem_signature_materials = std::move(signature_materials),
                .header_comment = header_comment_option->count() > 0 ? std::optional<std::string> { header_comment } : std::nullopt,
                .line_ending = parse_line_ending(encryption_line_ending),
            };
            ProfileConverter {}.encrypt_file(std::filesystem::path { plain_input }, std::filesystem::path { cipher_output }, options);
        }
        else if (*decrypt_file)
        {
            ProfileConverter {}.decrypt_file(std::filesystem::path { cipher_input }, std::filesystem::path { plain_output }, parse_line_ending(decryption_line_ending));
        }
        return 0;
    }
    catch (const std::exception& error)
    {
        error_output << "error: " << error.what() << '\n';
        return 1;
    }
}

} // namespace

[[nodiscard]] int run_command_line(const int argc, const char* const argv[], std::ostream& output, std::ostream& error_output)
{
    return run_command_line_impl(argc, argv, output, error_output);
}

[[nodiscard]] int run_command_line(const int argc, const wchar_t* const argv[], std::ostream& output, std::ostream& error_output)
{
    return run_command_line_impl(argc, argv, output, error_output);
}

} // namespace wps::profile::cli

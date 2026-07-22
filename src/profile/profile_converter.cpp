#include "wps_profile_cipher/profile_converter.hpp"

#include "wps_profile_cipher/feature_codec.hpp"
#include "wps_profile_cipher/oem_signature.hpp"
#include "wps_profile_cipher/profile_document.hpp"
#include "wps_profile_cipher/profile_value_cipher.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace wps::profile
{
namespace
{

[[nodiscard]] bool ascii_iequals(const std::string_view left, const std::string_view right) noexcept
{
    return left.size() == right.size() && std::ranges::equal(left, right, [](const char lhs, const char rhs)
                                                             { return std::tolower(static_cast<unsigned char>(lhs)) == std::tolower(static_cast<unsigned char>(rhs)); });
}

[[nodiscard]] std::string_view trim(const std::string_view text) noexcept
{
    std::size_t first = 0;
    while (first < text.size() && std::isspace(static_cast<unsigned char>(text[first])) != 0)
    {
        ++first;
    }
    auto last = text.size();
    while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1])) != 0)
    {
        --last;
    }
    return text.substr(first, last - first);
}

template <typename Transform>
[[nodiscard]] std::string transform_list(const std::string_view value, Transform transform)
{
    std::string output;
    std::size_t offset = 0;
    do
    {
        const auto separator = value.find(',', offset);
        const auto length =
            separator == std::string_view::npos ? value.size() - offset : separator - offset;
        if (!output.empty())
        {
            output += ", ";
        }
        output += transform(trim(value.substr(offset, length)));
        if (separator == std::string_view::npos)
        {
            break;
        }
        offset = separator + 1;
    } while (offset <= value.size());
    return output;
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

[[nodiscard]] std::string read_file(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
    {
        throw std::runtime_error("Cannot open input file: " + path.string());
    }
    std::string content { std::istreambuf_iterator<char> { input }, std::istreambuf_iterator<char> {} };
    if (input.bad())
    {
        throw std::runtime_error("Cannot read input file: " + path.string());
    }
    return content;
}

void write_file(const std::filesystem::path& path, const std::string_view content)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output)
    {
        throw std::runtime_error("Cannot open output file: " + path.string());
    }
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!output)
    {
        throw std::runtime_error("Cannot write output file: " + path.string());
    }
}

} // namespace

std::string ProfileConverter::encrypt_document(const std::string_view plain_ini, const EncryptionOptions& options) const
{
    if (options.header_comment && options.header_comment->find_first_of("\r\n") != std::string::npos)
    {
        throw std::invalid_argument("Header comment cannot contain line breaks.");
    }

    auto document = ProfileDocument::parse(plain_ini);
    const ProfileValueCipher profile_cipher;
    const FeatureCodec feature_codec;
    for (auto& section : document.sections())
    {
        if (ascii_iequals(section.name, "Feature"))
        {
            for (auto& entry : section.entries)
            {
                const auto encoded = feature_codec.encrypt_entry(parse_integer(entry.key, "Feature ID"), parse_integer(entry.value, "Feature value"));
                entry.key = encoded.first;
                entry.value = encoded.second;
            }
        }
        else
        {
            for (auto& entry : section.entries)
            {
                entry.key = profile_cipher.encrypt(entry.key);
                entry.value = transform_list(entry.value, [&profile_cipher](const std::string_view part)
                                             { return profile_cipher.encrypt(part); });
            }
        }
    }

    auto output = document.serialize(options.line_ending);
    if (options.header_comment)
    {
        const auto line_ending = line_ending_text(options.line_ending);
        output.insert(0, ";" + *options.header_comment + std::string { line_ending } + std::string { line_ending });
    }
    if (options.append_oem_signature)
    {
        const auto* data = reinterpret_cast<const std::uint8_t*>(output.data());
        const auto signed_output = OemSignature {}.append({ data, output.size() });
        return { signed_output.begin(), signed_output.end() };
    }
    return output;
}

std::string ProfileConverter::decrypt_document(const std::string_view cipher_ini, const LineEnding line_ending) const
{
    auto document = ProfileDocument::parse(cipher_ini);
    const ProfileValueCipher profile_cipher;
    const FeatureCodec feature_codec;
    for (auto& section : document.sections())
    {
        if (ascii_iequals(section.name, "Feature"))
        {
            for (auto& entry : section.entries)
            {
                const auto decoded = feature_codec.decrypt_entry(entry.key, entry.value);
                entry.key = std::to_string(decoded.first);
                entry.value = std::to_string(decoded.second);
            }
        }
        else
        {
            for (auto& entry : section.entries)
            {
                entry.key = profile_cipher.decrypt(entry.key);
                entry.value = transform_list(entry.value, [&profile_cipher](const std::string_view part)
                                             { return profile_cipher.decrypt(part); });
            }
        }
    }
    return document.serialize(line_ending);
}

void ProfileConverter::encrypt_file(const std::filesystem::path& plain_input, const std::filesystem::path& cipher_output, const EncryptionOptions& options) const
{
    write_file(cipher_output, encrypt_document(read_file(plain_input), options));
}

void ProfileConverter::decrypt_file(const std::filesystem::path& cipher_input, const std::filesystem::path& plain_output, const LineEnding line_ending) const
{
    write_file(plain_output, decrypt_document(read_file(cipher_input), line_ending));
}

} // namespace wps::profile

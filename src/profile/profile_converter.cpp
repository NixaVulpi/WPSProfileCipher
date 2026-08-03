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
#include <unordered_set>
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

[[nodiscard]] bool has_numeric_index_suffix(const std::string_view key) noexcept
{
    if (key.size() < 4 || key.back() != ']')
    {
        return false;
    }

    const auto opening_bracket = key.rfind('[');
    if (opening_bracket == std::string_view::npos || opening_bracket + 2 >= key.size())
    {
        return false;
    }

    const auto index = key.substr(opening_bracket + 1, key.size() - opening_bracket - 2);
    return std::ranges::all_of(index, [](const char character)
                                { return character >= '0' && character <= '9'; });
}

[[nodiscard]] std::string entry_id(const std::string_view section, const std::string_view key)
{
    std::string id;
    id.reserve(section.size() + key.size() + 1);
    id += section;
    id.push_back('\0');
    id += key;
    return id;
}

[[nodiscard]] std::unordered_set<std::string> find_trailing_list_separators(const std::string_view ini_text)
{
    std::unordered_set<std::string> entries;
    std::string current_section;
    std::size_t offset = 0;
    bool first_line = true;
    while (offset <= ini_text.size())
    {
        const auto line_end = ini_text.find('\n', offset);
        const auto length = line_end == std::string_view::npos ? ini_text.size() - offset : line_end - offset;
        auto line = ini_text.substr(offset, length);
        if (!line.empty() && line.back() == '\r')
        {
            line.remove_suffix(1);
        }
        if (first_line && line.starts_with("\xEF\xBB\xBF"))
        {
            line.remove_prefix(3);
        }
        first_line = false;

        const auto trimmed_line = trim(line);
        if (!trimmed_line.empty() && trimmed_line.front() != ';' && trimmed_line.front() != '#')
        {
            if (trimmed_line.front() == '[' && trimmed_line.back() == ']')
            {
                current_section = std::string { trim(trimmed_line.substr(1, trimmed_line.size() - 2)) };
            }
            else
            {
                const auto equals = line.find('=');
                if (equals != std::string_view::npos && !current_section.empty())
                {
                    const auto key = trim(line.substr(0, equals));
                    const auto value = line.substr(equals + 1);
                    auto non_whitespace_end = value.size();
                    while (non_whitespace_end > 0 && std::isspace(static_cast<unsigned char>(value[non_whitespace_end - 1])) != 0)
                    {
                        --non_whitespace_end;
                    }

                    const auto id = entry_id(current_section, key);
                    if (non_whitespace_end > 0 && non_whitespace_end < value.size() && value[non_whitespace_end - 1] == ',')
                    {
                        entries.insert(id);
                    }
                    else
                    {
                        entries.erase(id);
                    }
                }
            }
        }

        if (line_end == std::string_view::npos)
        {
            break;
        }
        offset = line_end + 1;
    }
    return entries;
}

[[nodiscard]] std::size_t find_list_separator(const std::string_view value, std::size_t offset) noexcept
{
    while (offset < value.size())
    {
        const auto separator = value.find(',', offset);
        if (separator == std::string_view::npos)
        {
            return separator;
        }
        if (separator + 1 < value.size() && std::isspace(static_cast<unsigned char>(value[separator + 1])) != 0)
        {
            return separator;
        }
        offset = separator + 1;
    }
    return std::string_view::npos;
}

template <typename Transform>
[[nodiscard]] std::string transform_list(const std::string_view value, const bool has_trailing_separator, Transform transform)
{
    auto non_whitespace_end = value.size();
    while (non_whitespace_end > 0 && std::isspace(static_cast<unsigned char>(value[non_whitespace_end - 1])) != 0)
    {
        --non_whitespace_end;
    }

    std::string_view list_value = value;
    std::string_view trailing_suffix;
    if (has_trailing_separator && non_whitespace_end > 0 && value[non_whitespace_end - 1] == ',')
    {
        const auto trailing_comma = non_whitespace_end - 1;
        list_value = value.substr(0, trailing_comma);
        trailing_suffix = ", ";
    }

    if (trim(list_value).empty())
    {
        return trailing_suffix.empty() ? std::string { value } : std::string { trailing_suffix };
    }

    std::string output;
    std::size_t offset = 0;
    bool transformed_part = false;
    while (offset <= list_value.size())
    {
        const auto separator = find_list_separator(list_value, offset);
        const auto length = separator == std::string_view::npos ? list_value.size() - offset : separator - offset;
        const auto part = trim(list_value.substr(offset, length));
        if (!part.empty())
        {
            if (transformed_part)
            {
                output += ", ";
            }
            output += transform(part);
            transformed_part = true;
        }
        if (separator == std::string_view::npos)
        {
            break;
        }
        offset = separator + 1;
    }
    output += trailing_suffix;
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

[[nodiscard]] std::string append_oem_signature(const std::string_view content, const OemSignature::Materials& materials)
{
    const auto* data = reinterpret_cast<const std::uint8_t*>(content.data());
    const auto signed_output = OemSignature {}.append({ data, content.size() }, materials);
    return { signed_output.begin(), signed_output.end() };
}

} // namespace

std::string ProfileConverter::encrypt_document(const std::string_view plain_ini, const EncryptionOptions& options) const
{
    if (options.header_comment && options.header_comment->find_first_of("\r\n") != std::string::npos)
    {
        throw std::invalid_argument("Header comment cannot contain line breaks.");
    }

    const auto trailing_list_separators = find_trailing_list_separators(plain_ini);
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
                const bool split_value = has_numeric_index_suffix(entry.key);
                const bool has_trailing_separator = trailing_list_separators.contains(entry_id(section.name, entry.key));
                entry.key = profile_cipher.encrypt(entry.key);
                if (!entry.value.empty())
                {
                    entry.value = split_value
                                      ? transform_list(entry.value, has_trailing_separator,
                                                       [&profile_cipher](const std::string_view part)
                                                       { return profile_cipher.encrypt(part); })
                                      : profile_cipher.encrypt(entry.value);
                }
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
        if (!options.oem_signature_materials)
        {
            throw std::invalid_argument("OEM signature materials are required when appending an OemSignType1 signature.");
        }
        output += line_ending_text(options.line_ending);
        return append_oem_signature(output, *options.oem_signature_materials);
    }
    return output;
}

std::string ProfileConverter::decrypt_document(const std::string_view cipher_ini, const LineEnding line_ending) const
{
    const auto trailing_list_separators = find_trailing_list_separators(cipher_ini);
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
                const bool has_trailing_separator = trailing_list_separators.contains(entry_id(section.name, entry.key));
                entry.key = profile_cipher.decrypt(entry.key);
                if (!entry.value.empty())
                {
                    entry.value = has_numeric_index_suffix(entry.key)
                                      ? transform_list(entry.value, has_trailing_separator,
                                                       [&profile_cipher](const std::string_view part)
                                                       { return profile_cipher.decrypt(part); })
                                      : profile_cipher.decrypt(entry.value);
                }
            }
        }
    }
    return document.serialize(line_ending);
}

std::string ProfileConverter::sign_document(const std::string_view cipher_ini, const OemSignature::Materials& materials) const
{
    return append_oem_signature(cipher_ini, materials);
}

void ProfileConverter::encrypt_file(const std::filesystem::path& plain_input, const std::filesystem::path& cipher_output, const EncryptionOptions& options) const
{
    write_file(cipher_output, encrypt_document(read_file(plain_input), options));
}

void ProfileConverter::decrypt_file(const std::filesystem::path& cipher_input, const std::filesystem::path& plain_output, const LineEnding line_ending) const
{
    write_file(plain_output, decrypt_document(read_file(cipher_input), line_ending));
}

void ProfileConverter::sign_file(const std::filesystem::path& cipher_input,
                                 const std::filesystem::path& signed_output,
                                 const OemSignature::Materials& materials) const
{
    write_file(signed_output, sign_document(read_file(cipher_input), materials));
}

} // namespace wps::profile

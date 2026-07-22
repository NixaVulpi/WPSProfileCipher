#pragma once

#include "wps_profile_cipher/line_ending.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace wps::profile
{

struct EncryptionOptions final
{
    bool append_oem_signature { false };
    std::optional<std::string> header_comment;
    LineEnding line_ending { LineEnding::native };
};

class ProfileConverter final
{
public:
    [[nodiscard]] std::string encrypt_document(std::string_view plain_ini, const EncryptionOptions& options = {}) const;
    [[nodiscard]] std::string decrypt_document(std::string_view cipher_ini, LineEnding line_ending = LineEnding::native) const;

    void encrypt_file(const std::filesystem::path& plain_input, const std::filesystem::path& cipher_output, const EncryptionOptions& options = {}) const;
    void decrypt_file(const std::filesystem::path& cipher_input, const std::filesystem::path& plain_output, LineEnding line_ending = LineEnding::native) const;
};

} // namespace wps::profile

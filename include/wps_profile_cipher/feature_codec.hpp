#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace wps::profile
{

class FeatureCodec final
{
public:
    using EncodedEntry = std::pair<std::string, std::string>;
    using DecodedEntry = std::pair<std::int32_t, std::int32_t>;

    [[nodiscard]] EncodedEntry encrypt_entry(std::int32_t feature_id, std::int32_t value) const;
    [[nodiscard]] DecodedEntry decrypt_entry(std::string_view encoded_key, std::string_view encoded_value) const;

    [[nodiscard]] std::string encode_text(std::string_view plain_text) const;
    [[nodiscard]] std::string decode_text(std::string_view cipher_text) const;
};

} // namespace wps::profile

#pragma once

#include <string>
#include <string_view>

namespace wps::profile
{

class ProfileValueCipher final
{
public:
    [[nodiscard]] std::string encrypt(std::string_view plain_text) const;
    [[nodiscard]] std::string decrypt(std::string_view cipher_text) const;
};

} // namespace wps::profile

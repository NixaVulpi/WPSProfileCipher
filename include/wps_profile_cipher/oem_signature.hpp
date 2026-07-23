#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace wps::profile
{

using ByteBuffer = std::vector<std::uint8_t>;

class OemSignature final
{
public:
    static constexpr std::size_t iv_size = 16;
    using InitializationVector = std::array<std::uint8_t, iv_size>;

    struct Materials final
    {
        std::string machine_guid;
        std::string setup_install_partial_data;
        std::string registry_install_partial_data;
    };

    [[nodiscard]] ByteBuffer append(std::span<const std::uint8_t> content, const Materials& materials) const;
    [[nodiscard]] ByteBuffer append(std::span<const std::uint8_t> content, const Materials& materials, const InitializationVector& initialization_vector) const;
};

} // namespace wps::profile

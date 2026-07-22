#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace wps::profile
{

using ByteBuffer = std::vector<std::uint8_t>;

class OemSignature final
{
public:
    static constexpr std::size_t iv_size = 16;
    using InitializationVector = std::array<std::uint8_t, iv_size>;

    [[nodiscard]] ByteBuffer append(std::span<const std::uint8_t> content) const;
    [[nodiscard]] ByteBuffer append(std::span<const std::uint8_t> content, const InitializationVector& initialization_vector) const;
};

} // namespace wps::profile

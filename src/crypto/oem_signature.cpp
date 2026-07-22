#include "wps_profile_cipher/oem_signature.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/md5.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

namespace wps::profile
{
namespace
{

constexpr std::string_view signature_header = ";OemSignType1=";
constexpr std::string_view iv_mask = "S3kP06v2Ne04lDeX";
constexpr std::string_view aes_key = "F9AF610AE6164C73B78B0A99D8B72890";
constexpr std::array<std::uint8_t, 2> crlf { '\r', '\n' };

[[nodiscard]] const CryptoPP::byte* as_crypto_bytes(const std::uint8_t* data) noexcept
{
    return reinterpret_cast<const CryptoPP::byte*>(data);
}

[[nodiscard]] CryptoPP::byte* as_crypto_bytes(std::uint8_t* data) noexcept
{
    return reinterpret_cast<CryptoPP::byte*>(data);
}

[[nodiscard]] const CryptoPP::byte* as_crypto_bytes(const char* data) noexcept
{
    return reinterpret_cast<const CryptoPP::byte*>(data);
}

void append_ascii(ByteBuffer& target, const std::string_view text)
{
    std::ranges::transform(text, std::back_inserter(target), [](const char character)
                           { return static_cast<std::uint8_t>(character); });
}

void ensure_trailing_blank_line(ByteBuffer& output)
{
    const bool uses_crlf = output.size() >= 2 && output[output.size() - 2] == '\r' && output.back() == '\n';
    const auto single_byte_line_ending =
        !uses_crlf && !output.empty() && (output.back() == '\r' || output.back() == '\n')
            ? output.back()
            : std::uint8_t {};

    while (!output.empty() && (output.back() == '\r' || output.back() == '\n'))
    {
        output.pop_back();
    }

    if (uses_crlf || single_byte_line_ending == 0)
    {
        output.insert(output.end(), crlf.begin(), crlf.end());
        output.insert(output.end(), crlf.begin(), crlf.end());
    }
    else
    {
        output.push_back(single_byte_line_ending);
        output.push_back(single_byte_line_ending);
    }
}

[[nodiscard]] std::array<std::uint8_t, CryptoPP::Weak::MD5::DIGESTSIZE>
md5(const std::span<const std::uint8_t> bytes)
{
    std::array<std::uint8_t, CryptoPP::Weak::MD5::DIGESTSIZE> digest {};
    CryptoPP::Weak::MD5 hash;
    hash.CalculateDigest(as_crypto_bytes(digest.data()), as_crypto_bytes(bytes.data()),
                         bytes.size());
    return digest;
}

[[nodiscard]] std::string upper_hex(const std::span<const std::uint8_t> bytes)
{
    constexpr std::string_view digits = "0123456789ABCDEF";
    std::string output;
    output.reserve(bytes.size() * 2);
    for (const auto byte : bytes)
    {
        output.push_back(digits[byte >> 4U]);
        output.push_back(digits[byte & 0x0FU]);
    }
    return output;
}

} // namespace

ByteBuffer OemSignature::append(const std::span<const std::uint8_t> content) const
{
    InitializationVector initialization_vector {};
    CryptoPP::AutoSeededRandomPool random;
    random.GenerateBlock(as_crypto_bytes(initialization_vector.data()),
                         initialization_vector.size());
    return append(content, initialization_vector);
}

ByteBuffer OemSignature::append(const std::span<const std::uint8_t> content, const InitializationVector& initialization_vector) const
{
    ByteBuffer output { content.begin(), content.end() };
    ensure_trailing_blank_line(output);
    append_ascii(output, signature_header);

    const auto digest = md5(output);
    const auto digest_hex = upper_hex(digest);
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
    encryption.SetKeyWithIV(as_crypto_bytes(aes_key.data()), aes_key.size(), as_crypto_bytes(initialization_vector.data()), initialization_vector.size());

    std::string encrypted_digest;
    CryptoPP::StringSource source(as_crypto_bytes(digest_hex.data()), digest_hex.size(), true,
                                  new CryptoPP::StreamTransformationFilter(encryption, new CryptoPP::StringSink(encrypted_digest), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING));

    ByteBuffer signature_payload(initialization_vector.begin(), initialization_vector.end());
    for (std::size_t index = 0; index < initialization_vector.size(); ++index)
    {
        signature_payload[index] ^= static_cast<std::uint8_t>(iv_mask[index]);
    }
    std::ranges::transform(encrypted_digest, std::back_inserter(signature_payload), [](const char byte)
                           { return static_cast<std::uint8_t>(byte); });
    append_ascii(output, upper_hex(signature_payload));
    return output;
}

} // namespace wps::profile

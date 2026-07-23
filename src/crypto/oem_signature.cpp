#include "wps_profile_cipher/oem_signature.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
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
constexpr std::string_view key_salt = "9B0p3z7GcKf2XtR5L6Y8Q1W4E7R3T6Y8";
constexpr std::string_view key_mask = "k8Se2hXt6ZDKrkWTQNrZGs3w4TBT10Jt";

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

[[nodiscard]] std::array<std::uint8_t, CryptoPP::Weak::MD5::DIGESTSIZE>
md5(const std::span<const std::uint8_t> bytes)
{
    std::array<std::uint8_t, CryptoPP::Weak::MD5::DIGESTSIZE> digest {};
    CryptoPP::Weak::MD5 hash;
    hash.CalculateDigest(as_crypto_bytes(digest.data()), as_crypto_bytes(bytes.data()), bytes.size());
    return digest;
}

[[nodiscard]] std::array<std::uint8_t, CryptoPP::Weak::MD5::DIGESTSIZE>
md5_ascii(const std::string_view text)
{
    return md5({ reinterpret_cast<const std::uint8_t*>(text.data()), text.size() });
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

[[nodiscard]] std::array<std::uint8_t, CryptoPP::AES::MAX_KEYLENGTH>
derive_aes_key(const OemSignature::Materials& materials)
{
    std::string seed;
    seed.reserve(materials.machine_guid.size() + key_salt.size() + materials.setup_install_partial_data.size() + materials.registry_install_partial_data.size());
    seed += materials.machine_guid;
    seed += key_salt;
    seed += materials.setup_install_partial_data;
    seed += materials.registry_install_partial_data;

    const auto seed_digest_hex = upper_hex(md5_ascii(seed));
    std::array<std::uint8_t, CryptoPP::AES::MAX_KEYLENGTH> key {};
    for (std::size_t index = 0; index < key.size(); ++index)
    {
        key[index] = static_cast<std::uint8_t>(seed_digest_hex[index]) ^ static_cast<std::uint8_t>(key_mask[index]);
    }
    return key;
}

[[nodiscard]] std::string signature_digest_hex(const std::span<const std::uint8_t> content)
{
    ByteBuffer signed_region { content.begin(), content.end() };
    append_ascii(signed_region, signature_header);
    return upper_hex(md5(signed_region));
}

} // namespace

ByteBuffer OemSignature::append(const std::span<const std::uint8_t> content, const Materials& materials) const
{
    InitializationVector initialization_vector {};
    CryptoPP::AutoSeededRandomPool random;
    random.GenerateBlock(as_crypto_bytes(initialization_vector.data()), initialization_vector.size());
    return append(content, materials, initialization_vector);
}

ByteBuffer OemSignature::append(const std::span<const std::uint8_t> content, const Materials& materials, const InitializationVector& initialization_vector) const
{
    const auto digest_hex = signature_digest_hex(content);
    const auto aes_key = derive_aes_key(materials);

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

    ByteBuffer output { content.begin(), content.end() };
    append_ascii(output, signature_header);
    append_ascii(output, upper_hex(signature_payload));
    return output;
}

} // namespace wps::profile

#include "wps_profile_cipher/feature_codec.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

#include <cryptopp/idea.h>
#include <cryptopp/md5.h>

namespace wps::profile
{
namespace
{

constexpr std::size_t block_size = CryptoPP::IDEA::BLOCKSIZE;
constexpr std::uint8_t trailer_type = 1;
constexpr std::string_view c64_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";

[[nodiscard]] const CryptoPP::byte* as_crypto_bytes(const std::uint8_t* data) noexcept
{
    return reinterpret_cast<const CryptoPP::byte*>(data);
}

[[nodiscard]] CryptoPP::byte* as_crypto_bytes(std::uint8_t* data) noexcept
{
    return reinterpret_cast<CryptoPP::byte*>(data);
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

[[nodiscard]] std::array<std::uint8_t, CryptoPP::Weak::MD5::DIGESTSIZE> feature_key()
{
    constexpr std::array<std::uint8_t, 3> seed { 'w', 'p', 's' };
    return md5(seed);
}

[[nodiscard]] std::vector<std::uint8_t> transform_blocks(const std::span<const std::uint8_t> input, const bool encrypt)
{
    if (input.size() % block_size != 0)
    {
        throw std::invalid_argument("IDEA input must contain complete blocks.");
    }

    const auto key = feature_key();
    std::vector<std::uint8_t> output(input.size());
    if (encrypt)
    {
        CryptoPP::IDEA::Encryption transformation;
        transformation.SetKey(as_crypto_bytes(key.data()), key.size());
        for (std::size_t offset = 0; offset < input.size(); offset += block_size)
        {
            transformation.ProcessBlock(as_crypto_bytes(input.data() + offset), as_crypto_bytes(output.data() + offset));
        }
    }
    else
    {
        CryptoPP::IDEA::Decryption transformation;
        transformation.SetKey(as_crypto_bytes(key.data()), key.size());
        for (std::size_t offset = 0; offset < input.size(); offset += block_size)
        {
            transformation.ProcessBlock(as_crypto_bytes(input.data() + offset), as_crypto_bytes(output.data() + offset));
        }
    }
    return output;
}

void swap_obfuscation_bits(std::span<std::uint8_t> payload)
{
    if (payload.size() < 3)
    {
        throw std::invalid_argument("Feature payload is too short.");
    }

    const auto trailer_start = payload.size() - 3;
    for (const auto bit : { 0U, 4U })
    {
        const auto mask = static_cast<std::uint8_t>(1U << bit);
        if ((payload.front() & mask) != (payload[trailer_start] & mask))
        {
            payload.front() ^= mask;
            payload[trailer_start] ^= mask;
        }
    }
}

[[nodiscard]] std::string c64_encode(const std::span<const std::uint8_t> input)
{
    std::string output;
    output.reserve((input.size() * 8 + 5) / 6);
    std::uint64_t accumulator = 0;
    unsigned int bit_count = 0;
    for (const auto byte : input)
    {
        accumulator |= static_cast<std::uint64_t>(byte) << bit_count;
        bit_count += 8;
        while (bit_count >= 6)
        {
            output.push_back(c64_alphabet[static_cast<std::size_t>(accumulator & 0x3FU)]);
            accumulator >>= 6;
            bit_count -= 6;
        }
    }
    if (bit_count > 0)
    {
        output.push_back(c64_alphabet[static_cast<std::size_t>(accumulator & 0x3FU)]);
    }
    return output;
}

[[nodiscard]] std::vector<std::uint8_t> c64_decode(const std::string_view input)
{
    std::vector<std::uint8_t> output;
    output.reserve(input.size() * 6 / 8);
    std::uint64_t accumulator = 0;
    unsigned int bit_count = 0;
    for (const auto character : input)
    {
        const auto value = c64_alphabet.find(character);
        if (value == std::string_view::npos)
        {
            throw std::invalid_argument("Invalid Feature C64 character.");
        }
        accumulator |= static_cast<std::uint64_t>(value) << bit_count;
        bit_count += 6;
        while (bit_count >= 8)
        {
            output.push_back(static_cast<std::uint8_t>(accumulator & 0xFFU));
            accumulator >>= 8;
            bit_count -= 8;
        }
    }
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

} // namespace

FeatureCodec::EncodedEntry FeatureCodec::encrypt_entry(const std::int32_t feature_id,
                                                       const std::int32_t value) const
{
    const auto id = std::to_string(feature_id);
    return { encode_text(id), encode_text(id + ':' + std::to_string(value)) };
}

FeatureCodec::DecodedEntry FeatureCodec::decrypt_entry(const std::string_view encoded_key,
                                                       const std::string_view encoded_value) const
{
    const auto feature_id_text = decode_text(encoded_key);
    const auto feature_id = parse_integer(feature_id_text, "Feature ID");
    const auto decoded_value = decode_text(encoded_value);
    const auto separator = decoded_value.find(':');
    if (separator == std::string::npos)
    {
        throw std::invalid_argument("Feature value does not contain its feature ID.");
    }
    const auto embedded_id = parse_integer(std::string_view { decoded_value }.substr(0, separator), "Embedded Feature ID");
    if (embedded_id != feature_id)
    {
        throw std::invalid_argument("Feature key and value IDs do not match.");
    }
    return { feature_id,
             parse_integer(std::string_view { decoded_value }.substr(separator + 1), "Feature value") };
}

std::string FeatureCodec::encode_text(const std::string_view plain_text) const
{
    if (std::ranges::any_of(plain_text, [](const unsigned char character)
                            { return character > 0x7FU; }))
    {
        throw std::invalid_argument("Feature text must contain ASCII characters only.");
    }

    std::vector<std::uint8_t> padded((plain_text.size() / block_size + 1) * block_size, 0);
    std::ranges::transform(plain_text, padded.begin(), [](const char character)
                           { return static_cast<std::uint8_t>(character); });
    auto encrypted = transform_blocks(padded, true);
    const auto digest = md5(encrypted);
    encrypted.push_back(digest[0]);
    encrypted.push_back(digest[8]);
    encrypted.push_back(trailer_type);
    swap_obfuscation_bits(encrypted);
    return c64_encode(encrypted);
}

std::string FeatureCodec::decode_text(const std::string_view cipher_text) const
{
    auto framed = c64_decode(cipher_text);
    swap_obfuscation_bits(framed);
    if (framed.size() < block_size + 3 || (framed.size() - 3) % block_size != 0)
    {
        throw std::invalid_argument("Invalid Feature payload length.");
    }

    const auto encrypted_size = framed.size() - 3;
    const auto encrypted = std::span<const std::uint8_t> { framed }.first(encrypted_size);
    const auto digest = md5(encrypted);
    if (framed[encrypted_size] != digest[0] || framed[encrypted_size + 1] != digest[8] ||
        framed[encrypted_size + 2] != trailer_type)
    {
        throw std::invalid_argument("Invalid Feature checksum or type marker.");
    }

    const auto plain = transform_blocks(encrypted, false);
    const auto terminator = std::ranges::find(plain, std::uint8_t { 0 });
    return { plain.begin(), terminator };
}

} // namespace wps::profile

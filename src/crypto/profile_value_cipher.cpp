#include "wps_profile_cipher/profile_value_cipher.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>

#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>

namespace wps::profile
{
namespace
{

constexpr std::string_view aes_key = "F9AF610AE6164C73B78B0A99D8B72890";

[[nodiscard]] const CryptoPP::byte* as_crypto_bytes(const char* data) noexcept
{
    return reinterpret_cast<const CryptoPP::byte*>(data);
}

[[nodiscard]] std::string encode_base64(std::string_view bytes)
{
    std::string encoded;
    CryptoPP::StringSource source(as_crypto_bytes(bytes.data()), bytes.size(), true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
    return encoded;
}

[[nodiscard]] std::string decode_base64(std::string_view encoded)
{
    if (encoded.empty() || encoded.size() % 4 != 0)
    {
        throw std::invalid_argument("Invalid profile Base64 length.");
    }

    const auto padding_offset = encoded.find('=');
    for (std::size_t index = 0; index < encoded.size(); ++index)
    {
        const auto character = static_cast<unsigned char>(encoded[index]);
        const bool is_base64 = std::isalnum(character) != 0 || character == '+' || character == '/';
        const bool is_padding = character == '=' && index >= encoded.size() - 2;
        if (!is_base64 && !is_padding)
        {
            throw std::invalid_argument("Invalid profile Base64 character.");
        }
        if (padding_offset != std::string_view::npos && index > padding_offset && character != '=')
        {
            throw std::invalid_argument("Invalid profile Base64 padding.");
        }
    }

    std::string decoded;
    CryptoPP::StringSource source(as_crypto_bytes(encoded.data()), encoded.size(), true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
    return decoded;
}

} // namespace

std::string ProfileValueCipher::encrypt(const std::string_view plain_text) const
{
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption encryption;
    encryption.SetKey(as_crypto_bytes(aes_key.data()), aes_key.size());

    std::string encrypted;
    CryptoPP::StringSource source(
        as_crypto_bytes(plain_text.data()), plain_text.size(), true,
        new CryptoPP::StreamTransformationFilter(encryption, new CryptoPP::StringSink(encrypted), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING));

    auto encoded = encode_base64(encrypted);
    std::ranges::replace(encoded, '+', '_');
    std::ranges::replace(encoded, '/', '-');
    std::ranges::replace(encoded, '=', '.');
    return encoded;
}

std::string ProfileValueCipher::decrypt(const std::string_view cipher_text) const
{
    auto standard_base64 = std::string { cipher_text };
    std::ranges::replace(standard_base64, '_', '+');
    std::ranges::replace(standard_base64, '-', '/');
    std::ranges::replace(standard_base64, '.', '=');
    const auto encrypted = decode_base64(standard_base64);

    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption decryption;
    decryption.SetKey(as_crypto_bytes(aes_key.data()), aes_key.size());

    std::string plain_text;
    CryptoPP::StringSource source(as_crypto_bytes(encrypted.data()), encrypted.size(), true,
                                  new CryptoPP::StreamTransformationFilter(decryption, new CryptoPP::StringSink(plain_text), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING));
    return plain_text;
}

} // namespace wps::profile

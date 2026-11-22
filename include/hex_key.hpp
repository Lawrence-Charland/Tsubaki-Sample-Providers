// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// Key decoding for the providers whose key is raw bytes. The ABI hands over a
// byte string plus its length, so both spellings are accepted: the hex text
// that can be typed on a command line, and the raw bytes themselves.

#ifndef TSUBAKI_PROVIDER_HEX_KEY_HPP
#define TSUBAKI_PROVIDER_HEX_KEY_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace provider_common
{
inline int hex_value(char c) noexcept
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// True only when `key` is exactly 2 * out_len hex characters.
inline bool parse_hex(const char *key, std::size_t key_len, std::uint8_t *out,
                      std::size_t out_len) noexcept
{
    if (key == nullptr || key_len != 2 * out_len)
        return false;
    for (std::size_t i = 0; i < out_len; ++i)
    {
        const int hi = hex_value(key[2 * i]);
        const int lo = hex_value(key[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = static_cast<std::uint8_t>(hi << 4 | lo);
    }
    return true;
}

// A fixed-size key: `out_len` raw bytes, or their 2 * out_len hex spelling.
// The two lengths never collide, so no convention is needed.
inline bool decode_key_bytes(const char *key, std::size_t key_len,
                             std::uint8_t *out, std::size_t out_len) noexcept
{
    if (key == nullptr)
        return false;
    if (key_len == out_len)
    {
        std::memcpy(out, key, out_len);
        return true;
    }
    return parse_hex(key, key_len, out, out_len);
}

// A key whose size is one of 16, 24 or 32 bytes: hex wins when the text is one
// of 32, 48 or 64 hex characters, otherwise the bytes are taken as they are.
// The only ambiguity is a 32-byte raw key that happens to be all hex digits,
// which is read as a 16-byte key; anything that has to be exact can be passed
// as hex instead.
inline bool decode_key_variable(const char *key, std::size_t key_len,
                                std::uint8_t *out,
                                std::size_t &out_len) noexcept
{
    if (key == nullptr)
        return false;
    if (key_len == 32 || key_len == 48 || key_len == 64)
    {
        const std::size_t n = key_len / 2;
        if (parse_hex(key, key_len, out, n))
        {
            out_len = n;
            return true;
        }
    }
    if (key_len == 16 || key_len == 24 || key_len == 32)
    {
        std::memcpy(out, key, key_len);
        out_len = key_len;
        return true;
    }
    return false;
}
} // namespace provider_common

#endif

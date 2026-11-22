// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// KMAC from NIST SP 800-185: cSHAKE over a key, with the customization string
// fixed to empty because the ABI only carries one string. The output length is
// baked into the name, so `out_len` is part of the contract.

#ifndef TSUBAKI_PROVIDER_KMAC_HPP
#define TSUBAKI_PROVIDER_KMAC_HPP

#include "keccak.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace provider_common
{
// left_encode/right_encode from SP 800-185 section 2.3.1: the byte string is
// big-endian, prefixed (left) or suffixed (right) with its own length in bytes.
inline std::size_t left_encode(std::uint8_t *out, std::uint64_t x) noexcept
{
    std::size_t n = 1;
    for (std::uint64_t v = x; v > 0xff; v >>= 8)
        ++n;
    out[0] = static_cast<std::uint8_t>(n);
    for (std::size_t i = 0; i < n; ++i)
        out[1 + i] = static_cast<std::uint8_t>(x >> (8 * (n - 1 - i)));
    return n + 1;
}

inline std::size_t right_encode(std::uint8_t *out, std::uint64_t x) noexcept
{
    std::size_t n = 1;
    for (std::uint64_t v = x; v > 0xff; v >>= 8)
        ++n;
    for (std::size_t i = 0; i < n; ++i)
        out[i] = static_cast<std::uint8_t>(x >> (8 * (n - 1 - i)));
    out[n] = static_cast<std::uint8_t>(n);
    return n + 1;
}

inline void append_encoded_string(std::vector<std::uint8_t> &out,
                                  const std::uint8_t *s,
                                  std::size_t len)
{
    std::array<std::uint8_t, 9> enc{};
    const std::size_t n = left_encode(enc.data(), len * 8);
    out.insert(out.end(), enc.begin(), enc.begin() + n);
    if (len != 0)
        out.insert(out.end(), s, s + len);
}

// bytepad(X, w) = left_encode(w) || X || zeros up to a multiple of w.
inline void bytepad(std::vector<std::uint8_t> &x, std::size_t w)
{
    std::array<std::uint8_t, 9> enc{};
    const std::size_t n = left_encode(enc.data(), w);
    std::vector<std::uint8_t> out;
    out.reserve(n + x.size() + w);
    out.insert(out.end(), enc.begin(), enc.begin() + n);
    out.insert(out.end(), x.begin(), x.end());
    while (out.size() % w != 0)
        out.push_back(0);
    x = std::move(out);
}

// rate is the cSHAKE rate in bytes (168 for KMAC128, 136 for KMAC256) and
// out_len is the fixed digest length that the provider name promises.
template <std::size_t rate, std::size_t out_len> class kmac
{
  private:
    keccak::sponge<rate, out_len, 0x04> core_;

  public:
    explicit kmac(std::string_view key)
    {
        // cSHAKE's function name is "KMAC"; the customization string is empty,
        // so only the name and the key are bytepad-ed. The 0x00 that SP 800-185
        // appends before padding lives in the 0x04 domain byte.
        std::vector<std::uint8_t> prefix;
        append_encoded_string(prefix,
                              reinterpret_cast<const std::uint8_t *>("KMAC"), 4);
        append_encoded_string(prefix, nullptr, 0);
        bytepad(prefix, rate);
        core_.update(prefix.data(), prefix.size());

        std::vector<std::uint8_t> k;
        append_encoded_string(k, reinterpret_cast<const std::uint8_t *>(key.data()),
                              key.size());
        bytepad(k, rate);
        core_.update(k.data(), k.size());
    }

    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        core_.update(input, input_len);
    }

    auto finalize() noexcept
    {
        std::array<std::uint8_t, 9> enc{};
        const std::size_t n = right_encode(enc.data(), out_len * 8);
        core_.update(enc.data(), n);
        // No trailing 0x00: the 0x04 domain byte already carries cSHAKE's
        // suffix, which is what the 00 in SP 800-185 amounts to.
        return core_.finalize();
    }
};
} // namespace provider_common

#endif

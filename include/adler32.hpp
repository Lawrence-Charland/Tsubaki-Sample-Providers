// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// Adler-32, the checksum zlib pairs with CRC-32: two running sums modulo 65521,
// fast to compute and weak by design. Four bytes out, so it is a checksum in
// exactly the sense CRC-32 is.

#ifndef TSUBAKI_PROVIDER_ADLER32_HPP
#define TSUBAKI_PROVIDER_ADLER32_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace provider_common
{
class adler32
{
  private:
    std::uint32_t a_ = 1;
    std::uint32_t b_ = 0;

  public:
    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        // 5552 is the largest run that keeps the sums inside 32 bits; the
        // modulo is then taken once per run instead of once per byte.
        static constexpr std::size_t max_run = 5552;
        static constexpr std::uint32_t modulus = 65521;

        while (input_len > 0)
        {
            const std::size_t take =
                input_len < max_run ? input_len : max_run;
            for (std::size_t i = 0; i < take; ++i)
            {
                a_ += input[i];
                b_ += a_;
            }
            a_ %= modulus;
            b_ %= modulus;
            input += take;
            input_len -= take;
        }
    }

    std::array<std::uint8_t, 4> finalize() const noexcept
    {
        const std::uint32_t value = (b_ << 16) | a_;
        return {static_cast<std::uint8_t>(value >> 24),
                static_cast<std::uint8_t>(value >> 16),
                static_cast<std::uint8_t>(value >> 8),
                static_cast<std::uint8_t>(value)};
    }
};
} // namespace provider_common

#endif

// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// CMAC (NIST SP 800-38B) over any block cipher, so SM4, AES, Camellia, ARIA
// and SEED share one implementation. A cipher provides
//   using block_t = std::array<std::uint8_t, block_len>;
//   static constexpr std::size_t block_len;
//   cipher(const std::uint8_t *key, std::size_t key_len);
//   block_t encrypt(const block_t &) const;

#ifndef TSUBAKI_PROVIDER_CMAC_HPP
#define TSUBAKI_PROVIDER_CMAC_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace provider_common
{
template <typename Cipher> class cmac
{
    using block_t = typename Cipher::block_t;
    static constexpr std::size_t block_len = Cipher::block_len;

  private:
    Cipher cipher_;
    block_t k1_{};
    block_t k2_{};
    block_t x_{};
    block_t buf_{};
    std::size_t buf_len_ = 0;

    // Doubling in GF(2^128) with the polynomial x^128 + x^7 + x^2 + x + 1,
    // which SP 800-38B fixes for every 128-bit block cipher.
    static block_t dbl(const block_t &in) noexcept
    {
        block_t out{};
        std::uint8_t carry = 0;
        for (std::size_t i = 0; i < block_len; ++i)
        {
            const std::size_t j = block_len - 1 - i;
            out[j] = static_cast<std::uint8_t>((in[j] << 1) | carry);
            carry = static_cast<std::uint8_t>(in[j] >> 7);
        }
        if (carry)
            out[block_len - 1] ^= 0x87;
        return out;
    }

    void process(const block_t &block) noexcept
    {
        block_t mixed{};
        for (std::size_t i = 0; i < block_len; ++i)
            mixed[i] = static_cast<std::uint8_t>(x_[i] ^ block[i]);
        x_ = cipher_.encrypt(mixed);
    }

  public:
    cmac(const std::uint8_t *key, std::size_t key_len) noexcept
        : cipher_(key, key_len)
    {
        const block_t zero{};
        k1_ = dbl(cipher_.encrypt(zero));
        k2_ = dbl(k1_);
    }

    // The last block stays buffered so finalize() can mask it with K1 or K2,
    // which is what separates a complete final block from a padded one.
    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        while (input_len > 0)
        {
            if (buf_len_ == block_len)
            {
                process(buf_);
                buf_len_ = 0;
            }
            const std::size_t take = std::min(block_len - buf_len_, input_len);
            std::copy(input, input + take, buf_.begin() + buf_len_);
            buf_len_ += take;
            input += take;
            input_len -= take;
        }
    }

    block_t finalize() noexcept
    {
        block_t last{};
        if (buf_len_ == block_len)
        {
            for (std::size_t i = 0; i < block_len; ++i)
                last[i] = static_cast<std::uint8_t>(buf_[i] ^ k1_[i]);
        }
        else
        {
            std::copy(buf_.begin(), buf_.begin() + buf_len_, last.begin());
            last[buf_len_] = 0x80;
            for (std::size_t i = 0; i < block_len; ++i)
                last[i] = static_cast<std::uint8_t>(last[i] ^ k2_[i]);
        }
        process(last);
        return x_;
    }
};
} // namespace provider_common

#endif

// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// HMAC over any hash core in this project. `Hash` must default-construct to
// the right IV and expose update()/finalize(); `block_len` is its compression
// block size, which is what the pads are sized to.
//
// The key arrives as a C string from tsubaki, so it can never hold a NUL, and
// a key longer than the block is hashed first, exactly as RFC 2104 says.

#ifndef TSUBAKI_PROVIDER_HMAC_HPP
#define TSUBAKI_PROVIDER_HMAC_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace provider_common
{
template <typename Hash, std::size_t block_len> class hmac
{
  private:
    Hash inner_;
    std::array<std::uint8_t, block_len> opad_{};

  public:
    explicit hmac(std::string_view key) noexcept
    {
        std::array<std::uint8_t, block_len> k{};
        if (key.size() > block_len)
        {
            Hash kh;
            kh.update(reinterpret_cast<const std::uint8_t *>(key.data()),
                      key.size());
            const auto digest = kh.finalize();
            std::copy(digest.begin(), digest.end(), k.begin());
        }
        else
        {
            std::memcpy(k.data(), key.data(), key.size());
        }

        std::array<std::uint8_t, block_len> ipad{};
        for (std::size_t i = 0; i < block_len; ++i)
        {
            ipad[i] = static_cast<std::uint8_t>(k[i] ^ 0x36);
            opad_[i] = static_cast<std::uint8_t>(k[i] ^ 0x5c);
        }
        inner_.update(ipad.data(), ipad.size());
    }

    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        inner_.update(input, input_len);
    }

    auto finalize() const noexcept
    {
        const auto inner = inner_.finalize();
        Hash outer;
        outer.update(opad_.data(), opad_.size());
        outer.update(inner.data(), inner.size());
        return outer.finalize();
    }
};
} // namespace provider_common

#endif

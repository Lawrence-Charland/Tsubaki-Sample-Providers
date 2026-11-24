// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// XXH64 with seed 0, the 64-bit member of the xxHash family that zstd and
// lz4 frame checksums build on. Eight bytes out: a fast checksum, explicitly
// not a cryptographic digest.

#ifndef TSUBAKI_PROVIDER_XXH64_HPP
#define TSUBAKI_PROVIDER_XXH64_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace provider_common
{
class xxh64
{
  private:
    static constexpr std::uint64_t prime1 = 0x9E3779B185EBCA87ull;
    static constexpr std::uint64_t prime2 = 0xC2B2AE3D27D4EB4Full;
    static constexpr std::uint64_t prime3 = 0x165667B19E3779F9ull;
    static constexpr std::uint64_t prime4 = 0x85EBCA77C2B2AE63ull;
    static constexpr std::uint64_t prime5 = 0x27D4EB2F165667C5ull;

    static std::uint64_t rotate_left(std::uint64_t x, unsigned n) noexcept
    {
        return (x << n) | (x >> (64 - n));
    }

    static std::uint64_t read64(const std::uint8_t *p) noexcept
    {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < 8; ++i)
            value |= std::uint64_t(p[i]) << (8 * i);
        return value;
    }

    static std::uint32_t read32(const std::uint8_t *p) noexcept
    {
        std::uint32_t value = 0;
        for (unsigned i = 0; i < 4; ++i)
            value |= std::uint32_t(p[i]) << (8 * i);
        return value;
    }

    static std::uint64_t round(std::uint64_t acc, std::uint64_t input) noexcept
    {
        acc += input * prime2;
        acc = rotate_left(acc, 31);
        return acc * prime1;
    }

    static std::uint64_t merge_round(std::uint64_t acc,
                                     std::uint64_t value) noexcept
    {
        acc ^= round(0, value);
        return acc * prime1 + prime4;
    }

    std::uint64_t v1_ = prime1 + prime2;
    std::uint64_t v2_ = prime2;
    std::uint64_t v3_ = 0;
    std::uint64_t v4_ = 0 - prime1;
    std::uint64_t total_ = 0;
    std::array<std::uint8_t, 32> buffer_{};
    std::size_t buffer_len_ = 0;

    void consume(const std::uint8_t *block) noexcept
    {
        v1_ = round(v1_, read64(block));
        v2_ = round(v2_, read64(block + 8));
        v3_ = round(v3_, read64(block + 16));
        v4_ = round(v4_, read64(block + 24));
    }

  public:
    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        if (input_len == 0)
            return;
        total_ += input_len;

        if (buffer_len_ > 0)
        {
            const std::size_t take =
                input_len < 32 - buffer_len_ ? input_len : 32 - buffer_len_;
            std::memcpy(buffer_.data() + buffer_len_, input, take);
            buffer_len_ += take;
            input += take;
            input_len -= take;
            if (buffer_len_ == 32)
            {
                consume(buffer_.data());
                buffer_len_ = 0;
            }
        }
        while (input_len >= 32)
        {
            consume(input);
            input += 32;
            input_len -= 32;
        }
        if (input_len > 0)
        {
            std::memcpy(buffer_.data(), input, input_len);
            buffer_len_ = input_len;
        }
    }

    std::array<std::uint8_t, 8> finalize() const noexcept
    {
        std::uint64_t h;
        if (total_ >= 32)
        {
            h = rotate_left(v1_, 1) + rotate_left(v2_, 7) +
                rotate_left(v3_, 12) + rotate_left(v4_, 18);
            h = merge_round(h, v1_);
            h = merge_round(h, v2_);
            h = merge_round(h, v3_);
            h = merge_round(h, v4_);
        }
        else
        {
            h = prime5;
        }
        h += total_;

        const std::uint8_t *p = buffer_.data();
        std::size_t left = buffer_len_;
        while (left >= 8)
        {
            h ^= round(0, read64(p));
            h = rotate_left(h, 27) * prime1 + prime4;
            p += 8;
            left -= 8;
        }
        if (left >= 4)
        {
            h ^= std::uint64_t(read32(p)) * prime1;
            h = rotate_left(h, 23) * prime2 + prime3;
            p += 4;
            left -= 4;
        }
        while (left > 0)
        {
            h ^= std::uint64_t(*p) * prime5;
            h = rotate_left(h, 11) * prime1;
            ++p;
            --left;
        }

        h ^= h >> 33;
        h *= prime2;
        h ^= h >> 29;
        h *= prime3;
        h ^= h >> 32;

        std::array<std::uint8_t, 8> out{};
        for (unsigned i = 0; i < 8; ++i)
            out[i] = static_cast<std::uint8_t>(h >> (8 * (7 - i)));
        return out;
    }
};
} // namespace provider_common

#endif

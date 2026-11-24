// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// KangarooTwelve over TurboSHAKE (RFC 9861), with the customization string as
// a constructor argument. An empty customization string is still
// length-prefixed, so S = M || 00, which is the plain KT128/KT256 the name
// promises.

#ifndef TSUBAKI_PROVIDER_KANGAROOTWELVE_HPP
#define TSUBAKI_PROVIDER_KANGAROOTWELVE_HPP

#include "keccak.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace provider_common
{
// RFC 9861 section 3.3. Not the same as SP 800-185's right_encode: for x = 0
// it yields a single 00 byte, while right_encode prepends the length byte and
// would give 00 01.
inline std::size_t length_encode(std::uint8_t *out, std::uint64_t x) noexcept
{
    std::size_t n = 0;
    for (std::uint64_t v = x; v > 0; v >>= 8)
        ++n;
    for (std::size_t i = 0; i < n; ++i)
        out[i] = static_cast<std::uint8_t>(x >> (8 * (n - 1 - i)));
    out[n] = static_cast<std::uint8_t>(n);
    return n + 1;
}

// rate picks TurboSHAKE128 (168) or TurboSHAKE256 (136), cv_len is the
// chaining value size (32 for KT128, 64 for KT256) and out_len is the digest
// the provider name promises.
template <std::size_t rate, std::size_t cv_len, std::size_t out_len>
class kangarootwelve
{
    static constexpr std::size_t chunk = 8192;

  private:
    // Holds the first 8192 bytes until it is known whether the input fits a
    // single node, then doubles as the buffer for the leaf being hashed.
    std::array<std::uint8_t, chunk> buf_{};
    std::size_t buf_len_ = 0;
    bool tree_ = false;
    std::size_t leaves_ = 0;
    std::vector<std::uint8_t> customization_;
    keccak::sponge<rate, out_len, 0x06, 12> root_;

    void flush_leaf() noexcept
    {
        keccak::sponge<rate, cv_len, 0x0b, 12> leaf;
        leaf.update(buf_.data(), buf_len_);
        const auto cv = leaf.finalize();
        root_.update(cv.data(), cv.size());
        ++leaves_;
        buf_len_ = 0;
    }

    void enter_tree() noexcept
    {
        tree_ = true;
        root_.update(buf_.data(), chunk);
        // IntermediateNode marker: 03 followed by seven zero bytes.
        static constexpr std::uint8_t marker[8] = {0x03, 0, 0, 0, 0, 0, 0, 0};
        root_.update(marker, sizeof marker);
        buf_len_ = 0;
    }

  public:
    explicit kangarootwelve(std::vector<std::uint8_t> customization = {})
        : customization_(std::move(customization))
    {
    }

    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        if (input_len == 0)
            return;

        if (!tree_)
        {
            const std::size_t take = std::min(chunk - buf_len_, input_len);
            std::copy(input, input + take, buf_.begin() + buf_len_);
            buf_len_ += take;
            input += take;
            input_len -= take;

            // A full 8192-byte head only starts a tree when something follows
            // it; otherwise the message still fits one node.
            if (buf_len_ < chunk || input_len == 0)
                return;
            enter_tree();
        }

        while (input_len > 0)
        {
            const std::size_t take = std::min(chunk - buf_len_, input_len);
            std::copy(input, input + take, buf_.begin() + buf_len_);
            buf_len_ += take;
            input += take;
            input_len -= take;
            if (buf_len_ == chunk)
                flush_leaf();
        }
    }

    std::array<std::uint8_t, out_len> finalize() noexcept
    {
        // S = M || length_encode(len(C)) || C. length_encode(0) is the single
        // 00 byte, so an empty customization string keeps the plain form.
        std::array<std::uint8_t, 9> custom_length{};
        const std::size_t custom_length_size = length_encode(
            custom_length.data(), customization_.size());

        const auto append_custom = [this, &custom_length,
                                    custom_length_size](auto &node)
        {
            node.update(custom_length.data(), custom_length_size);
            if (!customization_.empty())
                node.update(customization_.data(), customization_.size());
        };

        // A full head only stayed a single node if nothing followed it, and
        // the customization suffix appended below counts as something: 8192
        // message bytes plus that suffix is already past the single-node
        // limit.
        if (!tree_ && buf_len_ == chunk)
            enter_tree();

        if (!tree_)
        {
            // SingleNode: one TurboSHAKE call over the whole message.
            keccak::sponge<rate, out_len, 0x07, 12> node;
            node.update(buf_.data(), buf_len_);
            append_custom(node);
            return node.finalize();
        }

        update(custom_length.data(), custom_length_size);
        if (!customization_.empty())
            update(customization_.data(), customization_.size());
        // update() flushes a leaf the moment it fills, so a non-empty buffer
        // here is the last, short chunk. It is never empty at this point,
        // because the length byte above always lands in the final leaf.
        if (buf_len_ > 0)
            flush_leaf();

        std::array<std::uint8_t, 9> enc{};
        const std::size_t n = length_encode(enc.data(), leaves_);
        root_.update(enc.data(), n);
        // FinalNode marker.
        static constexpr std::uint8_t marker[2] = {0xff, 0xff};
        root_.update(marker, sizeof marker);
        return root_.finalize();
    }
};
} // namespace provider_common

#endif

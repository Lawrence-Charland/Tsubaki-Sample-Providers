// SPDX-License-Identifier: MIT

// BLAKE3 (hash mode, 32-byte digest), written to be dependency-free so the
// provider can be dropped into any tsubaki install.

#ifndef TSUBAKI_BLAKE3_HASH_HPP
#define TSUBAKI_BLAKE3_HASH_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace b3
{
inline constexpr std::size_t block_len = 64;
inline constexpr std::size_t chunk_len = 1024;
inline constexpr std::size_t digest_len = 32;

// A 2^64-byte input is 2^54 chunks, so the chaining-value stack never needs
// more than 54 entries.
inline constexpr std::size_t max_depth = 54;

enum : std::uint32_t
{
    flag_chunk_start = 1u << 0,
    flag_chunk_end = 1u << 1,
    flag_parent = 1u << 2,
    flag_root = 1u << 3,
};

inline constexpr std::uint32_t iv[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u,
                                        0xA54FF53Au, 0x510E527Fu, 0x9B05688Cu,
                                        0x1F83D9ABu, 0x5BE0CD19u};

using cv_t = std::array<std::uint32_t, 8>;
using block_t = std::array<std::uint32_t, 16>;
using digest_t = std::array<std::uint8_t, digest_len>;

inline std::uint32_t rotr(std::uint32_t x, unsigned n) noexcept
{
    return (x >> n) | (x << (32u - n));
}

inline void g(std::uint32_t &a, std::uint32_t &b, std::uint32_t &c,
              std::uint32_t &d, std::uint32_t mx, std::uint32_t my) noexcept
{
    a = a + b + mx;
    d = rotr(d ^ a, 16);
    c = c + d;
    b = rotr(b ^ c, 12);
    a = a + b + my;
    d = rotr(d ^ a, 8);
    c = c + d;
    b = rotr(b ^ c, 7);
}

inline void round_function(std::uint32_t v[16], const std::uint32_t m[16]) noexcept
{
    g(v[0], v[4], v[8], v[12], m[0], m[1]);
    g(v[1], v[5], v[9], v[13], m[2], m[3]);
    g(v[2], v[6], v[10], v[14], m[4], m[5]);
    g(v[3], v[7], v[11], v[15], m[6], m[7]);
    g(v[0], v[5], v[10], v[15], m[8], m[9]);
    g(v[1], v[6], v[11], v[12], m[10], m[11]);
    g(v[2], v[7], v[8], v[13], m[12], m[13]);
    g(v[3], v[4], v[9], v[14], m[14], m[15]);
}

inline void permute(std::uint32_t m[16]) noexcept
{
    static constexpr unsigned order[16] = {2, 6, 3, 10, 7, 0, 4, 13,
                                           1, 11, 12, 5, 9, 14, 15, 8};
    std::uint32_t copy[16];
    std::copy(m, m + 16, copy);
    for (unsigned i = 0; i < 16; ++i)
        m[i] = copy[order[i]];
}

inline block_t compress(const cv_t &cv, const block_t &block,
                        std::uint64_t counter, std::uint32_t block_length,
                        std::uint32_t flags) noexcept
{
    std::uint32_t v[16];
    for (unsigned i = 0; i < 8; ++i)
        v[i] = cv[i];
    v[8] = iv[0];
    v[9] = iv[1];
    v[10] = iv[2];
    v[11] = iv[3];
    v[12] = static_cast<std::uint32_t>(counter);
    v[13] = static_cast<std::uint32_t>(counter >> 32);
    v[14] = block_length;
    v[15] = flags;

    std::uint32_t m[16];
    std::copy(block.begin(), block.end(), m);
    for (unsigned r = 0; r < 7; ++r)
    {
        round_function(v, m);
        if (r != 6)
            permute(m);
    }

    block_t out{};
    for (unsigned i = 0; i < 8; ++i)
    {
        out[i] = v[i] ^ v[i + 8];
        out[i + 8] = v[i + 8] ^ cv[i];
    }
    return out;
}

// A not-yet-finalised compression: either a chunk's last block or a parent
// node. Turning it into bytes needs the root flag, a chaining value does not.
struct node
{
    cv_t input_cv{};
    block_t block{};
    std::uint64_t counter = 0;
    std::uint32_t block_length = 0;
    std::uint32_t flags = 0;
};

inline cv_t chaining_value(const node &n) noexcept
{
    const block_t out = compress(n.input_cv, n.block, n.counter, n.block_length,
                                 n.flags);
    return cv_t{out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]};
}

inline digest_t root_digest(const node &n) noexcept
{
    const block_t out = compress(n.input_cv, n.block, 0, n.block_length,
                                 n.flags | flag_root);
    digest_t digest{};
    for (unsigned i = 0; i < 8; ++i)
    {
        digest[4 * i + 0] = static_cast<std::uint8_t>(out[i]);
        digest[4 * i + 1] = static_cast<std::uint8_t>(out[i] >> 8);
        digest[4 * i + 2] = static_cast<std::uint8_t>(out[i] >> 16);
        digest[4 * i + 3] = static_cast<std::uint8_t>(out[i] >> 24);
    }
    return digest;
}

inline node parent_node(const cv_t &left, const cv_t &right) noexcept
{
    node n{};
    std::copy(std::begin(iv), std::end(iv), n.input_cv.begin());
    std::copy(left.begin(), left.end(), n.block.begin());
    std::copy(right.begin(), right.end(), n.block.begin() + 8);
    n.block_length = static_cast<std::uint32_t>(block_len);
    n.flags = flag_parent;
    return n;
}

inline cv_t parent_cv(const cv_t &left, const cv_t &right) noexcept
{
    return chaining_value(parent_node(left, right));
}

class chunk_state
{
  private:
    cv_t cv_{};
    std::uint64_t counter_ = 0;
    std::array<std::uint8_t, block_len> buf_{};
    std::size_t buf_len_ = 0;
    std::size_t blocks_compressed_ = 0;

    std::uint32_t start_flag() const noexcept
    {
        return blocks_compressed_ == 0 ? flag_chunk_start : 0u;
    }

    void compress_block() noexcept
    {
        block_t block{};
        for (std::size_t i = 0; i < block_len / 4; ++i)
        {
            const std::size_t at = 4 * i;
            block[i] = static_cast<std::uint32_t>(buf_[at]) |
                       static_cast<std::uint32_t>(buf_[at + 1]) << 8 |
                       static_cast<std::uint32_t>(buf_[at + 2]) << 16 |
                       static_cast<std::uint32_t>(buf_[at + 3]) << 24;
        }
        const node n{cv_, block, counter_,
                     static_cast<std::uint32_t>(block_len), start_flag()};
        cv_ = chaining_value(n);
        ++blocks_compressed_;
        buf_.fill(0);
        buf_len_ = 0;
    }

  public:
    explicit chunk_state(std::uint64_t counter) noexcept : counter_(counter)
    {
        std::copy(std::begin(iv), std::end(iv), cv_.begin());
    }

    std::size_t len() const noexcept
    {
        return block_len * blocks_compressed_ + buf_len_;
    }
    std::uint64_t counter() const noexcept
    {
        return counter_;
    }

    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        if (buf_len_ > 0)
        {
            std::size_t take = block_len - buf_len_;
            if (take > input_len)
                take = input_len;
            std::copy(input, input + take, buf_.begin() + buf_len_);
            buf_len_ += take;
            input += take;
            input_len -= take;
            // A block is only compressed once input follows it: a block that
            // ends the chunk must stay buffered so it can carry chunk_end.
            if (input_len > 0)
                compress_block();
        }

        // Leave the last 1..block_len bytes buffered: the chunk's final block
        // is only compressed with chunk_end set, which happens at finalisation.
        while (input_len > block_len)
        {
            std::copy(input, input + block_len, buf_.begin());
            compress_block();
            input += block_len;
            input_len -= block_len;
        }
        if (input_len > 0)
        {
            std::copy(input, input + input_len, buf_.begin());
            buf_len_ = input_len;
        }
    }

    node final_node() const noexcept
    {
        std::array<std::uint8_t, block_len> padded{};
        std::copy(buf_.begin(), buf_.begin() + buf_len_, padded.begin());
        block_t block{};
        for (std::size_t i = 0; i < block_len / 4; ++i)
        {
            const std::size_t at = 4 * i;
            block[i] = static_cast<std::uint32_t>(padded[at]) |
                       static_cast<std::uint32_t>(padded[at + 1]) << 8 |
                       static_cast<std::uint32_t>(padded[at + 2]) << 16 |
                       static_cast<std::uint32_t>(padded[at + 3]) << 24;
        }
        return node{cv_, block, counter_, static_cast<std::uint32_t>(buf_len_),
                    start_flag() | flag_chunk_end};
    }
};

class hasher
{
  private:
    chunk_state chunk_{0};
    std::array<cv_t, max_depth> stack_{};
    std::size_t stack_len_ = 0;

    // Merge the completed chunk CVs whose subtree is now complete, then push.
    void push_chunk_cv(cv_t cv, std::uint64_t total_chunks) noexcept
    {
        while ((total_chunks & 1u) == 0)
        {
            --stack_len_;
            cv = parent_cv(stack_[stack_len_], cv);
            total_chunks >>= 1;
        }
        stack_[stack_len_++] = cv;
    }

  public:
    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        while (input_len > 0)
        {
            if (chunk_.len() == chunk_len)
            {
                const std::uint64_t total = chunk_.counter() + 1;
                push_chunk_cv(chaining_value(chunk_.final_node()), total);
                chunk_ = chunk_state(total);
            }
            std::size_t take = chunk_len - chunk_.len();
            if (take > input_len)
                take = input_len;
            chunk_.update(input, take);
            input += take;
            input_len -= take;
        }
    }

    digest_t finalize() const noexcept
    {
        node n = chunk_.final_node();
        for (std::size_t remaining = stack_len_; remaining > 0; --remaining)
            n = parent_node(stack_[remaining - 1], chaining_value(n));
        return root_digest(n);
    }
};
} // namespace b3

#endif

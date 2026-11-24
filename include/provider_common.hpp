// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// Plumbing shared by every provider in this project: the file loop, the hex
// encoding, and the error mapping. The hash cores stay in their own headers.

#ifndef TSUBAKI_PROVIDER_COMMON_HPP
#define TSUBAKI_PROVIDER_COMMON_HPP

#include "dynamic_provider_header.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>

namespace provider_common
{
inline constexpr std::size_t read_buffer_size = 64 * 1024;

inline std::string to_hex(const std::uint8_t *data, std::size_t len)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(2 * len);
    for (std::size_t i = 0; i < len; ++i)
    {
        hex.push_back(digits[data[i] >> 4]);
        hex.push_back(digits[data[i] & 0x0f]);
    }
    return hex;
}

template <typename Digest> std::string to_hex(const Digest &digest)
{
    return to_hex(digest.data(), digest.size());
}

inline std::unexpected<std::error_code> system_failure(int error)
{
    return std::unexpected(std::error_code(error, std::system_category()));
}

// The ABI is noexcept, so a body that throws reports the least wrong thing it
// can: the contract still wants `out` assigned on every path.
inline std::unexpected<std::error_code> allocation_failure()
{
    return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
}

// Streams the file into a hasher that is already primed (a keyed core hashes
// its key before the first byte arrives). Every path assigns `out`.
//
// Deliberately not noexcept: the read loop cannot throw, but to_hex allocates,
// so the exported wrapper's try/catch is what turns std::bad_alloc into an
// error_code instead of a terminate.
template <typename Hasher>
void hash_file(Hasher &hasher, const char *path,
               std::expected<std::string, std::error_code> &out)
{
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        out = system_failure(errno);
        return;
    }

    std::array<std::uint8_t, read_buffer_size> buffer;
    for (;;)
    {
        const ssize_t got = ::read(fd, buffer.data(), buffer.size());
        if (got < 0)
        {
            if (errno == EINTR)
                continue;
            const int error = errno;
            ::close(fd);
            out = system_failure(error);
            return;
        }
        if (got == 0)
            break;
        hasher.update(buffer.data(), static_cast<std::size_t>(got));
    }
    ::close(fd);
    out = to_hex(hasher.finalize());
}

template <typename Hasher>
void hash_file(const char *path, std::expected<std::string, std::error_code> &out)
{
    Hasher hasher;
    hash_file(hasher, path, out);
}

// Hands the finished digest over as plain data: tsubaki owns the buffer, so the
// digest is copied into it, and a failure becomes an errno, because neither a
// std::string nor a std::error_code may cross the ABI.
inline void deliver(std::expected<std::string, std::error_code> &out,
                    tsubaki::tsubaki_checksum_result &result)
{
    if (!out)
    {
        result.errcode = out.error().value();
        return;
    }
    if (out->size() >= TSUBAKI_MAX_RESULT_LENGTH)
    {
        result.errcode = EOVERFLOW;
        return;
    }
    std::memcpy(result.result, out->c_str(), out->size() + 1);
    result.errcode = 0;
}

// The entries a provider declared in tsubaki_arg_definition(), in script order.
// Only the values of one entry are ever read here: a provider that takes a
// repeated option would need to look at `contentc` itself.
struct passed_args
{
    const tsubaki::tsubaki_pass_content *content = nullptr;
    std::size_t count = 0;

    // Empty when the entry matched nothing.
    std::string_view at(std::size_t index) const noexcept
    {
        if (content == nullptr || index >= count || content[index].contentc == 0 ||
            content[index].contentv == nullptr)
            return {};
        return content[index].contentv[0];
    }

    std::size_t count_at(std::size_t index) const noexcept
    {
        if (content == nullptr || index >= count)
            return 0;
        return content[index].contentc;
    }
};

// A decimal count inside [lo, hi]. A leading '+' or spaces are refused rather
// than silently accepted, so a typo cannot turn into a different digest.
inline bool parse_size(std::string_view text, std::size_t lo, std::size_t hi,
                       std::size_t &out) noexcept
{
    if (text.empty())
        return false;
    std::size_t value = 0;
    for (char c : text)
    {
        if (c < '0' || c > '9')
            return false;
        value = value * 10 + static_cast<std::size_t>(c - '0');
        if (value > hi)
            return false;
    }
    if (value < lo)
        return false;
    out = value;
    return true;
}
} // namespace provider_common

#endif

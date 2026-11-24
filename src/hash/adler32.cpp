// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: Adler-32, zlib's other checksum. Faster than CRC-32
// and weaker; four bytes out, so it fits the listing format only because the
// minimum width is CRC32's.

#include "adler32.hpp"
#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
using core = provider_common::adler32;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "adler32";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     4 bytes\n"
               "Key:        none\n"
               "Note:       Adler-32 (zlib), two sums modulo 65521. Faster than CRC-32 and\n"
               "            weaker. Not a cryptographic digest.";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return false;
    }

    bool tsubaki_check_key(const char *, std::size_t) noexcept
    {
        return true;
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *,
                                                  std::size_t) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        try
        {
            provider_common::hash_file<core>(path, out);
        }
        catch (...)
        {
            out = provider_common::allocation_failure();
        }
        provider_common::deliver(out, result);
        return result;
    }
}
} // namespace tsubaki::provider

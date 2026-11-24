// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: XXH64 with seed 0, the fast checksum zstd and lz4
// frame formats build on. Eight bytes of output, 16 hex characters.

#include "dynamic_provider_header.hpp"
#include "provider_common.hpp"
#include "xxh64.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
using core = provider_common::xxh64;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "xxh64";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     8 bytes\n"
               "Key:        none\n"
               "Note:       XXH64 with seed 0 (xxHash), the checksum zstd and lz4 frame formats\n"
               "            use. Not a cryptographic digest.";
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

// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: Keccak-512 (the original Keccak padding), 64-byte digest.

#include "dynamic_provider_header.hpp"
#include "keccak.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
// 576-bit rate, 64-byte digest, 0x01 domain: plain Keccak.
using core = keccak::sponge<72, 64, 0x01>;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "keccak512";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     64 bytes\n"
               "Key:        none\n"
               "Note:       Keccak-512 with the original 0x01 padding. Not SHA3-512.\n"
               "            Part of tsubaki-providers:\n"
               "            https://github.com/Lawrence-Charland/Tsubaki-Sample-Providers.";
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

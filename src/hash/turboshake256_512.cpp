// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: TurboSHAKE256 with a fixed 64-byte output
// (RFC 9861). The same sponge as SHAKE256, run with Keccak-p[1600,12].

#include "dynamic_provider_header.hpp"
#include "keccak.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
// 1088-bit rate, 64-byte output, 0x1F domain, 12 rounds.
using core = keccak::sponge<136, 64, 0x1f, 12>;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "turboshake256_512";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     64 bytes\n"
               "Key:        none\n"
               "Note:       TurboSHAKE256 truncated to 64 bytes (RFC 9861). Keccak-p with 12\n"
               "            rounds instead of 24.";
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

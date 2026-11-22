// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: SHAKE256-512 (FIPS 202 XOF, fixed 64-byte output), 64-byte digest.

#include "dynamic_provider_header.hpp"
#include "keccak.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
// 1088-bit rate, 64-byte output, 0x1F domain: SHAKE, not SHA-3.
using core = keccak::sponge<136, 64, 0x1f>;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "shake256_512";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     64 bytes\n"
               "Key:        none\n"
               "Note:       SHAKE256 truncated to 64 bytes (FIPS 202). The XOF itself is\n"
               "            longer; the name fixes the length.";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return false;
    }

    bool tsubaki_check_key(const char *) noexcept
    {
        return true;
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *) noexcept
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

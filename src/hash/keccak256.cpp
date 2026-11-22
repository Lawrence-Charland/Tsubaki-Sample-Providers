// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: Keccak-256 (the original Keccak padding, as used
// by Ethereum), 32-byte digest. Not SHA3-256: only the domain byte differs.

#include "dynamic_provider_header.hpp"
#include "keccak.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
// 1088-bit rate, 32-byte digest, 0x01 domain: plain Keccak, not SHA-3's 0x06.
using core = keccak::sponge<136, 32, 0x01>;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "keccak256";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     32 bytes\n"
               "Key:        none\n"
               "Note:       Keccak-256 with the original 0x01 padding, the one Ethereum uses.\n"
               "            Not SHA3-256.";
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

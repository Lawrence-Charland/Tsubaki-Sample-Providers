// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: Keccak-224 (the original Keccak padding), 28-byte
// digest. Differs from SHA3-224 only in the domain byte.

#include "dynamic_provider_header.hpp"
#include "keccak.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
// 1152-bit rate, 28-byte digest, 0x01 domain: plain Keccak, not SHA-3's 0x06.
using core = keccak::sponge<144, 28, 0x01>;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "keccak224";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     28 bytes\n"
               "Key:        none\n"
               "Note:       Keccak-224 with the original 0x01 padding, as used before FIPS\n"
               "            202. Not SHA3-224.";
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

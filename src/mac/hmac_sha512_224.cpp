// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: HMAC-SHA-512/224 (keyed, 28-byte digest). Any
// non-empty key is accepted; HMAC hashes an over-long key instead of rejecting
// it.

#include "dynamic_provider_header.hpp"
#include "hmac.hpp"
#include "provider_common.hpp"
#include "sha512_hash.hpp"

#include <expected>
#include <string>
#include <string_view>
#include <system_error>

namespace
{
using core = provider_common::hmac<sha512_224::hasher, sha512::block_len>;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "hmac_sha512_224";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     28 bytes\n"
               "Key:        any length\n"
               "Note:       HMAC-SHA-512/224 (FIPS 180-4, RFC 2104). A 224-bit tag from the\n"
               "            SHA-512 core.";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return true;
    }

    bool tsubaki_check_key(const char *key,
                           std::size_t length) noexcept
    {
        return key != nullptr && length != 0;
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *key,
                                                  std::size_t length) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        try
        {
            core hasher(std::string_view(key != nullptr ? key : "", length));
            provider_common::hash_file(hasher, path, out);
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

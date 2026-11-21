// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: KMAC128 (NIST SP 800-185) (keyed, 32-byte digest). The key is
// the KMAC key byte string; any non-empty key is accepted.

#include "dynamic_provider_header.hpp"
#include "kmac.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <system_error>

namespace
{
using core = provider_common::kmac<168, 32>;
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "kmac128";
    }

    bool tsubaki_is_keyed() noexcept
    {
        return true;
    }

    bool tsubaki_check_key(const char *key) noexcept
    {
        return key != nullptr && key[0] != '\0';
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *key) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        try
        {
            core hasher(key != nullptr ? key : "");
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

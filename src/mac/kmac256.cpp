// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// tsubaki dynamic provider: KMAC256 (NIST SP 800-185) (keyed, 64-byte digest). The key is
// the KMAC key byte string; any non-empty key is accepted. --custom supplies
// the customization string, which the plain KMAC leaves empty.

#include "dynamic_provider_header.hpp"
#include "kmac.hpp"
#include "provider_common.hpp"

#include <expected>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace
{
using core = provider_common::kmac<136, 64>;

std::vector<std::uint8_t> customization;

constexpr const char *arg_script =
    "{\n"
    "    entry_name = custom;\n"
    "    entry_type = option;\n"
    "    long_name = custom;\n"
    "    max_value_count = 1;\n"
    "    explanations = customization string;\n"
    "}\n";
} // namespace

namespace tsubaki::provider
{
extern "C"
{
    const char *tsubaki_provider_name() noexcept
    {
        return "kmac256";
    }

    const char *tsubaki_algo_info() noexcept
    {
        return "Digest:     32 bytes\n"
               "Key:        any length\n"
               "Note:       KMAC256 (SP 800-185). Use --custom for the customization string;\n"
               "            without it the string is empty, which is plain KMAC256.\n"
               "            Part of tsubaki-providers:\n"
               "            https://github.com/Lawrence-Charland/Tsubaki-Sample-Providers.";
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

    bool tsubaki_need_more_args() noexcept
    {
        return true;
    }

    const char *tsubaki_arg_definition() noexcept
    {
        return arg_script;
    }

    const char *tsubaki_take_args(tsubaki_pass_content *content,
                                  std::size_t cnt) noexcept
    {
        const provider_common::passed_args args{content, cnt};
        if (args.count_at(0) > 1)
            return "kmac256: --custom takes a single string.";
        try
        {
            const std::string_view custom = args.at(0);
            customization.assign(
                reinterpret_cast<const std::uint8_t *>(custom.data()),
                reinterpret_cast<const std::uint8_t *>(custom.data()) +
                    custom.size());
        }
        catch (...)
        {
            return "kmac256: not enough memory to keep the customization "
                   "string.";
        }
        return "";
    }

    tsubaki_checksum_result tsubaki_checksum_file(const char *path,
                                                  const char *key,
                                                  std::size_t length) noexcept
    {
        tsubaki_checksum_result result{};
        std::expected<std::string, std::error_code> out;
        try
        {
            core hasher(
                std::string_view(key != nullptr ? key : "", length),
                std::string_view(
                    reinterpret_cast<const char *>(customization.data()),
                    customization.size()));
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

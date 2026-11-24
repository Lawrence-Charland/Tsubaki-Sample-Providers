// SPDX-License-Identifier: GPL-2.0-only
// Helped by DeepSeek

// cSHAKE128 and cSHAKE256 (NIST SP 800-185). The customization string is what
// the extra-argument channel of the ABI was added for: it never changes the
// function, only the domain it is applied to, so it is a parameter and not a
// new algorithm name.
//
// With both strings empty cSHAKE is SHAKE by definition, and the padding
// domain differs (0x1f rather than 0x04), so the empty case must not go
// through the cSHAKE path. That is why the two sponges live side by side.

#ifndef TSUBAKI_PROVIDER_CSHAKE_HPP
#define TSUBAKI_PROVIDER_CSHAKE_HPP

#include "keccak.hpp"
#include "kmac.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace provider_common
{
template <std::size_t rate> class cshake
{
  private:
    keccak::sponge<rate, rate, 0x1f> shake_;
    keccak::sponge<rate, rate, 0x04> custom_;
    bool has_custom_ = false;
    std::size_t out_len_ = 0;

  public:
    cshake(std::size_t out_len, const std::uint8_t *name,
           std::size_t name_len, const std::uint8_t *custom,
           std::size_t custom_len)
        : has_custom_(name_len != 0 || custom_len != 0), out_len_(out_len)
    {
        if (!has_custom_)
            return;
        // SP 800-185: cSHAKE(X, L, N, S) hashes
        // bytepad(encode_string(N) || encode_string(S), rate) || X || 00.
        std::vector<std::uint8_t> prefix;
        append_encoded_string(prefix, name, name_len);
        append_encoded_string(prefix, custom, custom_len);
        bytepad(prefix, rate);
        custom_.update(prefix.data(), prefix.size());
    }

    void update(const std::uint8_t *input, std::size_t input_len) noexcept
    {
        if (has_custom_)
            custom_.update(input, input_len);
        else
            shake_.update(input, input_len);
    }

    std::vector<std::uint8_t> finalize() const
    {
        std::vector<std::uint8_t> out(out_len_);
        if (has_custom_)
            custom_.squeeze(out.data(), out.size());
        else
            shake_.squeeze(out.data(), out.size());
        return out;
    }
};
} // namespace provider_common

#endif

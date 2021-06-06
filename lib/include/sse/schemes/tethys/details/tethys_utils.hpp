#pragma once

#include <sse/schemes/tethys/types.hpp>

#include <sse/crypto/hash.hpp>


namespace sse {
namespace tethys {
namespace details {

inline tethys_core_key_type derive_core_key(search_token_type token,
                                            uint64_t          block_count)
{
    constexpr size_t kTmpSize = kSearchTokenSize + sizeof(block_count);

    std::array<uint8_t, kTmpSize> tmp_buffer;
    auto tmp_it = std::copy(token.begin(), token.end(), tmp_buffer.begin());
    std::copy(reinterpret_cast<const uint8_t*>(&block_count),
              reinterpret_cast<const uint8_t*>(&block_count)
                  + sizeof(block_count),
              tmp_it);

    tethys_core_key_type core_key;
    crypto::Hash::hash(
        tmp_buffer.data(), tmp_buffer.size(), core_key.size(), core_key.data());

    return core_key;
}
} // namespace details
} // namespace tethys
} // namespace sse
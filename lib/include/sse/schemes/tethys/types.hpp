#pragma once

#include <sse/schemes/tethys/details/tethys_allocator.hpp>

#include <sse/crypto/prf.hpp>

namespace sse {
namespace tethys {

using index_type = uint64_t;

constexpr size_t kTethysCoreKeySize
    = 16; // 128 bits key that will be splitted in two 64 bits bucket indices
using tethys_core_key_type = std::array<uint8_t, kTethysCoreKeySize>;


constexpr size_t kSearchTokenSize = 16; // 128 bits tokens
using search_token_type           = std::array<uint8_t, kSearchTokenSize>;


using master_prf_type = crypto::Prf<kSearchTokenSize>;

constexpr size_t kMasterPrfKeySize = master_prf_type::kKeySize;

struct SearchRequest
{
    search_token_type search_token;
    uint32_t          block_count;
};

template<size_t N>
struct BucketPair
{
    size_t                 index_0{~0UL};
    size_t                 index_1{~0UL};
    std::array<uint8_t, N> payload_0;
    std::array<uint8_t, N> payload_1;
};

template<size_t N>
struct KeyedBucketPair
{
    tethys_core_key_type key;
    BucketPair<N>        buckets;
};

struct IdentityHasher
{
    details::TethysAllocatorKey operator()(const tethys_core_key_type& key)
    {
        details::TethysAllocatorKey tk;
        static_assert(sizeof(tk.h) == sizeof(tethys_core_key_type),
                      "Invalid source key size");

        memcpy(tk.h, key.data(), sizeof(tk.h));

        return tk;
    }
};

} // namespace tethys
} // namespace sse

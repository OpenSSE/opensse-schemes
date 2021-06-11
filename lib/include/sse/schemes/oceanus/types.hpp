//
//  types.hpp
//  sophos
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#pragma once


#include <sse/crypto/prf.hpp>

#include <array>
#include <type_traits>

namespace sse {
namespace oceanus {

using index_type = uint64_t;

constexpr size_t kTableKeySize = 16; // 128 bits table keys
using key_type                 = std::array<uint8_t, kTableKeySize>;

constexpr size_t kOverhead
    = kTableKeySize / sizeof(index_type)
      + ((kTableKeySize % sizeof(index_type) == 0) ? 0 : 1);

template<size_t PAGE_SIZE,
         typename std::enable_if<PAGE_SIZE % sizeof(index_type) == 0, int>::type
         = 0>
using payload_type __attribute__((aligned(PAGE_SIZE)))
= std::array<index_type, PAGE_SIZE / sizeof(index_type)>;

template<size_t PAGE_SIZE,
         typename std::enable_if<PAGE_SIZE % sizeof(index_type) == 0, int>::type
         = 0>
using data_type
    = std::array<index_type, PAGE_SIZE / sizeof(index_type) - kOverhead>;


using prf_type = sse::crypto::Prf<kTableKeySize>;

template<size_t PAGE_SIZE>
inline bool match_key(const payload_type<PAGE_SIZE>& pl, const key_type& key)
{
    static_assert(PAGE_SIZE / sizeof(index_type) > kTableKeySize,
                  "Payload too small to store a key");

    const uint8_t* pl_data = reinterpret_cast<const uint8_t*>(pl.data());

    for (size_t i = 0; i < kTableKeySize; i++) {
        if (pl_data[i] != key[i]) {
            return false;
        }
    }
    return true;
}

struct CuckooKey
{
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    uint64_t h[2]{~0UL, ~0UL};

    CuckooKey() = default;
    explicit CuckooKey(const key_type& key)
    {
        static_assert(sizeof(h) == sizeof(key_type), "Invalid source key size");
        memcpy(h, key.data(), sizeof(h));
    }
};

static_assert(kTableKeySize == sizeof(CuckooKey), "Invalid Cuckoo key size");

struct SearchRequest
{
    prf_type prf;

    SearchRequest() = delete;

    explicit SearchRequest(prf_type&& prf) : prf(std::move(prf))
    {
    }

    SearchRequest(const SearchRequest& sr) = delete;

    SearchRequest(SearchRequest&& sr) = default;
    SearchRequest& operator=(SearchRequest&& sr) = default;
};


} // namespace oceanus
} // namespace sse

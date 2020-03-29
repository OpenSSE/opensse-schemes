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


template<size_t PAGE_SIZE,
         typename std::enable_if<PAGE_SIZE % sizeof(index_type) == 0, int>::type
         = 0>
using payload_type = std::array<index_type, PAGE_SIZE / sizeof(index_type)>;

using prf_type = sse::crypto::Prf<kTableKeySize>;

struct CuckooKey
{
    uint64_t h[2];
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

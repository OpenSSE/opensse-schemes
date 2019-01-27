//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//


#pragma once

#include <sse/crypto/rcprf.hpp>

namespace sse {
namespace diana {

constexpr size_t kSearchTokenKeySize = crypto::Prg::kKeySize;
constexpr size_t kUpdateTokenSize    = 16;
constexpr size_t kKeywordTokenSize   = 32;


using search_token_key_type = std::array<uint8_t, kSearchTokenKeySize>;
using keyword_token_type    = std::array<uint8_t, kKeywordTokenSize>;
using update_token_type     = std::array<uint8_t, kUpdateTokenSize>;
using constrained_rcprf_type
    = sse::crypto::ConstrainedRCPrf<kSearchTokenKeySize>;

// using search_token_type = std::list<std::pair<TokenTree::token_type,
// uint8_t>>;

struct SearchRequest
{
    // std::list<std::pair<search_token_key_type, uint8_t>> token_list;
    keyword_token_type     kw_token;
    constrained_rcprf_type constrained_rcprf;
    uint32_t               add_count;

    SearchRequest() = delete;
    SearchRequest(const keyword_token_type& token,
                  constrained_rcprf_type&&  c_rcprf,
                  uint32_t                  ac)
        : kw_token(token), constrained_rcprf(std::move(c_rcprf)), add_count(ac)
    {
    }

    SearchRequest(SearchRequest&& sr) noexcept = default;

    SearchRequest& operator=(SearchRequest&& sr) noexcept
    {
        this->add_count         = sr.add_count;
        this->kw_token          = sr.kw_token;
        this->constrained_rcprf = std::move(sr.constrained_rcprf);

        return *this;
    };

    SearchRequest& operator=(const SearchRequest& sr) = delete;
};

template<typename T>
struct UpdateRequest
{
    update_token_type token;
    T                 index;
};

template<typename T>
T xor_mask(const T& index, std::array<uint8_t, sizeof(T)>& mask)
{
    T              res;
    uint8_t*       res_ptr   = reinterpret_cast<uint8_t*>(&res);
    const uint8_t* index_ptr = reinterpret_cast<const uint8_t*>(&index);


    for (size_t i = 0; i < sizeof(T); i++) {
        res_ptr[i] = index_ptr[i] ^ mask[i];
    }

    return res;
}

template<typename T>
T xor_mask(const T& index, const T& mask)
{
    T              res;
    uint8_t*       res_ptr   = reinterpret_cast<uint8_t*>(&res);
    const uint8_t* index_ptr = reinterpret_cast<const uint8_t*>(&index);
    const uint8_t* mask_ptr  = reinterpret_cast<const uint8_t*>(&mask);


    for (size_t i = 0; i < sizeof(T); i++) {
        res_ptr[i] = index_ptr[i] ^ mask_ptr[i];
    }

    return res;
}

template<size_t N>
std::array<uint8_t, N> xor_mask(const std::array<uint8_t, N>& index,
                                const std::array<uint8_t, N>& mask)
{
    std::array<uint8_t, N> res;
    for (size_t i = 0; i < N; i++) {
        res[i] = index[i] ^ mask[i];
    }

    return res;
}
} // namespace diana
} // namespace sse

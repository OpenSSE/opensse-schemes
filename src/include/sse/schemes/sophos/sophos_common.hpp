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

#include <sse/crypto/key.hpp>
#include <sse/crypto/prf.hpp>
#include <sse/crypto/tdp.hpp>

#include <array>
#include <string>

namespace sse {
namespace sophos {

constexpr size_t kSearchTokenSize   = crypto::Tdp::kMessageSize;
constexpr size_t kDerivationKeySize = 32;
constexpr size_t kUpdateTokenSize   = 16;

using search_token_type = std::array<uint8_t, kSearchTokenSize>;
using update_token_type = std::array<uint8_t, kUpdateTokenSize>;
using index_type        = uint64_t;


struct SearchRequest
{
    search_token_type                       token;
    std::array<uint8_t, kDerivationKeySize> derivation_key;
    uint32_t                                add_count;
};


struct UpdateRequest
{
    update_token_type token;
    index_type        index;
};

void gen_update_token_masks(const crypto::Prf<kUpdateTokenSize>& derivation_prf,
                            const uint8_t*                       search_token,
                            update_token_type&                   update_token,
                            std::array<uint8_t, kUpdateTokenSize>& mask);
} // namespace sophos
} // namespace sse

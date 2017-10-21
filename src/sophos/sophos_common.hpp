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

#include <string>
#include <array>

#include <sse/crypto/tdp.hpp>
#include <sse/crypto/prf.hpp>

namespace sse {
    namespace sophos {

        constexpr size_t kSearchTokenSize = crypto::Tdp::kMessageSize;
        constexpr size_t kDerivationKeySize = 32;
        constexpr size_t kUpdateTokenSize = 16;
        
        typedef std::array<uint8_t, kSearchTokenSize> search_token_type;
        typedef std::array<uint8_t, kUpdateTokenSize> update_token_type;
        typedef uint64_t index_type;
        
        
        struct SearchRequest
        {
            search_token_type                               token;
            std::array<uint8_t, kDerivationKeySize>         derivation_key;
            uint32_t                                        add_count;
        };
        
        
        struct UpdateRequest
        {
            update_token_type   token;
            index_type          index;
        };
        
        void gen_update_token_masks(const std::array<uint8_t, kDerivationKeySize> &deriv_key,
                                    const uint8_t* search_token,
                                    update_token_type &update_token,
                                    std::array<uint8_t, kUpdateTokenSize> &mask);
    }
}

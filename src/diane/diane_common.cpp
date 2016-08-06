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

#include "diane_common.hpp"

#include <sse/crypto/block_hash.hpp>

#include <cstring>

namespace sse {
    namespace diane {
        
        void gen_update_token_mask(const uint8_t* search_token, update_token_type &update_token, index_type &mask)
        {
            uint8_t st_data[2*kSearchTokenKeySize], tmp[2*kSearchTokenKeySize];
            memcpy(st_data, search_token, kSearchTokenKeySize);
            memcpy(st_data+kSearchTokenKeySize, search_token, kSearchTokenKeySize);
            
            // Derive the update token and the mask from a leaf search token
            // We want to avoid using a HMAC-like construction or
            // using some different IVs to have two different hash functions.
            // So, to ensure domain separation, set the first byte of the key to 0x00 or 0x01
            st_data[0] = 0x00;
            st_data[kSearchTokenKeySize] = 0x01;
            
            crypto::BlockHash::mult_hash(st_data, 2*kSearchTokenKeySize, tmp);
            
            memcpy(update_token.data(), tmp, kSearchTokenKeySize);
            memcpy(&mask, tmp+kSearchTokenKeySize, sizeof(index_type));
        }

    }
}
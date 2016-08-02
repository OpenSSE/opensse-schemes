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

#include "types.hpp"

namespace sse {
    namespace diane {
        
        void gen_update_token_mask(const uint8_t* search_token, update_token_type &update_token, index_type &mask);
        
        inline void gen_update_token_mask(const search_token_key_type &search_token, update_token_type &update_token, index_type &mask)
        {
            gen_update_token_mask(search_token.data(), update_token, mask);
        }
    }
}
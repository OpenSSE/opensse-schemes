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

#include <sse/crypto/prg.hpp>

#include <array>
#include <list>
#include <utility>

namespace sse {
    namespace diane {
        
        class TokenTree
        {
        public:
            static constexpr uint8_t kTokenSize = crypto::Prg::kKeySize;
            typedef std::array<uint8_t, kTokenSize> token_type;
            
            static token_type derive_node(const token_type& K, uint64_t node_index, uint8_t depth);
            
            
            static inline std::list<std::pair<token_type, uint8_t>> covering_list(const token_type& root, uint64_t node_count, uint8_t depth);
            
        private:
            static void covering_list_aux(const token_type& root, uint64_t node_count, uint8_t depth, std::list<std::pair<token_type, uint8_t>> &list);
        };
        
        
        std::list<std::pair<TokenTree::token_type, uint8_t>> TokenTree::covering_list(const token_type& root, uint64_t node_count, uint8_t depth)
        {
            std::list<std::pair<TokenTree::token_type, uint8_t>> l;
            covering_list_aux(root, node_count, depth, l);
            
            return l;
        }

    }
}
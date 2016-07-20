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


#include "token_tree.hpp"

#include <cassert>


namespace sse {
    namespace diane {
        
        TokenTree::token_type TokenTree::derive_node(const token_type& K, uint64_t node_index, uint8_t depth)
        {
            if (depth == 0) {
                return K;
            }
            token_type t = K;
            
            uint64_t mask = 1UL << (depth-1);

            
            for (uint8_t i = 0; i < depth; i++) {
                uint32_t offset = ((node_index & mask) == 0) ? 0 : kTokenSize;
                crypto::Prg::derive(t, offset, t);
                
                mask >>= 1;
            }

            return t;
        }
        
        
        
        void TokenTree::covering_list_aux(const token_type& K, uint64_t node_count, uint8_t depth, std::list<std::pair<token_type, uint8_t>> &list)
        {
            assert(node_count > 0);
            
            uint64_t siblings_count = 1UL << depth;
            
            if (node_count == siblings_count) {
                list.push_back(std::make_pair(K, depth));
                return;
            }
            
            token_type K_left;
            crypto::Prg::derive(K, 0, K_left);

            if (node_count > (siblings_count>>1)) {
                list.push_back(std::make_pair(K_left, depth-1));
                token_type K_right;
                crypto::Prg::derive(K, kTokenSize, K_right);
                
                covering_list_aux(K_right, node_count - (siblings_count>>1), depth-1, list);
            }else{
                // node_count <= siblings_count/2
                covering_list_aux(K_left, node_count, depth-1, list);
            }
        }

    }
}
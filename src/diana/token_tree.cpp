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
#include <stack>

#define MAX(a,b) (((a) < (b)) ? (b) : (a))
#define MIN(a,b) (((a) > (b)) ? (b) : (a))

namespace sse {
    namespace diana {
        
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
        
        
        TokenTree::token_type TokenTree::derive_leftmost_node(const token_type& K, uint8_t depth, std::function<void(token_type, uint8_t)> right_node_callback)
        {
            if (depth == 0) {
                return K;
            }
            
            token_type t = K;

            for (uint8_t i = 0; i < depth; i++) {

                token_type right;
                
                // in the future, optimize this:
                // with AES-NI and a well written code, it should not cost more to derive two blocks than deriving a single one
                crypto::Prg::derive(t, kTokenSize, right);
                crypto::Prg::derive(t, 0, t);
                
                right_node_callback(right, depth-1-i);
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
        
        
/*
        void TokenTree::derive_all_leaves(const token_type& K, const uint8_t depth, const std::function<void(token_type)> &callback)
        {
//            if (depth == 0) {
//                callback(K);
//                return;
//            }
            std::stack<token_type> token_stack;
            std::stack<uint8_t> depth_stack;
            
            
            uint8_t current_depth = 0;
            token_type current_token = K;
            token_type right_token;
            std::array<uint8_t, 2*kTokenSize> derived_tokens;
            
            while (true) { // loop over the elements in the stack
                
                while (true) { // loop over the depth :
                    // we will reach the maximum depth while pushing intermediate nodes
                    // once we are done, we will pop the last node in the stack
                    
                    if (current_depth == depth) { // we are at the bottom level
                        // post the leaf and exit the inner loop
                        callback(current_token);
                        break;
                    }else{
                        // generate tokens for the two children
                        crypto::Prg::derive(current_token, 0, derived_tokens);
                        
                        std::copy(derived_tokens.begin(), derived_tokens.begin()+kTokenSize, current_token.begin());
                        std::copy(derived_tokens.begin()+kTokenSize, derived_tokens.end(), right_token.begin());

                        token_stack.push(right_token);
                        depth_stack.push(current_depth);

                        current_depth++;
                    }
                }
                // check if the stack is empty or not
                if (token_stack.empty()) {
                    // then we are done
                    break;
                }
                
                // pop the top element
                current_token = token_stack.top();
                current_depth = depth_stack.top();
                token_stack.pop();
                depth_stack.pop();
                
            }
            
        }
*/

        static void derive_all_leaves_aux(const uint8_t* K, const uint8_t depth, const std::function<void(const uint8_t *)> &callback)
        {
            // generate the children
            
            uint8_t derived_tokens[2*TokenTree::kTokenSize];
            
            crypto::Prg::derive(K, 0, 2*TokenTree::kTokenSize, derived_tokens);
            

            if (depth == 1) {
                // these are leaves
                callback(derived_tokens);
                callback(derived_tokens+TokenTree::kTokenSize);
                
                return;
            }
            
            // recursive call on children
            
            derive_all_leaves_aux(derived_tokens, depth-1, callback);
            derive_all_leaves_aux(derived_tokens+TokenTree::kTokenSize, depth-1, callback);
        }
        
        void TokenTree::derive_all_leaves(const token_type& K, const uint8_t depth, const std::function<void(const uint8_t *)> &callback)
        {
            if (depth == 0) {
                callback(K.data());
                return;
            }

            derive_all_leaves_aux(K.data(), depth, callback);
        }
        
        static void derive_leaves_aux(const uint8_t* K, const uint8_t depth, const uint64_t start_index, const uint64_t end_index, const std::function<void(const uint8_t *)> &callback)
        {
            if (depth == 0) {
                if (start_index != 0) {
                    throw std::out_of_range("Invalid start index (" + std::to_string(start_index) + "!= 0) for depth 0");
                }
                
                callback(K);
                
                // we are done
                return;
            }
            
            // if the input node (K) spans all the leaves, derive everything
            if (start_index == 0 && end_index == ((1UL << depth)-1)) {
                derive_all_leaves_aux(K, depth, callback);
                
                return;
            }
            
            uint64_t half_node_count = (1UL << (depth-1));
            
            // check if the left and/or right child is needed
            bool need_left = (start_index <= (half_node_count-1));
            bool need_right = (end_index >= half_node_count);
            
            uint8_t *left_node = NULL;
            uint8_t *right_node = NULL;
            
            
            if (need_left && need_right) {
                // generate  both children
                
                uint8_t derived_tokens[2*TokenTree::kTokenSize];
                
                crypto::Prg::derive(K, 0, 2*TokenTree::kTokenSize, derived_tokens);

                left_node = derived_tokens;
                right_node = derived_tokens + TokenTree::kTokenSize;
            }else if(need_left) {
                uint8_t derived_token[TokenTree::kTokenSize];
                
                crypto::Prg::derive(K, 0, TokenTree::kTokenSize, derived_token);
                
                left_node = derived_token;
            }else if(need_right) {
                uint8_t derived_token[TokenTree::kTokenSize];
                
                crypto::Prg::derive(K, TokenTree::kTokenSize, TokenTree::kTokenSize, derived_token);
                
                right_node = derived_token;
            }else{
                // both flags are set to false
                // this should not have happened
             
                throw std::out_of_range("Invalid start index (" + std::to_string(start_index) + ") or end index (" + std::to_string(end_index) + ")for depth " + std::to_string(depth));

            }
            
            // recurse on the left child if necessary
            if (need_left) {
                uint64_t left_end = half_node_count-1;
                if (!need_right) {
                    left_end = end_index;
                }
                derive_leaves_aux(left_node, depth-1, start_index, left_end, callback);
            }
            if (need_right) {
                uint64_t right_start = 0;
                if(!need_left) {
                    right_start = start_index - half_node_count;
                }
                uint64_t right_end = end_index - half_node_count;

                derive_leaves_aux(right_node, depth-1, right_start, right_end, callback);
            }
            
        }
        
        void TokenTree::derive_leaves(const token_type& K, const uint8_t depth, const uint64_t start_index, const uint64_t end_index, const std::function<void(const uint8_t *)> &callback)
        {
            derive_leaves_aux(K.data(), depth, start_index, end_index, callback);
        }
    }
}
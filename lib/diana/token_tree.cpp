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


#include <sse/schemes/diana/token_tree.hpp>

#include <cassert>

#include <exception>
#include <stack>

#define MAX(a, b) (((a) < (b)) ? (b) : (a))
#define MIN(a, b) (((a) > (b)) ? (b) : (a))

namespace sse {
namespace diana {

TokenTree::inner_token_type TokenTree::derive_inner_node(inner_token_type&& K,
                                                         uint64_t node_index,
                                                         uint8_t  depth)
{
    if (depth == 0) {
        return std::move(K);
    }
    if (depth >= 64) {
        throw std::invalid_argument("Invalid depth >= 64. Depth is too big.");
    }
    if (node_index >> depth != 0) {
        throw std::invalid_argument(
            "Invalid node index: node_index > 2^depth -1.");
    }

    inner_token_type t(std::move(K));

    uint64_t mask = 1UL << (depth - 1);


    for (uint8_t i = 0; i < depth; i++) {
        uint8_t offset = ((node_index & mask) == 0) ? 0 : 1;

        t = crypto::Prg::derive_key<kTokenSize>(std::move(t), offset);

        mask >>= 1;
    }

    return t;
}

TokenTree::token_type TokenTree::derive_node(inner_token_type&& K,
                                             uint64_t           node_index,
                                             uint8_t            depth)
{
    if (depth == 0) {
        throw std::invalid_argument(
            "Invalid depth == 0. A node at depth 0 is not an inner node");
    }
    if (depth >= 64) {
        throw std::invalid_argument("Invalid depth >= 64. Depth is too big.");
    }
    if (node_index >> depth != 0) {
        throw std::invalid_argument(
            "Invalid node index: node_index > 2^depth -1.");
    }

    inner_token_type last_inner
        = derive_inner_node(std::move(K), node_index >> 1, depth - 1);

    token_type res;
    uint32_t   offset = (node_index % 2) * kTokenSize;

    crypto::Prg::derive(std::move(last_inner), offset, kTokenSize, res.data());

    return res;
}

TokenTree::token_type TokenTree::derive_leftmost_node(
    const token_type&                               K,
    uint8_t                                         depth,
    const std::function<void(token_type, uint8_t)>& right_node_callback)
{
    if (depth >= 64) {
        throw std::invalid_argument("Invalid depth >= 64. Depth is too big.");
    }
    if (depth == 0) {
        return K;
    }

    token_type t = K;

    for (uint8_t i = 0; i < depth; i++) {
        token_type right;

        // in the future, optimize this:
        crypto::Prg prg((crypto::Key<crypto::Prg::kKeySize>(t.data())));


        prg.derive(0, kTokenSize, t.data());
        prg.derive(kTokenSize, kTokenSize, right.data());

        right_node_callback(right, depth - 1 - i);
    }

    return t;
}


void TokenTree::covering_list_aux(
    const token_type&                          K,
    uint64_t                                   node_count,
    uint8_t                                    depth,
    std::list<std::pair<token_type, uint8_t>>& list)
{
    assert(node_count > 0);

    uint64_t siblings_count = 1UL << depth;

    if (node_count == siblings_count) {
        list.emplace_back(K, depth);
        return;
    }

    token_type  K_left = K;
    crypto::Prg prg((crypto::Key<crypto::Prg::kKeySize>(K_left.data())));

    prg.derive(0, kTokenSize, K_left.data());

    if (node_count > (siblings_count >> 1)) {
        list.emplace_back(K_left, depth - 1);
        token_type K_right;

        prg.derive(kTokenSize, kTokenSize, K_right.data());

        covering_list_aux(
            K_right, node_count - (siblings_count >> 1), depth - 1, list);
    } else {
        // node_count <= siblings_count/2
        covering_list_aux(K_left, node_count, depth - 1, list);
    }
}


static void derive_all_leaves_aux(uint8_t*                             K,
                                  const uint8_t                        depth,
                                  const std::function<void(uint8_t*)>& callback)
{
    // generate the children

    uint8_t derived_tokens[2 * TokenTree::kTokenSize];

    crypto::Prg::derive(crypto::Key<crypto::Prg::kKeySize>(K),
                        0,
                        2 * TokenTree::kTokenSize,
                        derived_tokens);


    if (depth == 1) {
        // these are leaves
        callback(derived_tokens);
        callback(derived_tokens + TokenTree::kTokenSize);

        return;
    }

    // recursive call on children

    derive_all_leaves_aux(derived_tokens, depth - 1, callback);
    derive_all_leaves_aux(
        derived_tokens + TokenTree::kTokenSize, depth - 1, callback);
}

void TokenTree::derive_all_leaves(token_type&                          K,
                                  const uint8_t                        depth,
                                  const std::function<void(uint8_t*)>& callback)
{
    if (depth == 0) {
        callback(K.data());
        return;
    }
    if (depth >= 64) {
        throw std::invalid_argument("Invalid depth >= 64. Depth is too big.");
    }

    derive_all_leaves_aux(K.data(), depth, callback);
}

static void derive_leaves_aux(uint8_t*                             K,
                              const uint8_t                        depth,
                              const uint64_t                       start_index,
                              const uint64_t                       end_index,
                              const std::function<void(uint8_t*)>& callback)
{
    if (depth == 0) {
        if (start_index != 0) {
            throw std::out_of_range("Invalid start index ("
                                    + std::to_string(start_index)
                                    + "!= 0) for depth 0");
        }

        callback(K);

        // we are done
        return;
    }

    // if the input node (K) spans all the leaves, derive everything
    if (start_index == 0 && end_index == ((1UL << depth) - 1)) {
        derive_all_leaves_aux(K, depth, callback);

        return;
    }

    uint64_t half_node_count = (1UL << (depth - 1));

    // check if the left and/or right child is needed
    bool need_left  = (start_index <= (half_node_count - 1));
    bool need_right = (end_index >= half_node_count);

    uint8_t* left_node  = nullptr;
    uint8_t* right_node = nullptr;


    if (need_left && need_right) {
        // generate  both children

        uint8_t derived_tokens[2 * TokenTree::kTokenSize];

        crypto::Prg::derive(crypto::Key<crypto::Prg::kKeySize>(K),
                            0,
                            2 * TokenTree::kTokenSize,
                            derived_tokens);

        left_node  = derived_tokens;
        right_node = derived_tokens + TokenTree::kTokenSize;
    } else if (need_left) {
        uint8_t derived_token[TokenTree::kTokenSize];

        crypto::Prg::derive(crypto::Key<crypto::Prg::kKeySize>(K),
                            0,
                            TokenTree::kTokenSize,
                            derived_token);

        left_node = derived_token;
    } else if (need_right) {
        uint8_t derived_token[TokenTree::kTokenSize];

        crypto::Prg::derive(crypto::Key<crypto::Prg::kKeySize>(K),
                            TokenTree::kTokenSize,
                            TokenTree::kTokenSize,
                            derived_token);

        right_node = derived_token;
    } else {
        // both flags are set to false
        // this should not have happened

        throw std::out_of_range("Invalid start index ("
                                + std::to_string(start_index)
                                + ") or end index (" + std::to_string(end_index)
                                + ")for depth " + std::to_string(depth));
    }

    // recurse on the left child if necessary
    if (need_left) {
        uint64_t left_end = half_node_count - 1;
        if (!need_right) {
            left_end = end_index;
        }
        derive_leaves_aux(
            left_node, depth - 1, start_index, left_end, callback);
    }
    if (need_right) {
        uint64_t right_start = 0;
        if (!need_left) {
            right_start = start_index - half_node_count;
        }
        uint64_t right_end = end_index - half_node_count;

        derive_leaves_aux(
            right_node, depth - 1, right_start, right_end, callback);
    }
}

void TokenTree::derive_leaves(token_type&                          K,
                              const uint8_t                        depth,
                              const uint64_t                       start_index,
                              const uint64_t                       end_index,
                              const std::function<void(uint8_t*)>& callback)
{
    if (depth >= 64) {
        throw std::invalid_argument("Invalid depth >= 64. Depth is too big.");
    }
    derive_leaves_aux(K.data(), depth, start_index, end_index, callback);
}
} // namespace diana
} // namespace sse

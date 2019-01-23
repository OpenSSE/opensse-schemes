//
//  types.hpp
//  sophos
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#pragma once

#include <sse/schemes/diana/types.hpp>

#include <sse/crypto/puncturable_enc.hpp>

#include <array>

namespace sse {
namespace janus {

constexpr size_t kInsertionTokenPayloadSize = crypto::punct::kCiphertextSize;

using index_type = uint64_t;

constexpr size_t kKeywordTokenSize = 16;
using keyword_token_type           = std::array<uint8_t, kKeywordTokenSize>;

struct SearchRequest
{
    keyword_token_type keyword_token;

    diana::SearchRequest insertion_search_request;
    diana::SearchRequest deletion_search_request;

    crypto::punct::key_share_type first_key_share;

    SearchRequest() = delete;

    SearchRequest(const keyword_token_type&            token,
                  diana::SearchRequest&&               add_req,
                  diana::SearchRequest&&               del_req,
                  const crypto::punct::key_share_type& ks)
        : keyword_token(token), insertion_search_request(std::move(add_req)),
          deletion_search_request(std::move(del_req)), first_key_share(ks)
    {
    }

    SearchRequest(const SearchRequest& sr) = delete;

    SearchRequest(SearchRequest&& sr) = default;
    SearchRequest& operator=(SearchRequest&& sr) = default;
};

using InsertionRequest = diana::UpdateRequest<crypto::punct::ciphertext_type>;

using DeletionRequest = diana::UpdateRequest<crypto::punct::key_share_type>;

} // namespace janus
} // namespace sse

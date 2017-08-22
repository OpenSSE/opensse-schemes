//
//  types.hpp
//  sophos
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#pragma once

#include "diana/types.hpp"

#include <sse/crypto/puncturable_enc.hpp>
#include <array>

namespace sse {
    namespace janus {

        constexpr size_t kInsertionTokenPayloadSize = crypto::punct::kCiphertextSize;

        typedef uint64_t index_type;
        
        constexpr size_t kKeywordTokenSize = 16;
        typedef std::array<uint8_t, kKeywordTokenSize> keyword_token_type;
        
        struct SearchRequest
        {
            keyword_token_type keyword_token;
            
            diana::SearchRequest insertion_search_request;
            diana::SearchRequest deletion_search_request;
            
            crypto::punct::key_share_type first_key_share;
        };

        typedef diana::UpdateRequest<crypto::punct::ciphertext_type> InsertionRequest;
        
        typedef diana::UpdateRequest<crypto::punct::key_share_type> DeletionRequest;

    }
}

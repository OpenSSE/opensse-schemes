//
//  types.hpp
//  sophos
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#pragma once

#include "diane/types.hpp"

#include <sse/crypto/puncturable_enc.hpp>
#include <array>

namespace sse {
    namespace janus {

        constexpr size_t kInsertionTokenPayloadSize = crypto::punct::kCiphertextSize;

        typedef uint64_t index_type;
        
        struct SearchRequest
        {
            diane::SearchRequest insertion_search_request;
            diane::SearchRequest deletion_search_request;
            
            crypto::punct::key_share_type first_key_share;
        };

        typedef diane::UpdateRequest<crypto::punct::ciphertext_type> InsertionRequest;
        
        typedef diane::UpdateRequest<crypto::punct::key_share_type> DeletionRequest;

    }
}

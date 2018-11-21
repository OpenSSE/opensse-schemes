//
//  sophos_common.cpp
//  SSE_Schemes
//
//  Created by Raphael Bost on 04/10/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#include <sse/schemes/sophos/sophos_common.hpp>

#include <sse/crypto/prf.hpp>

#include <cstring>

namespace sse {
namespace sophos {

void gen_update_token_masks(const crypto::Prf<kUpdateTokenSize>& derivation_prf,
                            const uint8_t*                       search_token,
                            update_token_type&                   update_token,
                            std::array<uint8_t, kUpdateTokenSize>& mask)
{
    //            auto derivation_prf =
    //            crypto::Prf<kUpdateTokenSize>(deriv_key);

    std::string st_string(reinterpret_cast<const char*>(search_token),
                          kSearchTokenSize);

    update_token = derivation_prf.prf(st_string + '0');
    mask         = derivation_prf.prf(st_string + '1');
}

} // namespace sophos
} // namespace sse

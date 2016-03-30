//
//  sophos_core.cpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_core.hpp"

namespace sse {
namespace sophos {

size_t TokenHasher::operator()(const update_token_type& ut) const
{
    size_t h = 0;
    for (size_t i = 0; i < kUpdateTokenSize; i++) {
        if (i > 0) {
            h <<= 8;
        }
        h = ut[i] + h;
    }
    return 0;
}

    
SophosServer::SophosServer(const std::string& db_path, const std::string& tdp_pk) :
edb_(db_path, 1000), public_tdp_(tdp_pk)
{
    
}

} // namespace sophos
} // namespace sse

//
//  sophos_core.cpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_core.hpp"

#include <iostream>

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

std::list<index_type> SophosServer::search(const SearchRequest& req)
{
    std::list<index_type> results;
    
    search_token_type st = req.token;
    
    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);
    
    for (size_t i = 0; i < req.add_count; i++) {
        index_type r;
        update_token_type ut = derivation_prf.prf(st.data(), st.size());
        
        bool found = edb_.get(ut,r);
        
        if (found) {
            results.push_back(r);
        }else{
            std::cerr << "We were supposed to find something!" << std::endl;
        }
    }
    
    return results;
}

void SophosServer::update(const UpdateRequest& req)
{
    edb_.add(req.token, req.index);
}

} // namespace sophos
} // namespace sse

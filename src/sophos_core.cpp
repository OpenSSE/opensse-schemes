//
//  sophos_core.cpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_core.hpp"

#include "utils.hpp"

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

SophosClient::SophosClient() :
k_prf_(), token_map_(), inverse_tdp_()
{
    
}

SearchRequest   SophosClient::search_request(const std::string &keyword) const
{
    auto it = token_map_.find(keyword);
    
    SearchRequest req;
    req.add_count = 0;
    
    if (it != token_map_.end()) {
        req.token = it->second.first;
        req.derivation_key = k_prf_.prf_string(keyword);
        req.add_count = it->second.second;
    }
    return req;
}
    
UpdateRequest   SophosClient::update_request(const std::string &keyword, const index_type index)
{
    auto it = token_map_.find(keyword);

    UpdateRequest req;
    search_token_type st;
    
    if (it == token_map_.end()) { // the keyword does not already exist in the database
        st = inverse_tdp_.sample();
        
        token_map_.insert(std::make_pair(keyword, std::make_pair(st, 1)));
    }else{
        st = it->second.first;
        
        it->second.first = inverse_tdp_.invert(it->second.first);
        it->second.second++;
    }
    
    std::string deriv_key = k_prf_.prf_string(keyword);

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
    
    
    req.token = derivation_prf.prf(st + '0');
    req.index = xor_mask(index, derivation_prf.prf(st + '1'));
    
    return req;
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
        update_token_type ut = derivation_prf.prf(st + '0');
        
        bool found = edb_.get(ut,r);
        
        if (found) {
            r = xor_mask(r, derivation_prf.prf(st + '1'));
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

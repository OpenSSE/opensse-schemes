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

SophosClient::SophosClient(const std::string& save_path) :
k_prf_(), token_map_(save_path, 1000), inverse_tdp_()
{
    
}
const std::string SophosClient::public_key() const
{
    return inverse_tdp_.public_key();
}


SearchRequest   SophosClient::search_request(const std::string &keyword) const
{
    std::pair<search_token_type, uint32_t> search_pair;
    bool found;
    SearchRequest req;
    req.add_count = 0;

    found = token_map_.get(keyword, search_pair);
    
    if(found)
    {
        req.token = search_pair.first;
        req.derivation_key = k_prf_.prf_string(keyword);
        req.add_count = search_pair.second;
    }
    return req;
}
    
UpdateRequest   SophosClient::update_request(const std::string &keyword, const index_type index)
{
    std::pair<search_token_type, uint32_t> search_pair;
    bool found;

    UpdateRequest req;
    search_token_type st;

    // to get and modify the search pair, it might be more efficient
    // to directly use at() and see if an exception is raised
    found = token_map_.get(keyword, search_pair);

    if (!found) {
        st = inverse_tdp_.sample();
        token_map_.add(keyword, std::make_pair(st, 1));
    }else{
        st = inverse_tdp_.invert(search_pair.first);
        
        token_map_.at(keyword) = std::make_pair(st, search_pair.second+1);
    }
    
//    std::cout << st[0] << std::endl;
//    std::cout << token_map_.at(keyword).first[0] << std::endl;
    
    std::string deriv_key = k_prf_.prf_string(keyword);

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
    
    
    req.token = derivation_prf.prf(st + '0');
    req.index = xor_mask(index, derivation_prf.prf(st + '1'));
    
    std::cout << "Update token: " << std::hex << req.token[0] << std::endl;

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
        std::cout << "Derived token: " << std::hex << ut[0] << std::endl;

        bool found = edb_.get(ut,r);
        
        if (found) {
            r = xor_mask(r, derivation_prf.prf(st + '1'));
            results.push_back(r);
        }else{
            std::cerr << "We were supposed to find something!" << std::endl;
        }
        
        st = public_tdp_.eval(st);
    }
    
    return results;
}

void SophosServer::update(const UpdateRequest& req)
{
    edb_.add(req.token, req.index);
}

} // namespace sophos
} // namespace sse

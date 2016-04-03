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

SophosClient::SophosClient(const std::string& token_map_path, const size_t tm_setup_size) :
k_prf_(), token_map_(token_map_path, tm_setup_size), inverse_tdp_()
{
    
}
    
SophosClient::SophosClient(const std::string& token_map_path, const std::string& tdp_private_key, const std::string& derivation_master_key) :
k_prf_(derivation_master_key), token_map_(token_map_path), inverse_tdp_(tdp_private_key)
{
    
}
    
const std::string SophosClient::public_key() const
{
    return inverse_tdp_.public_key();
}

const std::string SophosClient::private_key() const
{
    return inverse_tdp_.private_key();
}
    
const std::string SophosClient::master_derivation_key() const
{
    return std::string(k_prf_.key().begin(), k_prf_.key().end());
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
//    search_pair = token_map_.at(keyword);
//    found = true;
        
    if (!found) {
        st = inverse_tdp_.sample_array();
        token_map_.add(keyword, std::make_pair(st, 1));
    }else{
        st = inverse_tdp_.invert(search_pair.first);
        
            std::cout << "ST0 " << st[0] << std::endl;

        token_map_.at(keyword) = std::make_pair(st, search_pair.second+1);
    }
    
    std::cout << "New ST0 "<< st[0] << std::endl;
//    std::cout << token_map_.at(keyword).first[0] << std::endl;
    
    std::string deriv_key = k_prf_.prf_string(keyword);
    std::cout << "Derived key: " << std::hex << deriv_key << std::endl;
    
    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
    
    std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
    
    req.token = derivation_prf.prf(st_string + '0');
    req.index = xor_mask(index, derivation_prf.prf(st_string + '1'));
    
    std::cout << "Update token: " << std::hex << req.token[0] << std::endl;

    return req;
}

SophosServer::SophosServer(const std::string& db_path, const std::string& tdp_pk) :
edb_(db_path), public_tdp_(tdp_pk)
{
    
}

SophosServer::SophosServer(const std::string& db_path, const size_t tm_setup_size, const std::string& tdp_pk) :
edb_(db_path, tm_setup_size), public_tdp_(tdp_pk)
{
    
}

const std::string SophosServer::public_key() const
{
    return public_tdp_.public_key();
}

std::list<index_type> SophosServer::search(const SearchRequest& req)
{
    std::list<index_type> results;
    
    search_token_type st = req.token;

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);
    
    for (size_t i = 0; i < req.add_count; i++) {
        std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
        index_type r;
        update_token_type ut = derivation_prf.prf(st_string + '0');
        std::cout << "Derived token: " << std::hex << ut[0] << std::endl;

        bool found = edb_.get(ut,r);
        
        if (found) {
            r = xor_mask(r, derivation_prf.prf(st_string + '1'));
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

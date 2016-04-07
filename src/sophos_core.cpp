//
//  sophos_core.cpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_core.hpp"

#include "utils.hpp"
#include "logger.hpp"

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
    return h;
}

SophosClient::SophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const size_t tm_setup_size) :
    k_prf_(), token_map_(token_map_path, tm_setup_size), inverse_tdp_()
{
    load_keyword_indices(keyword_indexer_path);

    keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
    if (!keyword_indexer_stream_.is_open()) {
        keyword_indexer_stream_.close();
        throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
    }
}
    
SophosClient::SophosClient(const std::string& token_map_path, const std::string& keyword_indexer_path, const std::string& tdp_private_key, const std::string& derivation_master_key) :
k_prf_(derivation_master_key), token_map_(token_map_path), inverse_tdp_(tdp_private_key)
{
    load_keyword_indices(keyword_indexer_path);
   
    keyword_indexer_stream_.open(keyword_indexer_path, std::ios_base::app | std::ios_base::out);
    if (!keyword_indexer_stream_.is_open()) {
        keyword_indexer_stream_.close();
        throw std::runtime_error("Could not open keyword index file " + keyword_indexer_path);
    }
}

SophosClient::~SophosClient()
{
    keyword_indexer_stream_.close();
}

void SophosClient::load_keyword_indices(const std::string &path)
{
    std::ifstream keyword_indices_in(path);
    
    if(keyword_indices_in)
    {
        bool ret = parse_keyword_map(keyword_indices_in, keyword_indices_);
        
        if (!ret) {
            logger::log(logger::WARNING) << "Error when parsing the keyword indices" << std::endl;
        }
    }
    keyword_indices_in.close();
    
    keyword_counter_ = keyword_indices_.size();
}

size_t SophosClient::keyword_count() const
{
    return token_map_.size();
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

    auto it = keyword_indices_.find(keyword);

    if (it != keyword_indices_.end()) {
        found = token_map_.get(it->second, search_pair);
        
        if(!found)
        {
            logger::log(logger::ERROR) << "No matching token found for keyword " << keyword << " (index " << it->second << ")" << std::endl;
        }else{
            req.token = search_pair.first;
            req.derivation_key = k_prf_.prf_string(keyword);
            req.add_count = search_pair.second;
        }
    }
    return req;
}
    
UpdateRequest   SophosClient::update_request(const std::string &keyword, const index_type index)
{
    std::pair<search_token_type, uint32_t> search_pair;
    bool found;
    std::map<std::string, uint32_t>::iterator it;
    
    UpdateRequest req;
    search_token_type st;
    
    std::unique_lock<std::mutex> kw_index_lock(kw_index_mtx_, std::defer_lock);

    kw_index_lock.lock();
    it = keyword_indices_.find(keyword);
    kw_index_lock.unlock();
    
    if (it == keyword_indices_.end()) {
        // we have to insert the keyword
        uint32_t c = keyword_counter_++;
        kw_index_lock.lock();
        it = keyword_indices_.insert(std::make_pair(keyword, c)).first;
        append_keyword_map(keyword_indexer_stream_, keyword, c);
        kw_index_lock.unlock();
    }
    
    uint32_t kw_index = it->second;
    
    // to get and modify the search pair, it might be more efficient
    // to directly use at() and see if an exception is raised
    {
        std::lock_guard<std::mutex> lock(token_map_mtx_);
        found = token_map_.get(kw_index, search_pair);
    }
    
    if (!found) {
        st = inverse_tdp_.sample_array();
        
        {
            std::lock_guard<std::mutex> lock(token_map_mtx_);
            token_map_.add(kw_index, std::make_pair(st, 1));
        }
        logger::log(logger::DBG) << "ST0 " << logger::hex_string(st) << std::endl;
    }else{
        st = inverse_tdp_.invert(search_pair.first);

        logger::log(logger::DBG) << "New ST " << logger::hex_string(st) << std::endl;

        {
            std::lock_guard<std::mutex> lock(token_map_mtx_);
            token_map_.at(kw_index) = std::make_pair(st, search_pair.second+1);
        }
    }
    
    
    std::string deriv_key = k_prf_.prf_string(keyword);

    logger::log(logger::DBG) << "Derivation key: " << logger::hex_string(deriv_key) << std::endl;

    
    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
    
    std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
    
    req.token = derivation_prf.prf(st_string + '0');
    req.index = xor_mask(index, derivation_prf.prf(st_string + '1'));
    
    logger::log(logger::DBG) << "Update token: (" << logger::hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;

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

    logger::log(logger::DBG) << "Search token: " << logger::hex_string(req.token) << std::endl;

    auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);
    
    logger::log(logger::DBG) << "Derivation key: " << logger::hex_string(req.derivation_key) << std::endl;

    for (size_t i = 0; i < req.add_count; i++) {
        std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
        index_type r;
        update_token_type ut = derivation_prf.prf(st_string + '0');

        logger::log(logger::DBG) << "Derived token: " << logger::hex_string(ut) << std::endl;

        bool found = edb_.get(ut,r);
        
        if (found) {
            logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
            
            r = xor_mask(r, derivation_prf.prf(st_string + '1'));
            results.push_back(r);
        }else{
            logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
        }
        
        st = public_tdp_.eval(st);
    }
    
    return results;
}

void SophosServer::update(const UpdateRequest& req)
{
    logger::log(logger::DBG) << "Update: (" << logger::hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;

    edb_.add(req.token, req.index);
}

} // namespace sophos
} // namespace sse

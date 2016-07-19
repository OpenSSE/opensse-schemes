//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//


#include "diane_client.hpp"

#include "utils.hpp"
#include "logger.hpp"

#include <sse/crypto/block_hash.hpp>

#include <sse/dbparser/rapidjson/rapidjson.h>
#include <sse/dbparser/rapidjson/writer.h>
#include <sse/dbparser/rapidjson/prettywriter.h>
#include <sse/dbparser/rapidjson/filewritestream.h>
#include <sse/dbparser/rapidjson/filereadstream.h>
#include <sse/dbparser/rapidjson/ostreamwrapper.h>
#include <sse/dbparser/rapidjson/document.h>


namespace sse {
    namespace diane {
        
        DianeClient::DianeClient(const std::string& token_map_path, const size_t tm_setup_size) :
        root_prf_(), kw_token_prf_(), counter_map_(token_map_path, tm_setup_size)
        {
            
        }
        
        DianeClient::DianeClient(const std::string& token_map_path, const std::string& derivation_master_key, const std::string& kw_token_master_key) :
        root_prf_(derivation_master_key), kw_token_prf_(kw_token_master_key), counter_map_(token_map_path)
        {
            
        }
        DianeClient::~DianeClient()
        {
            
        }

        
        size_t DianeClient::keyword_count() const
        {
            return counter_map_.size();
        }
        
        const std::string DianeClient::master_derivation_key() const
        {
            return std::string(root_prf_.key().begin(), root_prf_.key().end());
        }

        const std::string DianeClient::kw_token_master_key() const
        {
            return std::string(kw_token_prf_.key().begin(), kw_token_prf_.key().end());
        }


        DianeClient::keyword_index_type DianeClient::get_keyword_index(const std::string &kw) const
        {
            std::string hash_string = crypto::Hash::hash(kw);
            
            keyword_index_type ret;
            std::copy_n(hash_string.begin(), kKeywordIndexSize, ret.begin());
            
            return ret;
        }
        
        SearchRequest   DianeClient::search_request(const std::string &keyword) const
        {
            keyword_index_type kw_index = get_keyword_index(keyword);
            
            return search_request_index(kw_index);
        }

        
        SearchRequest   DianeClient::random_search_request() const
        {
            SearchRequest req;
            req.add_count = 0;
            
            auto rnd_elt = counter_map_.random_element();
            
            keyword_index_type kw_index = rnd_elt.first;
            
            return search_request_index(kw_index);
        }
        
        SearchRequest   DianeClient::search_request_index(const keyword_index_type &kw_index) const
        {
            bool found;
            uint32_t kw_counter;
            SearchRequest req;
            req.add_count = 0;

            found = counter_map_.get(kw_index, kw_counter);

            if(!found)
            {
                logger::log(logger::INFO) << "No matching counter found for keyword index " << hex_string(std::string(kw_index.begin(),kw_index.end())) << std::endl;
            }else{
                req.add_count = kw_counter+1;

                // Compute the root of the tree attached to kw_index

                TokenTree::token_type root = root_prf_.prf(kw_index.data(), kw_index.size());
                
                req.token_list = TokenTree::covering_list(root, req.add_count, kTreeDepth);
                
                
                // set the kw_token
                req.kw_token = kw_token_prf_.prf(kw_index);
            }
            
            return req;

        }

        UpdateRequest   DianeClient::update_request(const std::string &keyword, const index_type index)
        {
            bool found = false;
            
            UpdateRequest req;
            search_token_key_type st;
            
            // get (and possibly construct) the keyword index
            keyword_index_type kw_index = get_keyword_index(keyword);
            std::string seed(kw_index.begin(),kw_index.end());
            
            // retrieve the counter
            uint32_t kw_counter;
            {
                std::lock_guard<std::mutex> lock(token_map_mtx_);
                found = counter_map_.get(kw_index, kw_counter);
            }

            if (!found) {
                // set the counter to 0
                kw_counter = 0;
                keyword_counter_++;
                
                {
                    std::lock_guard<std::mutex> lock(token_map_mtx_);
                    counter_map_.add(kw_index, 0);
                }
                
            }else{
                // increment and store the counter
                kw_counter++;
                {
                    std::lock_guard<std::mutex> lock(token_map_mtx_);
                    counter_map_.at(kw_index) = kw_counter;
                }

                
                
            }
            
            
            TokenTree::token_type root = root_prf_.prf(kw_index.data(), kw_index.size());

            st = TokenTree::derive_node(root, kw_counter, kTreeDepth);

            logger::log(logger::DBG) << "New ST " << hex_string(st) << std::endl;

            std::array<uint8_t, sizeof(index_type)> mask;
            
            // derive the two parts of the leaf search token
            // it avoids having to use some different IVs to have two different hash functions.
            // it might decrease the security bounds by a few bits, but, meh ...
            crypto::BlockHash::hash(st.data(), 16, req.token.data());
            crypto::BlockHash::hash(st.data()+16, sizeof(index_type), mask.data());

            req.index = xor_mask(index, mask);

            return req;
        }

    }
}

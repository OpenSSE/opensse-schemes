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


#include "diane_server.hpp"

#include <sse/crypto/block_hash.hpp>

namespace sse {
    namespace diane {
        
        DianeServer::DianeServer(const std::string& db_path) :
        edb_(db_path)
        {
        }

        DianeServer::DianeServer(const std::string& db_path, const size_t tm_setup_size) :
        edb_(db_path)
        {
            
        }

        std::list<index_type> DianeServer::search(const SearchRequest& req)
        {
            std::list<index_type> results;
            index_type r;

            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.kw_token);

            for (auto it_token = req.token_list.begin(); it_token != req.token_list.end(); ++it_token) {
                
                logger::log(logger::DBG) << "Search token key: " << hex_string(it_token->key) << std::endl;

                // for now we implement the search algorithm in a naive way:
                // the tokens are iteratively generated using the derive_node function
                // this is not smart as some inner nodes will be recomputed several times.
                // we leave optimizations for later
                
                
                uint64_t count = 1 << it_token->depth;
                
                for (uint64_t i = 0; i < count; i++) {
                    auto t = TokenTree::derive_node(it_token->key, i, it_token->depth);
                    
                    logger::log(logger::DBG) << "Derived leaf token: " << hex_string(t) << std::endl;

                    update_token_type ut;
                    std::array<uint8_t, sizeof(index_type)> mask;

                    // derive the two parts of the leaf search token
                    // it avoids having to use some different IVs to have two different hash functions.
                    // it might decrease the security bounds by a few bits, but, meh ...
                    crypto::BlockHash::hash(t.data(), 16, ut.data());
                    crypto::BlockHash::hash(t.data()+16, sizeof(index_type), mask.data());

                    
                    logger::log(logger::DBG) << "Derived token : " << hex_string(ut) << std::endl;
                    logger::log(logger::DBG) << "Mask : " << hex_string(mask) << std::endl;

                    bool found = edb_.get(ut,r);

                    if (found) {
                        logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
                        
                        r = xor_mask(r, mask);
                        
                        results.push_back(r);
                    }else{
                        logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
                    }

                }
            }
            
            
            return results;
        }
        
        void DianeServer::update(const UpdateRequest& req)
        {
            logger::log(logger::DBG) << "Update: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            
            edb_.put(req.token, req.index);
        }
        
        std::ostream& DianeServer::print_stats(std::ostream& out) const
        {
            return out;
        }

    }
}
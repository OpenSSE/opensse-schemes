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


#include "sophos_client.hpp"


#include "utils/utils.hpp"
#include "utils/logger.hpp"
#include "utils/thread_pool.hpp"

#include <iostream>
#include <algorithm>

namespace sse {
    namespace sophos {
        
        const std::string SophosClient::tdp_sk_file__ = "tdp_sk.key";
        const std::string SophosClient::derivation_key_file__ = "derivation_master.key";
        
        
        const std::string SophosClient::rsa_prg_key_file__ = "rsa_prg.key";
        const std::string SophosClient::counter_map_file__ = "counters.dat";
        
        constexpr size_t SophosClient::kKeywordIndexSize;
        
        SophosClient::SophosClient(const std::string& token_map_path, const std::string& tdp_private_key, crypto::Key<kKeySize>&& derivation_master_key, crypto::Key<kKeySize>&& rsa_prg_key) :
        k_prf_(std::move(derivation_master_key)), inverse_tdp_(tdp_private_key), rsa_prg_(std::move(rsa_prg_key)), counter_map_(token_map_path)
        {
        }
        
        SophosClient::~SophosClient()
        {
            
        }
        
        size_t SophosClient::keyword_count() const
        {
            return counter_map_.approximate_size();
        }
        
        const std::string SophosClient::public_key() const
        {
            return inverse_tdp_.public_key();
        }
        
        const std::string SophosClient::private_key() const
        {
            return inverse_tdp_.private_key();
        }
        
        const crypto::Prf<kDerivationKeySize>& SophosClient::derivation_prf() const
        {
            return k_prf_;
        }
        const sse::crypto::TdpInverse& SophosClient::inverse_tdp() const
        {
            return inverse_tdp_;
        }
        
        std::string SophosClient::get_keyword_index(const std::string &kw) const
        {
            std::string hash_string = crypto::Hash::hash(kw);
            return hash_string.erase(kKeywordIndexSize);
        }
        
        SearchRequest   SophosClient::search_request(const std::string &keyword) const
        {
            uint32_t kw_counter;
            bool found;
            SearchRequest req;
            req.add_count = 0;
            
            std::string seed = get_keyword_index(keyword);
            
            found = counter_map_.get(keyword, kw_counter);
            
            if(!found)
            {
                logger::log(logger::INFO) << "No matching counter found for keyword " << keyword << " (index " << hex_string(seed) << ")" << std::endl;
            }else{
                // Now derive the original search token from the kw_index (as seed)
                req.token = inverse_tdp().generate_array(rsa_prg_, seed);
                req.token = inverse_tdp().invert_mult(req.token, kw_counter);
                
                
                req.derivation_key = derivation_prf().prf(reinterpret_cast<const uint8_t *>(seed.data()), kKeywordIndexSize);
                req.add_count = kw_counter+1;
            }
            
            return req;
        }
        
        
        UpdateRequest   SophosClient::update_request(const std::string &keyword, const index_type index)
        {
            UpdateRequest req;
            search_token_type st;
            
            // get (and possibly construct) the keyword index
            std::string seed = get_keyword_index(keyword);
            
            
            
            // retrieve the counter
            uint32_t kw_counter;
            
            bool success = counter_map_.get_and_increment(keyword, kw_counter);
            
            assert(success);
            
            st = inverse_tdp().generate_array(rsa_prg_, seed);
            
            if (kw_counter==0) {
                logger::log(logger::DBG) << "ST0 " << hex_string(st) << std::endl;
            }else{
                st = inverse_tdp().invert_mult(st, kw_counter);
                
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "New ST " << hex_string(st) << std::endl;
                }
            }
            
            
            auto deriv_key = derivation_prf().prf(reinterpret_cast<const uint8_t *>(seed.data()), kKeywordIndexSize);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Derivation key: " << hex_string(deriv_key) << std::endl;
            }
            
            std::array<uint8_t, kUpdateTokenSize> mask;
            
            gen_update_token_masks(crypto::Prf<kUpdateTokenSize>(deriv_key.data()), st.data(), req.token,mask);
            req.index = xor_mask(index, mask);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Update token: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            }
            
            return req;
        }
        
        std::ostream& SophosClient::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << keyword_count() << std::endl;
            
            return out;
        }

        /*
        void SophosClient::write_keys(const std::string& dir_path) const
        {
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string sk_path = dir_path + "/" + tdp_sk_file__;
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            
            std::ofstream sk_out(sk_path.c_str());
            if (!sk_out.is_open()) {
                throw std::runtime_error(sk_path + ": unable to write the secret key");
            }
            
            sk_out << private_key();
            sk_out.close();
            
            std::ofstream master_key_out(master_key_path.c_str());
            if (!master_key_out.is_open()) {
                throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
            }
            
            master_key_out << master_derivation_key();
            master_key_out.close();
            
            std::string rsa_prg_key_path = dir_path + "/" + rsa_prg_key_file__;
            
            std::ofstream rsa_prg_key_out(rsa_prg_key_path.c_str());
            if (!rsa_prg_key_out.is_open()) {
                throw std::runtime_error(rsa_prg_key_path + ": unable to write the rsa prg key");
            }
            
            rsa_prg_key_out << rsa_prg_key();
            rsa_prg_key_out.close();
        }
         */
    }
}

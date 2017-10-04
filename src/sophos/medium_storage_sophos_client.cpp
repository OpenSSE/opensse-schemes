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


#include "medium_storage_sophos_client.hpp"
#include "utils/utils.hpp"
#include "utils/logger.hpp"


#include <sse/dbparser/rapidjson/rapidjson.h>
#include <sse/dbparser/rapidjson/writer.h>
#include <sse/dbparser/rapidjson/prettywriter.h>
#include <sse/dbparser/rapidjson/filewritestream.h>
#include <sse/dbparser/rapidjson/filereadstream.h>
#include <sse/dbparser/rapidjson/ostreamwrapper.h>
#include <sse/dbparser/rapidjson/document.h>


#define DERIVATION_KEY "derivation"
#define TDP_KEY "tdp_pk"
#define RSA_PRG_KEY "rsa_prg"
#define TOKEN_KEY "tokens"
#define TOKEN_MAP_SIZE_KEY "map_size"


namespace sse {
    namespace sophos {
        
        
        size_t MediumStorageSophosClient::IndexHasher::operator()(const keyword_index_type& index) const
        {
            size_t h = 0;
            for (size_t i = 0; i < index.size(); i++) {
                if (i > 0) {
                    h <<= 8;
                }
                h = index[i] + h;
            }
            return h;
        }

        
        const std::string MediumStorageSophosClient::rsa_prg_key_file__ = "rsa_prg.key";
        const std::string MediumStorageSophosClient::counter_map_file__ = "counters.dat";

        std::unique_ptr<SophosClient> MediumStorageSophosClient::construct_from_directory(const std::string& dir_path)
        {
            // try to initialize everything from this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string sk_path = dir_path + "/" + tdp_sk_file__;
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            std::string counter_map_path = dir_path + "/" + counter_map_file__;
            std::string rsa_prg_key_path = dir_path + "/" + rsa_prg_key_file__;
            
            if (!is_file(sk_path)) {
                // error, the secret key file is not there
                throw std::runtime_error("Missing secret key file");
            }
            if (!is_file(master_key_path)) {
                // error, the derivation key file is not there
                throw std::runtime_error("Missing master derivation key file");
            }
            if (!is_file(rsa_prg_key_path)) {
                // error, the rsa prg key file is not there
                throw std::runtime_error("Missing rsa prg key file");
            }
            if (!is_directory(counter_map_path)) {
                // error, the token map data is not there
                throw std::runtime_error("Missing token data");
            }
            
            std::ifstream sk_in(sk_path.c_str());
            std::ifstream master_key_in(master_key_path.c_str());
            std::ifstream rsa_prg_key_in(rsa_prg_key_path.c_str());
            std::stringstream sk_buf, master_key_buf, rsa_prg_key_buf;
            
            sk_buf << sk_in.rdbuf();
            master_key_buf << master_key_in.rdbuf();
            rsa_prg_key_buf << rsa_prg_key_in.rdbuf();
            
            return std::unique_ptr<SophosClient>(new  MediumStorageSophosClient(counter_map_path, sk_buf.str(), master_key_buf.str(), rsa_prg_key_buf.str()));
        }
        
        
        std::unique_ptr<SophosClient> MediumStorageSophosClient::init_in_directory(const std::string& dir_path, uint32_t n_keywords)
        {
            // try to initialize everything in this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string counter_map_path = dir_path + "/" + counter_map_file__;
            
            auto c_ptr =  std::unique_ptr<SophosClient>(new MediumStorageSophosClient(counter_map_path, n_keywords));
            
            c_ptr->write_keys(dir_path);

            return c_ptr;
        }

        MediumStorageSophosClient::MediumStorageSophosClient(const std::string& token_map_path, const size_t tm_setup_size) :
        SophosClient(), rsa_prg_(), counter_map_(token_map_path)
        {
        }
        
        MediumStorageSophosClient::MediumStorageSophosClient(const std::string& token_map_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key) :
        SophosClient(tdp_private_key, derivation_master_key), rsa_prg_(rsa_prg_key), counter_map_(token_map_path)
        {
        }
        
        MediumStorageSophosClient::MediumStorageSophosClient(const std::string& token_map_path, const std::string& tdp_private_key, const std::string& derivation_master_key, const std::string& rsa_prg_key, const size_t tm_setup_size) :
        SophosClient(tdp_private_key, derivation_master_key), rsa_prg_(rsa_prg_key), counter_map_(token_map_path)
        {
        }
        
        
        MediumStorageSophosClient::~MediumStorageSophosClient()
        {
        }
        
        size_t MediumStorageSophosClient::keyword_count() const
        {
            return counter_map_.approximate_size();
        }
        
        MediumStorageSophosClient::keyword_index_type MediumStorageSophosClient::get_keyword_index(const std::string &kw) const
        {
            std::string hash_string = crypto::Hash::hash(kw);
            
            keyword_index_type ret;
            std::copy_n(hash_string.begin(), kKeywordIndexSize, ret.begin());
            
            return ret;
        }
        
        SearchRequest   MediumStorageSophosClient::search_request(const std::string &keyword) const
        {
            uint32_t kw_counter;
            bool found;
            SearchRequest req;
            req.add_count = 0;
            
            keyword_index_type kw_index = get_keyword_index(keyword);
            std::string seed(kw_index.begin(),kw_index.end());
            
            found = counter_map_.get(keyword, kw_counter);
            
            if(!found)
            {
                logger::log(logger::INFO) << "No matching counter found for keyword " << keyword << " (index " << hex_string(seed) << ")" << std::endl;
            }else{
                // Now derive the original search token from the kw_index (as seed)
                req.token = inverse_tdp().generate_array(rsa_prg_, seed);
                req.token = inverse_tdp().invert_mult(req.token, kw_counter);
                
                
                req.derivation_key = derivation_prf().prf_string(seed);
                req.add_count = kw_counter+1;
            }
            
            return req;
        }
        
        
        UpdateRequest   MediumStorageSophosClient::update_request(const std::string &keyword, const index_type index)
        {
            UpdateRequest req;
            search_token_type st;
            
            // get (and possibly construct) the keyword index
            keyword_index_type kw_index = get_keyword_index(keyword);
            std::string seed(kw_index.begin(),kw_index.end());

            
            
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

            
            std::string deriv_key = derivation_prf().prf_string(seed);

            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Derivation key: " << hex_string(deriv_key) << std::endl;
            }
            
            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
            
            std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
            
            req.token = derivation_prf.prf(st_string + '0');
            req.index = xor_mask(index, derivation_prf.prf(st_string + '1'));
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Update token: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            }
            
            return req;
        }
        
        std::string MediumStorageSophosClient::rsa_prg_key() const
        {
            return std::string(rsa_prg_.key().begin(), rsa_prg_.key().end());
        }

        void MediumStorageSophosClient::write_keys(const std::string& dir_path) const
        {
            SophosClient::write_keys(dir_path);

            std::string rsa_prg_key_path = dir_path + "/" + rsa_prg_key_file__;

            std::ofstream rsa_prg_key_out(rsa_prg_key_path.c_str());
            if (!rsa_prg_key_out.is_open()) {
                throw std::runtime_error(rsa_prg_key_path + ": unable to write the rsa prg key");
            }
            
            rsa_prg_key_out << rsa_prg_key();
            rsa_prg_key_out.close();
            
        }

        std::ostream& MediumStorageSophosClient::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << keyword_count() << std::endl;
            
            return out;
        }
    }
}

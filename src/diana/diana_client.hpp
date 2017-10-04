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


#pragma once


#include "token_tree.hpp"
#include "types.hpp"

#include "diana_common.hpp"

#include "utils/rocksdb_wrapper.hpp"
#include "utils/utils.hpp"
#include "utils/logger.hpp"

#include <sse/crypto/block_hash.hpp>

#include <sse/dbparser/rapidjson/rapidjson.h>
#include <sse/dbparser/rapidjson/writer.h>
#include <sse/dbparser/rapidjson/prettywriter.h>
#include <sse/dbparser/rapidjson/filewritestream.h>
#include <sse/dbparser/rapidjson/filereadstream.h>
#include <sse/dbparser/rapidjson/ostreamwrapper.h>
#include <sse/dbparser/rapidjson/document.h>

#include <sse/crypto/prf.hpp>

namespace sse {
    namespace diana {
        
        template <typename T>
        class DianaClient {
        public:
            static constexpr size_t kKeywordIndexSize = 16;
            typedef std::array<uint8_t, kKeywordIndexSize> keyword_index_type;
            typedef T index_type;

            static constexpr size_t kTreeDepth = 48;
            
            DianaClient(const std::string& token_map_path);
            DianaClient(const std::string& token_map_path, const std::string& derivation_master_key, const std::string& kw_token_master_key);
            ~DianaClient();

            size_t keyword_count() const;
            
            const std::string master_derivation_key() const;
            const std::string kw_token_master_key() const;
            
            keyword_index_type get_keyword_index(const std::string &kw) const;

            uint32_t get_match_count(const std::string &kw) const;

            SearchRequest       search_request(const std::string &keyword, bool log_not_found = true) const;
            UpdateRequest<T>    update_request(const std::string &keyword, const index_type index);
            std::list<UpdateRequest<T>>   bulk_update_request(const std::list<std::pair<std::string, index_type>> &update_list);

            bool remove_keyword(const std::string &kw);

//            SearchRequest   search_request_index(const keyword_index_type &kw_index) const;
//            SearchRequest   random_search_request() const;

            std::ostream& print_stats(std::ostream& out) const;
            
            const crypto::Prf<kSearchTokenKeySize>& root_prf() const;
            const crypto::Prf<kKeywordTokenSize>& kw_token_prf() const;
            
            static const std::string derivation_keys_file__;
            
            struct IndexHasher
            {
            public:
                inline size_t operator()(const keyword_index_type& index) const
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

            };

        private:

            std::list<std::tuple<std::string, T, uint32_t>>   get_counters_and_increment(const std::list<std::pair<std::string, index_type>> &update_list);

            crypto::Prf<kSearchTokenKeySize> root_prf_;
            crypto::Prf<kKeywordTokenSize> kw_token_prf_;
            
            
            sophos::RocksDBCounter counter_map_;
            std::atomic_uint keyword_counter_;
        };
        
        

    }
}


namespace sse {
    namespace diana {
        
        template <typename T>
        DianaClient<T>::DianaClient(const std::string& token_map_path) :
        root_prf_(), kw_token_prf_(), counter_map_(token_map_path)
        {
            
        }
        
        template <typename T>
        DianaClient<T>::DianaClient(const std::string& token_map_path, const std::string& derivation_master_key, const std::string& kw_token_master_key) :
        root_prf_(derivation_master_key), kw_token_prf_(kw_token_master_key), counter_map_(token_map_path)
        {
            
        }
        
        template <typename T>
        DianaClient<T>::~DianaClient()
        {
            
        }
        
        
        template <typename T>
        const std::string DianaClient<T>::master_derivation_key() const
        {
            return std::string(root_prf_.key().begin(), root_prf_.key().end());
        }
        
        template <typename T>
        const std::string DianaClient<T>::kw_token_master_key() const
        {
            return std::string(kw_token_prf_.key().begin(), kw_token_prf_.key().end());
        }
        
        
        template <typename T>
        typename DianaClient<T>::keyword_index_type DianaClient<T>::get_keyword_index(const std::string &kw) const
        {
            std::string hash_string = crypto::Hash::hash(kw);
            
            keyword_index_type ret;
            std::copy_n(hash_string.begin(), kKeywordIndexSize, ret.begin());
            
            return ret;
        }

        template <typename T>
        uint32_t DianaClient<T>::get_match_count(const std::string &kw) const
        {
            uint32_t kw_counter;

            bool found = counter_map_.get(kw, kw_counter);
            
            return (found) ? kw_counter : 0;
        }
        

        template <typename T>
        SearchRequest   DianaClient<T>::search_request(const std::string &keyword, bool log_not_found) const
        {
            keyword_index_type kw_index = get_keyword_index(keyword);
            
            bool found;
            uint32_t kw_counter;
            SearchRequest req;
            req.add_count = 0;
            
            found = counter_map_.get(keyword, kw_counter);
            
            if(!found)
            {
                if (log_not_found) {
                    logger::log(logger::INFO) << "No matching counter found for keyword " << hex_string(std::string(kw_index.begin(),kw_index.end())) << std::endl;
                }
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
        
        template <typename T>
        UpdateRequest<T>   DianaClient<T>::update_request(const std::string &keyword, const index_type index)
        {
            UpdateRequest<T> req;
            search_token_key_type st;
            index_type mask;
            
            // get (and possibly construct) the keyword index
            keyword_index_type kw_index = get_keyword_index(keyword);
            std::string seed(kw_index.begin(),kw_index.end());
            
            // retrieve the counter
            uint32_t kw_counter;
            
            bool success = counter_map_.get_and_increment(keyword, kw_counter);
            
            assert(success);
            
            TokenTree::token_type root = root_prf_.prf(kw_index.data(), kw_index.size());
            
            st = TokenTree::derive_node(root, kw_counter, kTreeDepth);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "New ST " << hex_string(st) << std::endl;
            }
            
            
            gen_update_token_mask(st, req.token, mask);
            
            req.index = xor_mask(index,mask);
            
            //            if (logger::severity() <= logger::DBG) {
            //                logger::log(logger::DBG) << "Update Request: (" << hex_string(ut) << ", " << std::hex << req.index << ")" << std::endl;
            //            }
            
            return req;
        }
 
        template <typename T>
        std::list<UpdateRequest<T>>   DianaClient<T>::bulk_update_request(const std::list<std::pair<std::string, index_type>> &update_list)
        {
            std::string keyword;
            index_type index;
            
            std::list<UpdateRequest<T>> req_list;
            
            std::list<std::tuple<std::string, T, uint32_t>> counter_list = get_counters_and_increment(update_list);

            for (auto it = counter_list.begin(); it != counter_list.end(); ++it) {
                
                keyword = std::get<0>(*it);
                index = std::get<1>(*it);
                UpdateRequest<T> req;
                search_token_key_type st;
                index_type mask;
                
                // get (and possibly construct) the keyword index
                keyword_index_type kw_index = get_keyword_index(keyword);
                std::string seed(kw_index.begin(),kw_index.end());
                
                // retrieve the counter
                uint32_t kw_counter = std::get<2>(*it);
                
                
                TokenTree::token_type root = root_prf_.prf(kw_index.data(), kw_index.size());
                
                st = TokenTree::derive_node(root, kw_counter, kTreeDepth);
                
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "New ST " << hex_string(st) << std::endl;
                }
                
                
                gen_update_token_mask(st, req.token, mask);
                
                req.index = xor_mask(index, mask);
                
                req_list.push_back(req);
            }
            
            return req_list;
        }
        
        template <typename T>
        std::list<std::tuple<std::string, T, uint32_t>>   DianaClient<T>::get_counters_and_increment(const std::list<std::pair<std::string, index_type>> &update_list)
        {
            std::string keyword;
            index_type index;
            
            std::list<std::tuple<std::string, index_type, uint32_t>> res;
            
            
            for (auto it = update_list.begin(); it != update_list.end(); ++it) {
                
                
                
                keyword = it->first;
                index = it->second;
 
                // retrieve the counter
                uint32_t kw_counter;
                bool success = counter_map_.get_and_increment(keyword, kw_counter);
                
                assert(success);
                
                res.push_back({keyword, index, kw_counter});

            }
            
            return res;
        }
        
        template <typename T>
        bool DianaClient<T>::remove_keyword(const std::string &kw)
        {
            return counter_map_.remove_key(kw);
        }
        
        template <typename T>
        std::ostream& DianaClient<T>::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << keyword_count() << std::endl;
           
            return out;
        }
        
        template <typename T>
        size_t DianaClient<T>::keyword_count() const
        {
            return counter_map_.approximate_size();
        }

    }
}

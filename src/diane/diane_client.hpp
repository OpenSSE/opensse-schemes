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

#include "diane_common.hpp"

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

#include <ssdmap/bucket_map.hpp>

namespace sse {
    namespace diane {
        
        template <typename T>
        class DianeClient {
        public:
            static constexpr size_t kKeywordIndexSize = 16;
            typedef std::array<uint8_t, kKeywordIndexSize> keyword_index_type;
            typedef T index_type;

            static constexpr size_t kTreeDepth = 48;
            
            DianeClient(const std::string& token_map_path, const size_t tm_setup_size);
            DianeClient(const std::string& token_map_path, const std::string& derivation_master_key, const std::string& kw_token_master_key);
            ~DianeClient();

            size_t keyword_count() const;
            
            const std::string master_derivation_key() const;
            const std::string kw_token_master_key() const;
            
            keyword_index_type get_keyword_index(const std::string &kw) const;

            SearchRequest       search_request(const std::string &keyword) const;
            UpdateRequest<T>    update_request(const std::string &keyword, const index_type index);
            std::list<UpdateRequest<T>>   bulk_update_request(const std::list<std::pair<std::string, index_type>> &update_list);


            SearchRequest   search_request_index(const keyword_index_type &kw_index) const;
            SearchRequest   random_search_request() const;

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
            
            
            ssdmap::bucket_map< keyword_index_type, uint32_t, IndexHasher> counter_map_;
            std::mutex token_map_mtx_;
            std::atomic_uint keyword_counter_;
        };
        
        

    }
}


namespace sse {
    namespace diane {
        
        template <typename T>
        DianeClient<T>::DianeClient(const std::string& token_map_path, const size_t tm_setup_size) :
        root_prf_(), kw_token_prf_(), counter_map_(token_map_path, tm_setup_size)
        {
            
        }
        
        template <typename T>
        DianeClient<T>::DianeClient(const std::string& token_map_path, const std::string& derivation_master_key, const std::string& kw_token_master_key) :
        root_prf_(derivation_master_key), kw_token_prf_(kw_token_master_key), counter_map_(token_map_path)
        {
            
        }
        
        template <typename T>
        DianeClient<T>::~DianeClient()
        {
            
        }
        
        
        template <typename T>
        size_t DianeClient<T>::keyword_count() const
        {
            return counter_map_.size();
        }
        
        template <typename T>
        const std::string DianeClient<T>::master_derivation_key() const
        {
            return std::string(root_prf_.key().begin(), root_prf_.key().end());
        }
        
        template <typename T>
        const std::string DianeClient<T>::kw_token_master_key() const
        {
            return std::string(kw_token_prf_.key().begin(), kw_token_prf_.key().end());
        }
        
        
        template <typename T>
        typename DianeClient<T>::keyword_index_type DianeClient<T>::get_keyword_index(const std::string &kw) const
        {
            std::string hash_string = crypto::Hash::hash(kw);
            
            keyword_index_type ret;
            std::copy_n(hash_string.begin(), kKeywordIndexSize, ret.begin());
            
            return ret;
        }
        
        template <typename T>
        SearchRequest   DianeClient<T>::search_request(const std::string &keyword) const
        {
            keyword_index_type kw_index = get_keyword_index(keyword);
            
            return search_request_index(kw_index);
        }
        
        
        template <typename T>
        SearchRequest   DianeClient<T>::random_search_request() const
        {
            SearchRequest req;
            req.add_count = 0;
            
            auto rnd_elt = counter_map_.random_element();
            
            keyword_index_type kw_index = rnd_elt.first;
            
            return search_request_index(kw_index);
        }
        
        template <typename T>
        SearchRequest   DianeClient<T>::search_request_index(const keyword_index_type &kw_index) const
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
        
        template <typename T>
        UpdateRequest<T>   DianeClient<T>::update_request(const std::string &keyword, const index_type index)
        {
            bool found = false;
            
            UpdateRequest<T> req;
            search_token_key_type st;
            index_type mask;
            
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
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "New ST " << hex_string(st) << std::endl;
            }
            
            
            gen_update_token_mask(st, req.token, mask);
            
            req.index = index^mask;
            
            //            if (logger::severity() <= logger::DBG) {
            //                logger::log(logger::DBG) << "Update Request: (" << hex_string(ut) << ", " << std::hex << req.index << ")" << std::endl;
            //            }
            
            return req;
        }
        
/*
        template <typename T>
        std::list<UpdateRequest<T>>   DianeClient<T>::bulk_update_request(const std::list<std::pair<std::string, index_type>> &update_list)
        {
            std::string keyword;
            index_type index;
            
            std::list<UpdateRequest<T>> req_list;
            
            token_map_mtx_.lock();
            
            for (auto it = update_list.begin(); it != update_list.end(); ++it) {
                
                bool found = false;
                
                
                keyword = it->first;
                index = it->second;
                UpdateRequest<T> req;
                search_token_key_type st;
                index_type mask;
                
                // get (and possibly construct) the keyword index
                keyword_index_type kw_index = get_keyword_index(keyword);
                std::string seed(kw_index.begin(),kw_index.end());
                
                // retrieve the counter
                uint32_t kw_counter;
                
                found = counter_map_.get(kw_index, kw_counter);
                
                if (!found) {
                    // set the counter to 0
                    kw_counter = 0;
                    keyword_counter_++;
                    
                    counter_map_.add(kw_index, 0);
                    
                }else{
                    // increment and store the counter
                    kw_counter++;
                    counter_map_.at(kw_index) = kw_counter;
                }
                
                
                TokenTree::token_type root = root_prf_.prf(kw_index.data(), kw_index.size());
                
                st = TokenTree::derive_node(root, kw_counter, kTreeDepth);
                
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "New ST " << hex_string(st) << std::endl;
                }
                
                
                gen_update_token_mask(st, req.token, mask);
                
                req.index = xor_mask(index, mask);
                
                req_list.push_back(req);
            }
            token_map_mtx_.unlock();
            
            return req_list;
        }
        */
        
        template <typename T>
        std::list<UpdateRequest<T>>   DianeClient<T>::bulk_update_request(const std::list<std::pair<std::string, index_type>> &update_list)
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
        std::list<std::tuple<std::string, T, uint32_t>>   DianeClient<T>::get_counters_and_increment(const std::list<std::pair<std::string, index_type>> &update_list)
        {
            std::string keyword;
            index_type index;
            
            std::list<std::tuple<std::string, index_type, uint32_t>> res;
            
            token_map_mtx_.lock();
            
            for (auto it = update_list.begin(); it != update_list.end(); ++it) {
                
                bool found = false;
                
                
                keyword = it->first;
                index = it->second;
                
                // get (and possibly construct) the keyword index
                keyword_index_type kw_index = get_keyword_index(keyword);
                
                // retrieve the counter
                uint32_t kw_counter;
                
                found = counter_map_.get(kw_index, kw_counter);
                
                if (!found) {
                    // set the counter to 0
                    kw_counter = 0;
                    keyword_counter_++;
                    
                    counter_map_.add(kw_index, 0);
                    
                }else{
                    // increment and store the counter
                    kw_counter++;
                    counter_map_.at(kw_index) = kw_counter;
                }
                
                res.push_back({keyword, index, kw_counter});

            }
            token_map_mtx_.unlock();
            
            return res;
        }
        

        
        template <typename T>
        std::ostream& DianeClient<T>::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << counter_map_.size();
            out << "; Load: " << counter_map_.load();
            out << "; Overflow bucket size: " << counter_map_.overflow_size() << std::endl;
            
            return out;
        }
        
    }
}

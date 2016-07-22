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

#include "thread_pool.hpp"

#include <sse/crypto/block_hash.hpp>

#define MIN(a,b) (((a) > (b)) ? (b) : (a))
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

            auto callback = [&results](index_type i)
            {
                results.push_back(i);
            };
            
            search(req, callback);
            
            return results;
        }

        void DianeServer::search(const SearchRequest& req, std::function<void(index_type)> post_callback)
        {
            index_type r;
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Expected matches: " << req.add_count << std::endl;
                logger::log(logger::DBG) << "Number of search nodes: " << req.token_list.size() << std::endl;
            }
            
            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(&req.kw_token);
            
            for (auto it_token = req.token_list.begin(); it_token != req.token_list.end(); ++it_token) {
                
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "Search token key: " << hex_string(it_token->first) << std::endl;
                    logger::log(logger::DBG) << "Search token depth: " << std::dec << (uint32_t)(it_token->second) << std::endl;
                }
                
                // for now we implement the search algorithm in a naive way:
                // the tokens are iteratively generated using the derive_node function
                // this is not smart as some inner nodes will be recomputed several times.
                // we leave optimizations for later
                
                
                uint64_t count = 1 << it_token->second;
                
                for (uint64_t i = 0; i < count; i++) {
                    auto t = TokenTree::derive_node(it_token->first, i, it_token->second);
                    
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Derived leaf token: " << hex_string(t) << std::endl;
                    }
                    
                    update_token_type ut;
                    std::array<uint8_t, sizeof(index_type)> mask;
                    
                    // derive the two parts of the leaf search token
                    // it avoids having to use some different IVs to have two different hash functions.
                    // it might decrease the security bounds by a few bits, but, meh ...
                    crypto::BlockHash::hash(t.data(), 16, ut.data());
                    crypto::BlockHash::hash(t.data()+16, sizeof(index_type), mask.data());
                    
                    
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Derived token : " << hex_string(ut) << std::endl;
                        logger::log(logger::DBG) << "Mask : " << hex_string(mask) << std::endl;
                    }
                    
                    bool found = edb_.get(ut,r);
                    
                    if (found) {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
                        }
                        
                        r = xor_mask(r, mask);
                        
                        post_callback(r);
                    }else{
                        logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
                    }
                    
                }
            }
        }

        std::list<index_type> DianeServer::search_parallel(const SearchRequest& req, uint8_t derivation_threads_count,uint8_t access_threads_count)
        {
            std::list<index_type> results;
            std::mutex list_mutex;
            
            auto callback = [&results, &list_mutex](index_type i)
            {
                list_mutex.lock();
                results.push_back(i);
                list_mutex.unlock();
            };
            
            search_parallel(req, callback, derivation_threads_count, access_threads_count);
            
            return results;
        }
        

        void DianeServer::search_parallel(const SearchRequest& req, std::function<void(index_type)> post_callback, uint8_t derivation_threads_count,uint8_t access_threads_count)
        {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Expected matches: " << req.add_count << std::endl;
                logger::log(logger::DBG) << "Number of search nodes: " << req.token_list.size() << std::endl;
            }
            
            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(&req.kw_token);
            
            ThreadPool access_pool(access_threads_count);
            ThreadPool derive_pool(derivation_threads_count);


            auto lookup_job = [this, &post_callback](const update_token_type &ut, const std::array<uint8_t, sizeof(index_type)> &mask)
            {
                index_type r;
                
                
                bool found = edb_.get(ut,r);
                
                if (found) {
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
                    }
                    
                    post_callback(xor_mask(r, mask));
                }else{
                    logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
                }
            };
            
            std::function<void(TokenTree::token_type, uint8_t)> derive_job = [&derive_job, &access_pool, &lookup_job, &derive_pool](TokenTree::token_type t, uint8_t d)
            {
                TokenTree::token_type st = TokenTree::derive_leftmost_node(t, d, derive_job);
                
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "Derived leaf token: " << hex_string(st) << std::endl;
                }
                
                // apply the hash function
                
                // derive the two parts of the leaf search token
                // it avoids having to use some different IVs to have two different hash functions.
                // it might decrease the security bounds by a few bits, but, meh ...
                update_token_type ut;
                std::array<uint8_t, sizeof(index_type)> mask;

                crypto::BlockHash::hash(st.data(), 16, ut.data());
                crypto::BlockHash::hash(st.data()+16, sizeof(index_type), mask.data());
                
                
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "Derived token : " << hex_string(ut) << std::endl;
                    logger::log(logger::DBG) << "Mask : " << hex_string(mask) << std::endl;
                }
                
                access_pool.enqueue(lookup_job, ut, mask);

            };
            
            
            
            
            for (auto it_token = req.token_list.begin(); it_token != req.token_list.end(); ++it_token) {
                
                if (logger::severity() <= logger::DBG) {
                    logger::log(logger::DBG) << "Search token key: " << hex_string(it_token->first) << std::endl;
                    logger::log(logger::DBG) << "Search token depth: " << std::dec << (uint32_t)(it_token->second) << std::endl;
                }
                
                // post the derivation job
                
                derive_pool.enqueue(derive_job, it_token->first, it_token->second);
            }
            
            // wait for the pools to finish
            derive_pool.join();
            access_pool.join();
        }

        std::list<index_type> DianeServer::search_simple_parallel(const SearchRequest& req, uint8_t threads_count)
        {
            assert(threads_count > 0);
            
            
            // use one result list per thread so to avoid using locks
            std::list<index_type> *result_lists = new std::list<index_type>[threads_count];
            
            auto callback = [&result_lists](index_type i, uint8_t thread_id)
            {
                result_lists[thread_id].push_back(i);
            };
            
            search_simple_parallel(req, callback, threads_count);
            
            // merge the result lists
            std::list<index_type> results(std::move(result_lists[0]));
            for (uint8_t i = 1; i < threads_count; i++) {
                results.splice(results.end(), result_lists[i]);
            }
            
            delete []  result_lists;
            
            return results;
        }

        void DianeServer::search_simple_parallel(const SearchRequest& req, std::function<void(index_type)> post_callback, uint8_t threads_count)
        {
            auto aux = [&post_callback](index_type ind, uint8_t i)
            {
                post_callback(ind);
            };
            search_simple_parallel(req, aux, threads_count);
        }
        
        void DianeServer::search_simple_parallel(const SearchRequest& req, std::function<void(index_type, uint8_t)> post_callback, uint8_t threads_count)
        {
            auto job = [this, &post_callback](const uint8_t t_id, const SearchRequest& req, const uint64_t min_index, const uint64_t max_index)
            {
                uint64_t loc_min_index = min_index;
                uint64_t loc_max_index = max_index;
                
                // find the starting token
                uint64_t leaf_count = 0;
                
                auto key_it = req.token_list.begin();
                
                do{
                    // this is the number of leafs for the current node
                    leaf_count = (1UL << key_it->second);

                    if((leaf_count > loc_min_index))
                    {
                        // the selected leaf does not cover the minimum index
                        break;
                    }

                    // update the local index counters
                    loc_min_index -= leaf_count; // no underflow:
                    loc_max_index -= leaf_count; // leaf_count <= loc_min_index <= loc_max_index

                    // get the next tree node
                    ++key_it;
                }while((key_it != req.token_list.end()));
                
                if (key_it == req.token_list.end()) {
                    logger::log(logger::ERROR) << "Out of Bounds!" << std::endl;
                    return;
                }
                
                index_type r;
                update_token_type ut;
                TokenTree::token_type t;
                
                for (size_t i = loc_min_index; i <= loc_max_index; i++) {
                    // check that i is still in the span of the current node
                    if (leaf_count <= i) {
                        // we are out of the span of this node
                        i -= leaf_count;
                        loc_max_index -= leaf_count;
                        
                        ++key_it;
                        if (key_it == req.token_list.end()) {
                            logger::log(logger::ERROR) << "Out of Bounds!" << std::endl;
                            break;
                        }
                        leaf_count = (1UL << key_it->second);
                    }
                    
                    // ok, now we are sure that i is in the span.
                    // do a regular leaf derivation
                    t = TokenTree::derive_node(key_it->first, i, key_it->second);

                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Derived leaf token: " << hex_string(t) << std::endl;
                    }
                    
                    std::array<uint8_t, sizeof(index_type)> mask;
                    
                    // derive the two parts of the leaf search token
                    // it avoids having to use some different IVs to have two different hash functions.
                    // it might decrease the security bounds by a few bits, but, meh ...
                    crypto::BlockHash::hash(t.data(), 16, ut.data());
                    crypto::BlockHash::hash(t.data()+16, sizeof(index_type), mask.data());
                    
                    
                    if (logger::severity() <= logger::DBG) {
                        logger::log(logger::DBG) << "Derived token : " << hex_string(ut) << std::endl;
                        logger::log(logger::DBG) << "Mask : " << hex_string(mask) << std::endl;
                    }
                    
                    bool found = edb_.get(ut,r);
                    
                    if (found) {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
                        }
                        
                        r = xor_mask(r, mask);
                        
                        post_callback(r, t_id);
                    }else{
                        logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
                    }

                }
            };
            
            std::vector<std::thread> threads;

            size_t step = req.add_count/threads_count;
            size_t remaining = req.add_count % threads_count;

            size_t min = 0;
            size_t max = step;

            for (uint8_t t = 0; t < threads_count; t++) {
                
                if (t < remaining) {
                    max++;
                }
                                
                threads.push_back(std::thread(job, t, req, min, MIN(max, req.add_count)-1));
                
                min = max;
                max += step;
            }
            
            for (uint8_t t = 0; t < threads_count; t++) {
                threads[t].join();
            }

        }
        
        void DianeServer::update(const UpdateRequest& req)
        {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Update: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            }
            
            edb_.put(req.token, req.index);
        }
        
        std::ostream& DianeServer::print_stats(std::ostream& out) const
        {
            return out;
        }

    }
}
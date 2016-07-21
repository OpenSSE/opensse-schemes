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


#include "db_generator.hpp"
#include "logger.hpp"

#include <sse/crypto/fpe.hpp>

#include <string>
#include <thread>
#include <vector>
#include <iostream>

namespace sse {
    namespace sophos {

        const std::string kKeyword01PercentBase    = "0.1";
        const std::string kKeyword1PercentBase     = "1";
        const std::string kKeyword10PercentBase    = "10";

        const std::string kKeywordGroupBase      = "Group-";
        const std::string kKeyword10GroupBase    = kKeywordGroupBase + "10^";

        constexpr uint32_t max_10_counter = ~0;
        
        static void generation_job(unsigned int thread_id, size_t N_entries, size_t step, crypto::Fpe *rnd_perm, std::atomic_size_t *entries_counter, std::function<void(const std::string &, size_t)> callback)
        {
            size_t counter = thread_id;
            std::string id_string = std::to_string(thread_id);
            
            uint32_t counter_10_1 = 0, counter_20 = 0, counter_30 = 0, counter_60 = 0, counter_10_2 = 0, counter_10_3 = 0, counter_10_4 = 0, counter_10_5 = 0;
            
            std::string keyword_01, keyword_1, keyword_10;
            std::string kw_10_1, kw_10_2, kw_10_3, kw_10_4, kw_10_5, kw_20, kw_30, kw_60;
            
            for (size_t i = 0; counter < N_entries; counter += step, i++) {
                size_t ind = rnd_perm->encrypt_64(counter);
                
                uint32_t ind_01 = ind % 1000;
                uint32_t ind_1  = ind_01 % 100;
                uint32_t ind_10 = ind_1 % 10;
                
                keyword_01  = kKeyword01PercentBase    + "_" + std::to_string(ind_01)   + "_1";
                keyword_1   = kKeyword1PercentBase     + "_" + std::to_string(ind_1)    + "_1";
                keyword_10  = kKeyword10PercentBase    + "_" + std::to_string(ind_10)   + "_1";
                
                callback(keyword_01, ind);
                callback(keyword_1, ind);
                callback(keyword_10, ind);
                
                ind_01 = (ind/1000) % 1000;
                ind_1  = ind_01 % 100;
                ind_10 = ind_1 % 10;
                
                keyword_01  = kKeyword01PercentBase    + "_" + std::to_string(ind_01)   + "_2";
                keyword_1   = kKeyword1PercentBase     + "_" + std::to_string(ind_1)    + "_2";
                keyword_10  = kKeyword10PercentBase    + "_" + std::to_string(ind_10)   + "_2";
                
                callback(keyword_01, ind);
                callback(keyword_1, ind);
                callback(keyword_10, ind);

                ind_01 = (ind/((unsigned int)1e6)) % 1000;
                ind_1  = ind_01 % 100;
                ind_10 = ind_1 % 10;
                
                keyword_01  = kKeyword01PercentBase    + "_" + std::to_string(ind_01)   + "_3";
                keyword_1   = kKeyword1PercentBase     + "_" + std::to_string(ind_1)    + "_3";
                keyword_10  = kKeyword10PercentBase    + "_" + std::to_string(ind_10)   + "_3";
                
//                client->async_update(keyword_01, ind);
//                client->async_update(keyword_1, ind);
//                client->async_update(keyword_10, ind);

                
                if (counter_10_1 < max_10_counter) {
                    kw_10_1 = kKeyword10GroupBase  + "1_" + id_string + "_" + std::to_string(counter_10_1);
                    
                    if((i+1)%10 == 0)
                    {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_1 << std::endl;
                        }
                        counter_10_1++;
                    }
                }
                if (counter_20 < max_10_counter) {
                    kw_20 = kKeywordGroupBase  + "20_" + id_string + "_" + std::to_string(counter_20);
                    
                    if((i+1)%20 == 0)
                    {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_20 << std::endl;
                        }
                        counter_20++;
                    }
                }
                if (counter_30 < max_10_counter) {
                    kw_30 = kKeywordGroupBase  + "30_" + id_string + "_" + std::to_string(counter_30);
                    
                    if((i+1)%30 == 0)
                    {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_30 << std::endl;
                        }
                        counter_30++;
                    }
                }
                if (counter_60 < max_10_counter) {
                    kw_60 = kKeywordGroupBase  + "60_" + id_string + "_" + std::to_string(counter_60);
                    
                    if((i+1)%60 == 0)
                    {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_60 << std::endl;
                        }
                        counter_60++;
                    }
                }
                if (counter_10_2 < max_10_counter) {
                    kw_10_2 = kKeyword10GroupBase  + "2_" + id_string + "_" + std::to_string(counter_10_2);

                    if((i+1)%100 == 0)
                    {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_2 << std::endl;
                        }
                        counter_10_2++;
                    }
                }
                if (counter_10_3 < max_10_counter) {
                    kw_10_3 = kKeyword10GroupBase  + "3_" + id_string + "_" + std::to_string(counter_10_3);

                    if((i+1)%((size_t)(1e3)) == 0)
                    {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_3 << std::endl;
                        }
                        counter_10_3++;
                    }
                }
                if (counter_10_4 < max_10_counter) {
                    kw_10_4 = kKeyword10GroupBase  + "4_" + id_string + "_" + std::to_string(counter_10_4);
                    
                    if((i+1)%((size_t)(1e4)) == 0)
                    {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_4 << std::endl;
                        }
                        counter_10_4++;
                    }
                }
                if (counter_10_5 < max_10_counter) {
                    kw_10_5 = kKeyword10GroupBase  + "5_" + id_string + "_" + std::to_string(counter_10_5);
                    
                    if((i+1)%((size_t)(1e5)) == 0)
                    {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_5 << std::endl;
                        }
                        counter_10_5++;
                    }
                }
                
                (*entries_counter)++;
                if (((*entries_counter) % 100) == 0) {
                    logger::log(sse::logger::INFO) << "Random DB generation: " << (*entries_counter) << " entries generated\r" << std::flush;
                }
                
                callback(kw_10_1, ind);
                callback(kw_10_2, ind);
                callback(kw_10_3, ind);
                callback(kw_10_4, ind);
                callback(kw_10_5, ind);
                callback(kw_20, ind);
                callback(kw_30, ind);
                callback(kw_60, ind);

            }
            
            std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed: (" + std::to_string(counter_10_1) + ", " + std::to_string(counter_10_2) + ", "+ std::to_string(counter_10_3) + ", "+ std::to_string(counter_10_4) + ", "+ std::to_string(counter_10_5) + ")";
            logger::log(logger::INFO) << log << std::endl;
        }
        
        
        void gen_db(size_t N_entries, std::function<void(const std::string &, size_t)> callback)
        {
            crypto::Fpe rnd_perm;
            std::atomic_size_t entries_counter(0);

            unsigned int n_threads = std::thread::hardware_concurrency();
            std::vector<std::thread> threads;
            std::mutex rpc_mutex;
            
            for (unsigned int i = 0; i < n_threads; i++) {
                threads.push_back(std::thread(generation_job, i, N_entries, n_threads, &rnd_perm, &entries_counter, callback));
            }

            for (unsigned int i = 0; i < n_threads; i++) {
                threads[i].join();
            }
        }

    }
}
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
#include "utils/logger.hpp"

#include <sse/crypto/fpe.hpp>
#include <sse/crypto/random.hpp>

#include <string>
#include <thread>
#include <vector>
#include <list>
#include <iostream>
#include <cassert>
#include <cmath>

#define MIN(a,b) (((a) > (b)) ? (b) : (a))

namespace sse {
    namespace sophos {

        static uint64_t xorshift128(uint64_t &x, uint64_t &y, uint64_t &z, uint64_t &w) {
            uint64_t t = x;
            t ^= t << 11;
            t ^= t >> 8;
            x = y; y = z; z = w;
            w ^= w >> 19;
            w ^= t;
            return w;
        }

        
        static uint64_t optimal_num_group(size_t N_entries, size_t step, size_t group_size)
        {
            return floorl(((long double)N_entries)/(1.2*step*group_size));
        }
        
        const std::string kKeyword01PercentBase    = "0.1";
        const std::string kKeyword1PercentBase     = "1";
        const std::string kKeyword10PercentBase    = "10";

        const std::string kKeywordGroupBase      = "Group-";
        const std::string kKeyword10GroupBase    = kKeywordGroupBase + "10^";
        const std::string kKeywordRand10GroupBase    = kKeywordGroupBase + "rand-10^";

        constexpr uint32_t max_10_counter = ~0;
        
        static void generation_job(unsigned int thread_id, size_t N_entries, size_t step, crypto::Fpe *rnd_perm, std::atomic_size_t *entries_counter, std::atomic_size_t *docs_counter, std::function<void(const std::string &, size_t)> callback)
        {
            
            size_t counter = thread_id;
            std::string id_string = std::to_string(thread_id);
            
            uint32_t counter_10_1 = 0, counter_20 = 0, counter_30 = 0, counter_60 = 0, counter_10_2 = 0, counter_10_3 = 0, counter_10_4 = 0, counter_10_5 = 0, counter_10_6 = 0;


            std::string keyword_01, keyword_1, keyword_10;
            std::string kw_10_1, kw_10_2, kw_10_3, kw_10_4, kw_10_5, kw_10_6, kw_20, kw_30, kw_60;
            std::string kw_rand_10_3;
            
            
            bool use_rnd_group_3 = false, use_rnd_group_4 = false, use_rnd_group_5 = false, use_rnd_group_6 = false;
            
//            uint16_t n_groups_3 = (int)ceilf(96./step), n_groups_4 = (int)ceilf(100./step), n_groups_5 = (int)ceilf(10./step), n_groups_6 = (int)ceilf(10./step);

            
            uint64_t size_group_3 = 1e3, size_group_4 = 1e4, size_group_5 = 1e5, size_group_6 = 1e6;
            uint64_t n_groups_3 = optimal_num_group(N_entries, step, size_group_3);
            uint64_t n_groups_4 = optimal_num_group(N_entries, step, size_group_4);
            uint64_t n_groups_5 = optimal_num_group(N_entries, step, size_group_5);
            uint64_t n_groups_6 = optimal_num_group(N_entries, step, size_group_6);

            
            use_rnd_group_3 = true || (1.5*N_entries >= n_groups_3*size_group_3*step);
            use_rnd_group_4 = true || (1.5*N_entries >= n_groups_4*size_group_4*step);
            use_rnd_group_5 = true || (1.5*N_entries >= n_groups_5*size_group_5*step);
            use_rnd_group_6 = true || (1.5*N_entries >= n_groups_6*size_group_6*step);

//            use_rnd_group_3 = false;
//            use_rnd_group_4 = false;
//            use_rnd_group_5 = false;
//            use_rnd_group_6 = false;

//            assert(use_rnd_group_3);
//            assert(use_rnd_group_4);
//            assert(use_rnd_group_5);
//            assert(use_rnd_group_6);
            
            const double r_threshold_3 = 1;//2*((double)n_groups_3*size_group_3*step)/((double)N_entries);
            const double r_threshold_4 = 1.2*((double)n_groups_4*size_group_4*step)/((double)N_entries);
            const double r_threshold_5 = 1.2*((double)n_groups_5*size_group_5*step)/((double)N_entries);
            const double r_threshold_6 = 1.2*((double)n_groups_6*size_group_6*step)/((double)N_entries);

            uint64_t group_rand_10_3[n_groups_3];
            uint64_t group_rand_10_4[n_groups_4];
            uint64_t group_rand_10_5[n_groups_5];
            uint64_t group_rand_10_6[n_groups_6];

            for (size_t i=0; i< n_groups_3; i++) {
                group_rand_10_3[i] = 0;
            }
            for (size_t i=0; i< n_groups_4; i++) {
                group_rand_10_4[i] = 0;
            }
            for (size_t i=0; i< n_groups_5; i++) {
                group_rand_10_5[i] = 0;
            }
            for (size_t i=0; i< n_groups_6; i++) {
                group_rand_10_6[i] = 0;
            }
            
            
            std::string kw;
            uint32_t new_entries;

            for (size_t i = 0; counter < N_entries; counter += step, i++) {
                size_t ind = rnd_perm->encrypt_64(counter);
                new_entries = 0;

                double w_d = ((double)ind)/((uint64_t)~0);
                std::list<std::string> insertions;
                
                uint32_t ind_01 = ind % 1000;
                uint32_t ind_1  = ind_01 % 100;
                uint32_t ind_10 = ind_1 % 10;
                
                keyword_01  = kKeyword01PercentBase    + "_" + std::to_string(ind_01)   + "_1";
                keyword_1   = kKeyword1PercentBase     + "_" + std::to_string(ind_1)    + "_1";
                keyword_10  = kKeyword10PercentBase    + "_" + std::to_string(ind_10)   + "_1";
                
                callback(keyword_01, ind);
                callback(keyword_1, ind);
                callback(keyword_10, ind);
                
                new_entries += 3;
                
                ind_01 = (ind/1000) % 1000;
                ind_1  = ind_01 % 100;
                ind_10 = ind_1 % 10;
                
                keyword_01  = kKeyword01PercentBase    + "_" + std::to_string(ind_01)   + "_2";
                keyword_1   = kKeyword1PercentBase     + "_" + std::to_string(ind_1)    + "_2";
                keyword_10  = kKeyword10PercentBase    + "_" + std::to_string(ind_10)   + "_2";
                
                callback(keyword_01, ind);
                callback(keyword_1, ind);
                callback(keyword_10, ind);

                new_entries += 3;

                ind_01 = (ind/((unsigned int)1e6)) % 1000;
                ind_1  = ind_01 % 100;
                ind_10 = ind_1 % 10;
                
                keyword_01  = kKeyword01PercentBase    + "_" + std::to_string(ind_01)   + "_3";
                keyword_1   = kKeyword1PercentBase     + "_" + std::to_string(ind_1)    + "_3";
                keyword_10  = kKeyword10PercentBase    + "_" + std::to_string(ind_10)   + "_3";
                
//                client->async_update(keyword_01, ind);
//                client->async_update(keyword_1, ind);
//                client->async_update(keyword_10, ind);
//                new_entries += 3;

                
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
                    
                    if (use_rnd_group_3 && w_d < r_threshold_3) {
                        uint16_t g = ind%n_groups_3;
                        if (group_rand_10_3[g] < size_group_3) {
                            group_rand_10_3[g]++;
                            kw = kKeywordRand10GroupBase  + "3_" + id_string + "_" + std::to_string(g);
                            insertions.push_back(kw);
                        }
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
                    if (use_rnd_group_4 && w_d < r_threshold_4) {
                        uint16_t g = ind%n_groups_4;
                        if (group_rand_10_4[g] < size_group_4) {
                            group_rand_10_4[g]++;
                            kw = kKeywordRand10GroupBase  + "4_" + id_string + "_" + std::to_string(g);
                            insertions.push_back(kw);
                        }
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
                    
                    if (use_rnd_group_5 && w_d < r_threshold_5) {
                        uint16_t g = ind%n_groups_5;
                        if (group_rand_10_5[g] < size_group_5) {
                            group_rand_10_5[g]++;
                            kw = kKeywordRand10GroupBase  + "5_" + id_string + "_" + std::to_string(g);
                            insertions.push_back(kw);
                        }
                    }
                    

                }

                if (counter_10_6 < max_10_counter) {
                    kw_10_6 = kKeyword10GroupBase  + "6_" + id_string + "_" + std::to_string(counter_10_6);
                    
                    if((i+1)%((size_t)(1e6)) == 0)
                    {
                        if (logger::severity() <= logger::DBG) {
                            logger::log(logger::DBG) << "Random DB generation: completed keyword: " << kw_10_6 << std::endl;
                        }
                        counter_10_6++;
                    }
                    
                    if (use_rnd_group_6 && w_d < r_threshold_6) {
                        uint16_t g = ind%n_groups_6;
                        if (group_rand_10_6[g] < size_group_6) {
                            group_rand_10_6[g]++;
                            kw = kKeywordRand10GroupBase  + "6_" + id_string + "_" + std::to_string(g);
                            insertions.push_back(kw);
                        }
                    }
                }

                
                (*docs_counter)++;
                if (((*docs_counter) % 1000) == 0) {
                    logger::log(sse::logger::INFO) << "Random DB generation: " << (*docs_counter) << " documents generated (" << (*entries_counter) << " entries)\r" << std::flush;
                }
                

                callback(kw_10_1, ind);
                callback(kw_10_2, ind);
                callback(kw_10_3, ind);
                callback(kw_10_4, ind);
                callback(kw_10_5, ind);
                callback(kw_10_6, ind);
                callback(kw_20, ind);
                callback(kw_30, ind);
                callback(kw_60, ind);
                
                
                for (auto k : insertions) {
                    callback(k, ind);
                }

                new_entries += 9;
                new_entries += insertions.size();
                
                (*entries_counter) += new_entries;
            }
            
            std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed: (" + std::to_string(counter_10_1) + ", " + std::to_string(counter_10_2) + ", "+ std::to_string(counter_10_3) + ", "+ std::to_string(counter_10_4) + ", "+ std::to_string(counter_10_5) + ")";
            
            
            log += " min rand: (";// + std::to_string(group_rand_10_3) + "-" + std::to_string(num_rand_10_3) + ")";
            
            size_t min = group_rand_10_3[0];
            for (size_t i=1; i< n_groups_3; i++) {
                min = MIN(min, group_rand_10_3[i]);
            }
            log += std::to_string(min) + ",";
            
            min = group_rand_10_4[0];
            for (size_t i=1; i< n_groups_4; i++) {
                min = MIN(min, group_rand_10_4[i]);
            }
            log += std::to_string(min) + ",";
            min = group_rand_10_5[0];
            for (size_t i=1; i< n_groups_5; i++) {
                min = MIN(min, group_rand_10_5[i]);
            }
            log += std::to_string(min) + ",";
            min = group_rand_10_6[0];
            for (size_t i=1; i< n_groups_6; i++) {
                min = MIN(min, group_rand_10_6[i]);
            }
            log += std::to_string(min) + ")";
            
            logger::log(logger::INFO) << log << std::endl;
        }
        
        
        void gen_db(size_t N_entries, std::function<void(const std::string &, size_t)> callback)
        {
            crypto::Fpe rnd_perm;
            std::atomic_size_t entries_counter(0);
            std::atomic_size_t docs_counter(0);

            unsigned int n_threads = std::thread::hardware_concurrency();
            std::vector<std::thread> threads;
            std::mutex rpc_mutex;
            
            for (unsigned int i = 0; i < n_threads; i++) {
                threads.push_back(std::thread(generation_job, i, N_entries, n_threads, &rnd_perm, &entries_counter, &docs_counter, callback));
            }

            for (unsigned int i = 0; i < n_threads; i++) {
                threads[i].join();
            }
            
            std::string log = "Random DB generation: " + std::to_string(docs_counter.load()) + " new documents generated, representing " + std::to_string(entries_counter.load()) + " entries";

            logger::log(logger::INFO) << log << std::endl;
        }

    }
}
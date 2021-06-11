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


#include "utils/db_generator.hpp"

#include "utils/logger.hpp"

#include <sse/crypto/random.hpp>

#include <cassert>
#include <cmath>

#include <atomic>
#include <iostream>
#include <list>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#define MIN(a, b) (((a) > (b)) ? (b) : (a))

namespace sse {
namespace sophos {

static uint64_t optimal_num_group(double fraction,
                                  size_t N_entries,
                                  size_t step,
                                  size_t group_size)
{
    return static_cast<uint64_t>(
        floorl(fraction * (static_cast<long double>(N_entries))
               / (1.2 * static_cast<long double>(step * group_size))));
}

const char* kKeyword01PercentBase = "0.1";
const char* kKeyword1PercentBase  = "1";
const char* kKeyword10PercentBase = "10";

const char* kKeywordGroupBase       = "Group-";
const char* kKeyword10GroupBase     = "Group-10^";
const char* kKeywordRand10GroupBase = "Group-rand-10^";

constexpr uint32_t max_10_counter = ~0;

// This function is very badly implemented, I know ...
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static void generation_job(
    unsigned int                                           thread_id,
    size_t                                                 N_entries,
    size_t                                                 step,
    std::atomic_size_t*                                    entries_counter,
    std::atomic_size_t*                                    docs_counter,
    const std::function<void(const std::string&, size_t)>& callback)
{
    std::random_device rd;
    std::mt19937 rng(rd()); // Standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<size_t> dist;

    size_t      counter   = thread_id;
    std::string id_string = std::to_string(thread_id);

    uint32_t counter_10_1 = 0;
    uint32_t counter_20   = 0;
    uint32_t counter_30   = 0;
    uint32_t counter_60   = 0;
    uint32_t counter_10_2 = 0;
    uint32_t counter_10_3 = 0;
    uint32_t counter_10_4 = 0;
    uint32_t counter_10_5 = 0;
    uint32_t counter_10_6 = 0;


    std::string keyword_01;
    std::string keyword_1;
    std::string keyword_10;
    std::string kw_10_1;
    std::string kw_10_2;
    std::string kw_10_3;
    std::string kw_10_4;
    std::string kw_10_5;
    std::string kw_10_6;
    std::string kw_20;
    std::string kw_30;
    std::string kw_60;


    bool use_rnd_group_2 = true;
    bool use_rnd_group_3 = true;
    bool use_rnd_group_4 = true;
    bool use_rnd_group_5 = true;
    bool use_rnd_group_6 = true;

    const uint64_t size_group_2 = 1e2;
    const uint64_t size_group_3 = 1e3;
    const uint64_t size_group_4 = 1e4;
    const uint64_t size_group_5 = 1e5;
    const uint64_t size_group_6 = 1e6;
    const uint64_t n_groups_2
        = optimal_num_group(0.9, N_entries, step, size_group_2);
    const uint64_t n_groups_3
        = optimal_num_group(1.0, N_entries, step, size_group_3);
    const uint64_t n_groups_4
        = optimal_num_group(1.0, N_entries, step, size_group_4);
    const uint64_t n_groups_5
        = optimal_num_group(1.0, N_entries, step, size_group_5);
    const uint64_t n_groups_6
        = optimal_num_group(1.0, N_entries, step, size_group_6);


    // use_rnd_group_2
    //     = true || (1.5 * N_entries >= n_groups_2 * size_group_2 * step);
    // use_rnd_group_3
    //     = true || (1.5 * N_entries >= n_groups_3 * size_group_3 * step);
    // use_rnd_group_4
    //     = true || (1.5 * N_entries >= n_groups_4 * size_group_4 * step);
    // use_rnd_group_5
    //     = true || (1.5 * N_entries >= n_groups_5 * size_group_5 * step);
    // use_rnd_group_6
    //     = true || (1.5 * N_entries >= n_groups_6 * size_group_6 * step);

    const long double r_threshold_2
        = 1.4 * (static_cast<long double>(n_groups_2) * size_group_2 * step)
          / (static_cast<long double>(N_entries));
    const long double r_threshold_3
        = 1.2 * (static_cast<long double>(n_groups_3) * size_group_3 * step)
          / (static_cast<long double>(N_entries));
    const long double r_threshold_4
        = 1.2 * (static_cast<long double>(n_groups_4) * size_group_4 * step)
          / (static_cast<long double>(N_entries));
    const long double r_threshold_5
        = 1.2 * (static_cast<long double>(n_groups_5) * size_group_5 * step)
          / (static_cast<long double>(N_entries));
    const long double r_threshold_6
        = 1.2 * (static_cast<long double>(n_groups_6) * size_group_6 * step)
          / (static_cast<long double>(N_entries));

    std::vector<uint64_t> group_rand_10_2(n_groups_2, 0);
    std::vector<uint64_t> group_rand_10_3(n_groups_3, 0);
    std::vector<uint64_t> group_rand_10_4(n_groups_4, 0);
    std::vector<uint64_t> group_rand_10_5(n_groups_5, 0);
    std::vector<uint64_t> group_rand_10_6(n_groups_6, 0);

    std::string kw;

    for (size_t i = 0; counter < N_entries; counter += step, i++) {
        size_t   ind         = dist(rng);
        uint32_t new_entries = 0;

        double w_d = (static_cast<double>(ind)) / (static_cast<double>(~0UL));
        std::list<std::string> insertions;

        uint32_t ind_01 = ind % 1000;
        uint32_t ind_1  = ind_01 % 100;
        uint32_t ind_10 = ind_1 % 10;

        keyword_01 = kKeyword01PercentBase;
        keyword_01.append("_").append(std::to_string(ind_01)).append("_1");
        keyword_1 = kKeyword1PercentBase;
        keyword_1.append("_").append(std::to_string(ind_1)).append("_1");
        keyword_10 = kKeyword10PercentBase;
        keyword_10.append("_").append(std::to_string(ind_10)).append("_1");

        callback(keyword_01, ind);
        callback(keyword_1, ind);
        callback(keyword_10, ind);

        new_entries += 3;

        ind_01 = (ind / 1000) % 1000;
        ind_1  = ind_01 % 100;
        ind_10 = ind_1 % 10;

        keyword_01 = kKeyword01PercentBase;
        keyword_01.append("_").append(std::to_string(ind_01)).append("_2");
        keyword_1 = kKeyword1PercentBase;
        keyword_1.append("_").append(std::to_string(ind_1)).append("_2");
        keyword_10 = kKeyword10PercentBase;
        keyword_10.append("_").append(std::to_string(ind_10)).append("_2");

        callback(keyword_01, ind);
        callback(keyword_1, ind);
        callback(keyword_10, ind);

        new_entries += 3;

        // ind_01 = (ind / (static_cast<unsigned int>(1e6))) % 1000;
        // ind_1  = ind_01 % 100;
        // ind_10 = ind_1 % 10;

        // keyword_01 = kKeyword01PercentBase;
        // keyword_01.append("_").append(std::to_string(ind_01)).append("_3");
        // keyword_1 = kKeyword1PercentBase;
        // keyword_1.append("_").append(std::to_string(ind_1)).append("_3");
        // keyword_10 = kKeyword10PercentBase;
        // keyword_1.append("_").append(std::to_string(ind_10)).append("_3");


        if (counter_10_1 < max_10_counter) {
            kw_10_1 = kKeyword10GroupBase;
            kw_10_1.append("1_").append(id_string).append("_").append(
                std::to_string(counter_10_1));

            if ((i + 1) % 10 == 0) {
                logger::logger()->debug(
                    "Random DB generation: completed keyword " + kw_10_1);

                counter_10_1++;
            }
        }
        if (counter_20 < max_10_counter) {
            kw_20 = kKeywordGroupBase;
            kw_20.append("20_").append(id_string).append("_").append(
                std::to_string(counter_20));

            if ((i + 1) % 20 == 0) {
                logger::logger()->debug(
                    "Random DB generation: completed keyword " + kw_20);
                counter_20++;
            }
        }
        if (counter_30 < max_10_counter) {
            kw_30 = kKeywordGroupBase;
            kw_30.append("30_").append(id_string).append("_").append(
                std::to_string(counter_30));

            if ((i + 1) % 30 == 0) {
                logger::logger()->debug(
                    "Random DB generation: completed keyword " + kw_30);
                counter_30++;
            }
        }
        if (counter_60 < max_10_counter) {
            kw_60 = kKeywordGroupBase;
            kw_60.append("60_").append(id_string).append("_").append(
                std::to_string(counter_60));

            if ((i + 1) % 60 == 0) {
                logger::logger()->debug(
                    "Random DB generation: completed keyword " + kw_60);
                counter_60++;
            }
        }
        if (counter_10_2 < max_10_counter) {
            kw_10_2 = kKeyword10GroupBase;
            kw_10_2.append("2_").append(id_string).append("_").append(
                std::to_string(counter_10_2));

            if ((i + 1) % 100 == 0) {
                logger::logger()->debug(
                    "Random DB generation: completed keyword " + kw_10_2);
                counter_10_2++;
            }


            // cppcheck-suppress knownConditionTrueFalse
            if (use_rnd_group_2 && w_d < r_threshold_2) {
                uint16_t g = ind % n_groups_2;
                if (group_rand_10_2[g] < size_group_2) {
                    group_rand_10_2[g]++;
                    kw = kKeywordRand10GroupBase;
                    kw.append("3_").append(id_string).append("_").append(
                        std::to_string(g));
                    insertions.push_back(kw);
                }
            }
        }
        if (counter_10_3 < max_10_counter) {
            kw_10_3 = kKeyword10GroupBase;
            kw_10_3.append("3_").append(id_string).append("_").append(
                std::to_string(counter_10_3));

            if ((i + 1) % (static_cast<size_t>(1e3)) == 0) {
                logger::logger()->debug(
                    "Random DB generation: completed keyword " + kw_10_3);
                counter_10_3++;
            }

            // cppcheck-suppress knownConditionTrueFalse
            if (use_rnd_group_3 && w_d < r_threshold_3) {
                uint16_t g = ind % n_groups_3;
                if (group_rand_10_3[g] < size_group_3) {
                    group_rand_10_3[g]++;
                    kw = kKeywordRand10GroupBase;
                    kw.append("3_").append(id_string).append("_").append(
                        std::to_string(g));
                    insertions.push_back(kw);
                }
            }
        }
        if (counter_10_4 < max_10_counter) {
            kw_10_4 = kKeyword10GroupBase;
            kw_10_4.append("4_").append(id_string).append("_").append(
                std::to_string(counter_10_4));

            if ((i + 1) % (static_cast<size_t>(1e4)) == 0) {
                logger::logger()->debug(
                    "Random DB generation: completed keyword " + kw_10_4);
                counter_10_4++;
            }
            // cppcheck-suppress knownConditionTrueFalse
            if (use_rnd_group_4 && w_d < r_threshold_4) {
                uint16_t g = ind % n_groups_4;
                if (group_rand_10_4[g] < size_group_4) {
                    group_rand_10_4[g]++;
                    kw = kKeywordRand10GroupBase;
                    kw.append("4_").append(id_string).append("_").append(
                        std::to_string(g));
                    insertions.push_back(kw);
                }
            }
        }
        if (counter_10_5 < max_10_counter) {
            kw_10_5 = kKeyword10GroupBase;
            kw_10_5.append("5_").append(id_string).append("_").append(
                std::to_string(counter_10_5));

            if ((i + 1) % (static_cast<size_t>(1e5)) == 0) {
                logger::logger()->debug(
                    "Random DB generation: completed keyword " + kw_10_5);
                counter_10_5++;
            }

            // cppcheck-suppress knownConditionTrueFalse
            if (use_rnd_group_5 && w_d < r_threshold_5) {
                uint16_t g = ind % n_groups_5;
                if (group_rand_10_5[g] < size_group_5) {
                    group_rand_10_5[g]++;
                    kw = kKeywordRand10GroupBase;
                    kw.append("5_").append(id_string).append("_").append(
                        std::to_string(g));
                    insertions.push_back(kw);
                }
            }
        }

        if (counter_10_6 < max_10_counter) {
            kw_10_6 = kKeyword10GroupBase;
            kw_10_6.append("6_").append(id_string).append("_").append(
                std::to_string(counter_10_6));

            if ((i + 1) % (static_cast<size_t>(1e6)) == 0) {
                logger::logger()->debug(
                    "Random DB generation: completed keyword " + kw_10_6);
                counter_10_6++;
            }

            // cppcheck-suppress knownConditionTrueFalse
            if (use_rnd_group_6 && w_d < r_threshold_6) {
                uint16_t g = ind % n_groups_6;
                if (group_rand_10_6[g] < size_group_6) {
                    group_rand_10_6[g]++;
                    kw = kKeywordRand10GroupBase;
                    kw.append("6_").append(id_string).append("_").append(
                        std::to_string(g));
                    insertions.push_back(kw);
                }
            }
        }


        (*docs_counter)++;
        if (((*docs_counter) % 1000) == 0) {
            logger::logger()->info(
                "Random DB generation : documents generated ( entries)",
                *docs_counter,
                *entries_counter);
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


        for (const auto& k : insertions) {
            callback(k, ind);
        }

        new_entries += 9;
        new_entries += insertions.size();

        (*entries_counter) += new_entries;
    }

    std::string log
        = "Random DB generation: thread " + std::to_string(thread_id)
          + " completed: (" + std::to_string(counter_10_1) + ", "
          + std::to_string(counter_10_2) + ", " + std::to_string(counter_10_3)
          + ", " + std::to_string(counter_10_4) + ", "
          + std::to_string(counter_10_5) + ")";


    log += " min rand: ("; // + std::to_string(group_rand_10_3) + "-" +
                           // std::to_string(num_rand_10_3) + ")";

    size_t min;
    size_t non_full;

    if (n_groups_2 > 0) {
        min      = group_rand_10_2[0];
        non_full = 0;
        if (group_rand_10_2[0] < size_group_2) {
            non_full++;
        }

        for (size_t i = 1; i < n_groups_2; i++) {
            min = MIN(min, group_rand_10_2[i]);

            if (group_rand_10_2[i] < size_group_2) {
                non_full++;
            }
        }
        log += std::to_string(min) + "/" + std::to_string(n_groups_2) + "/"
               + std::to_string(non_full);
    }

    if (n_groups_3 > 0) {
        log += ",";
        min      = group_rand_10_3[0];
        non_full = 0;
        if (group_rand_10_3[0] < size_group_3) {
            non_full++;
        }

        for (size_t i = 1; i < n_groups_3; i++) {
            min = MIN(min, group_rand_10_3[i]);
            if (group_rand_10_3[i] < size_group_3) {
                non_full++;
            }
        }
        log += std::to_string(min) + "/" + std::to_string(n_groups_3) + "/"
               + std::to_string(non_full);
    }
    if (n_groups_4 > 0) {
        log += ",";
        min      = group_rand_10_4[0];
        non_full = 0;
        if (group_rand_10_4[0] < size_group_4) {
            non_full++;
        }

        for (size_t i = 1; i < n_groups_4; i++) {
            min = MIN(min, group_rand_10_4[i]);
            if (group_rand_10_4[i] < size_group_4) {
                non_full++;
            }
        }
        log += std::to_string(min) + "/" + std::to_string(n_groups_4) + "/"
               + std::to_string(non_full);
    }

    if (n_groups_5 > 0) {
        log += ",";
        min      = group_rand_10_5[0];
        non_full = 0;
        if (group_rand_10_5[0] < size_group_5) {
            non_full++;
        }

        for (size_t i = 1; i < n_groups_5; i++) {
            min = MIN(min, group_rand_10_5[i]);
            if (group_rand_10_5[i] < size_group_5) {
                non_full++;
            }
        }
        log += std::to_string(min) + "/" + std::to_string(n_groups_5) + "/"
               + std::to_string(non_full);
    }

    if (n_groups_6 > 0) {
        log += ",";
        min      = group_rand_10_6[0];
        non_full = 0;
        if (group_rand_10_6[0] < size_group_6) {
            non_full++;
        }

        for (size_t i = 1; i < n_groups_6; i++) {
            min = MIN(min, group_rand_10_6[i]);
            if (group_rand_10_6[i] < size_group_6) {
                non_full++;
            }
        }
        log += std::to_string(min) + "/" + std::to_string(n_groups_6) + "/"
               + std::to_string(non_full);
    }
    log += ")";

    logger::logger()->info(log);
}


void gen_db(size_t                                                 N_entries,
            const std::function<void(const std::string&, size_t)>& callback)
{
    std::atomic_size_t entries_counter(0);
    std::atomic_size_t docs_counter(0);

    unsigned int             n_threads = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;

    for (unsigned int i = 0; i < n_threads; i++) {
        threads.emplace_back(std::thread(generation_job,
                                         i,
                                         N_entries,
                                         n_threads,
                                         &entries_counter,
                                         &docs_counter,
                                         callback));
    }

    for (unsigned int i = 0; i < n_threads; i++) {
        threads[i].join();
    }

    std::string log
        = "Random DB generation: " + std::to_string(docs_counter.load())
          + " new documents generated, representing "
          + std::to_string(entries_counter.load()) + " entries";

    logger::logger()->info(log);
}

} // namespace sophos
} // namespace sse

#include <sse/schemes/utils/db_generator.hpp>

#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include <gtest/gtest.h>

namespace sse {
namespace test {

static void check_keyword_group(const size_t       group_size,
                                const size_t       n_id,
                                const std::string& keyword_prefix,
                                const std::map<std::string, size_t>& db_stats,
                                const size_t                         N_entries)
{
    size_t sum{0};
    for (size_t i = 0; i < n_id; i++) {
        std::string kw_id = keyword_prefix + std::to_string(i) + "_";

        for (size_t j = 0;; j++) {
            std::string kw = kw_id + std::to_string(j);
            auto        it = db_stats.find(kw);

            if (it != db_stats.end()) {
                // keyword found
                EXPECT_LE(it->second, group_size);
                sum += it->second;
            } else {
                break;
            }
        }
    }
    EXPECT_EQ(sum, N_entries);
}

static void check_percentile_group(
    const size_t                         quantile,
    const std::string&                   keyword_prefix,
    const std::map<std::string, size_t>& db_stats,
    const size_t                         N_entries)
{
    size_t sum_1{0};
    size_t sum_2{0};

    for (size_t i = 0; i < quantile; i++) {
        std::string kw_1 = keyword_prefix + std::to_string(i) + "_1";
        std::string kw_2 = keyword_prefix + std::to_string(i) + "_2";

        auto it = db_stats.find(kw_1);

        if (it != db_stats.end()) {
            // keyword found
            sum_1 += it->second;
        }
        it = db_stats.find(kw_2);

        if (it != db_stats.end()) {
            // keyword found
            sum_2 += it->second;
        }
    }
    EXPECT_EQ(sum_1, N_entries);
    EXPECT_EQ(sum_2, N_entries);
} // namespace test

TEST(db_generator, stats)
{
    std::map<std::string, size_t> gen_db_stats;
    std::mutex                    mtx;

    constexpr size_t N_entries = 1001;
    size_t           total{0};

    auto gen_cb = [&gen_db_stats, &mtx, &total](const std::string& kw, size_t) {
        std::unique_lock<std::mutex> lck(mtx);
        gen_db_stats[kw]++;
        total++;
    };

    sse::sophos::gen_db(N_entries, gen_cb);


    for (auto e : gen_db_stats) {
        // std::cerr << e.first << "\n";
    }
    // number of different ids
    size_t n_id = std::thread::hardware_concurrency();

    check_keyword_group(10, n_id, "Group-10^1_", gen_db_stats, N_entries);
    check_keyword_group(20, n_id, "Group-20_", gen_db_stats, N_entries);
    check_keyword_group(30, n_id, "Group-30_", gen_db_stats, N_entries);
    check_keyword_group(60, n_id, "Group-60_", gen_db_stats, N_entries);

    check_keyword_group(1E2, n_id, "Group-10^2_", gen_db_stats, N_entries);
    check_keyword_group(1E3, n_id, "Group-10^3_", gen_db_stats, N_entries);
    check_keyword_group(1E4, n_id, "Group-10^4_", gen_db_stats, N_entries);
    check_keyword_group(1E5, n_id, "Group-10^5_", gen_db_stats, N_entries);
    check_keyword_group(1E6, n_id, "Group-10^6_", gen_db_stats, N_entries);


    check_percentile_group(1000, "0.1_", gen_db_stats, N_entries);
    check_percentile_group(100, "1_", gen_db_stats, N_entries);
    // check_percentile_group(10, "10_", gen_db_stats, N_entries);
}
} // namespace test
} // namespace sse
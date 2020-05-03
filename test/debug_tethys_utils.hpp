#include <sse/schemes/tethys/tethys_store_builder.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/prf.hpp>
#include <sse/crypto/utils.hpp>

#include <cassert>
#include <cstring>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>

constexpr size_t kPageSize     = 4096; // 4 kB
constexpr size_t kTableKeySize = 16;   // 128 bits table keys
using key_type                 = std::array<uint8_t, kTableKeySize>;

using namespace sse::tethys;

template<class StoreBuilder>
void generate_random_store(size_t n_elements, const std::string test_dir)
{
    static_assert(
        std::is_same<uint64_t, typename StoreBuilder::value_type>::value,
        "Store value type must be uint64_t");

    if (sse::utility::is_directory(test_dir)) {
        std::cerr << "Random store already created\n";
        return;
    }
    sse::utility::create_directory(test_dir, static_cast<mode_t>(0700));

    using value_type = typename StoreBuilder::value_type;

    constexpr size_t kMaxListSize
        = kPageSize / sizeof(value_type)
          - StoreBuilder::value_encoder_type::kListControlValues;
    const size_t average_n_lists = 2 * (n_elements / kMaxListSize + 1);


    const size_t expected_tot_n_elements
        = n_elements
          + StoreBuilder::value_encoder_type::kListControlValues
                * average_n_lists;

    TethysStoreBuilderParam builder_params;
    builder_params.max_n_elements    = expected_tot_n_elements;
    builder_params.tethys_table_path = test_dir + "/tethys_table.bin";
    builder_params.tethys_stash_path = test_dir + "/tethys_stash.bin";
    builder_params.epsilon           = 0.2;


    size_t                                remaining_elts = n_elements;
    std::random_device                    rd;
    std::mt19937                          gen;
    std::uniform_int_distribution<size_t> dist(1, kMaxListSize);
    size_t                                list_index = 0;


    constexpr size_t kKeySize = sse::crypto::Prf<kTableKeySize>::kKeySize;
    std::array<uint8_t, kKeySize> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);
    sse::crypto::Prf<kTableKeySize> prf(
        sse::crypto::Key<kKeySize>(prf_key.data()));

    // generate a seed and display it (for replay in case of bugs)
    size_t seed = rd();
    // seed the random number generator
    // seed = 1267674774; // this is useful when you want to replay a previously
    // failing seed
    gen.seed(seed);

    std::cerr << "RNG seed: " << seed << "\n";

    StoreBuilder store_builder(builder_params);

    while (remaining_elts) {
        size_t list_size = dist(gen);

        std::array<uint8_t, kTableKeySize> prf_out = prf.prf(
            reinterpret_cast<uint8_t*>(&list_index), sizeof(list_index));


        if (list_size > remaining_elts) {
            // avoid overflows
            list_size = remaining_elts;
        }
        // // copy the list index
        // *reinterpret_cast<size_t*>(key.data() + index_offset) = list_index;

        std::vector<value_type> list(list_size, (uint64_t)list_index);

        store_builder.insert_list(prf_out, list);

        list_index++;
        remaining_elts -= list_size;
    }

    std::cerr << list_index << " generated lists (" << average_n_lists
              << " expected average). Starting to build the data structure \n";

    store_builder.build();

    std::cerr << "Built completed\n";
}


template<class Store>
void store_read_queries(const size_t n_elements, const std::string test_dir)
{
    static_assert(std::is_same<uint64_t, typename Store::value_type>::value,
                  "Store value type must be uint64_t");

    if (!sse::utility::is_directory(test_dir)) {
        std::cerr << "Random store not created\n";
        return;
    }

    using value_type = typename Store::value_type;

    constexpr size_t kMaxListSize = kPageSize / sizeof(value_type)
                                    - Store::decoder_type::kListControlValues;
    const size_t average_n_lists = 2 * (n_elements / kMaxListSize + 1);


    constexpr size_t kKeySize = sse::crypto::Prf<kTableKeySize>::kKeySize;
    std::array<uint8_t, kKeySize> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);
    sse::crypto::Prf<kTableKeySize> prf(
        sse::crypto::Key<kKeySize>(prf_key.data()));


    Store store(test_dir + "/tethys_table.bin", test_dir + "/tethys_stash.bin");

    const size_t n_queries = 0.8 * average_n_lists;

    auto begin = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < n_queries; i++) {
        std::array<uint8_t, kTableKeySize> prf_out
            = prf.prf(reinterpret_cast<uint8_t*>(&i), sizeof(size_t));

        auto res = store.get_list(prf_out);

        if (res.size() > kMaxListSize) {
            std::cerr << "List too large??\n";
        }
        std::set<value_type> set(res.begin(), res.end());
        bool                 failure = false;
        if (set.size() != 1) {
            std::cerr << set.size()
                      << " different results, while 1 was expected\n";
            failure = true;
        }
        if (*set.begin() != i) {
            std::cerr << "Invalid element in the list: " << *set.begin()
                      << " was found instead of " << i << "\n";
            failure = true;
        }
        if (!failure) {
            std::cerr << "OK\n";
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> time_ms = end - begin;

    std::cout << "Sync read duration: " << time_ms.count() << " ms\n";
    std::cout << 1000 * time_ms.count() / n_queries << " mus/buckets_pairs\n";
    std::cout << 1000 * n_queries / time_ms.count() << " buckets_pairs/s\n\n";
}

template<class Store>
void async_store_read_queries(const size_t      n_elements,
                              const std::string test_dir)
{
    static_assert(std::is_same<uint64_t, typename Store::value_type>::value,
                  "Store value type must be uint64_t");

    if (!sse::utility::is_directory(test_dir)) {
        std::cerr << "Random store not created\n";
        return;
    }

    using value_type = typename Store::value_type;

    constexpr size_t kMaxListSize = kPageSize / sizeof(value_type)
                                    - Store::decoder_type::kListControlValues;
    const size_t average_n_lists = 2 * (n_elements / kMaxListSize + 1);

    constexpr size_t kKeySize = sse::crypto::Prf<kTableKeySize>::kKeySize;
    std::array<uint8_t, kKeySize> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);
    sse::crypto::Prf<kTableKeySize> prf(
        sse::crypto::Key<kKeySize>(prf_key.data()));

    Store store(test_dir + "/tethys_table.bin", test_dir + "/tethys_stash.bin");

    store.use_direct_IO(true);

    const size_t n_queries = 0.8 * average_n_lists;

    std::atomic_size_t completed_queries(0);

    std::promise<void> notifier;
    std::future<void>  notifier_future = notifier.get_future();

    auto callback
        = [&notifier, n_queries, &completed_queries](
              std::unique_ptr<std::array<uint8_t, kPageSize>> /*bucket*/,
              size_t /*b_index*/) {
              size_t query_count = completed_queries.fetch_add(1) + 1;

              if (query_count == n_queries) {
                  notifier.set_value();
              }
          };

    auto begin = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < n_queries; i++) {
        std::array<uint8_t, kTableKeySize> prf_out
            = prf.prf(reinterpret_cast<uint8_t*>(&i), sizeof(size_t));

        store.async_get_buckets(prf_out, callback);
    }

    // wait for completion of the queries
    notifier_future.get();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> time_ms = end - begin;

    std::cout << "Async read duration: " << time_ms.count() << " ms\n";
    std::cout << 1000 * time_ms.count() / n_queries << " mus/buckets_pairs\n";
    std::cout << 1000 * n_queries / time_ms.count() << " buckets_pairs/s\n\n";
}
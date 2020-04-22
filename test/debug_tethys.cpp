#include <sse/schemes/tethys/details/tethys_graph.hpp>
#include <sse/schemes/tethys/encoders/encode_separate.hpp>
#include <sse/schemes/tethys/tethys_store.hpp>
#include <sse/schemes/tethys/tethys_store_builder.hpp>

#include <sse/crypto/prf.hpp>
#include <sse/crypto/utils.hpp>

#include <cassert>
#include <cstring>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>

using namespace sse::tethys;
using namespace sse::tethys::details;


void test_dfs()
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    graph.add_edge_from_source(0, 2, 0);
    graph.add_edge(1, 2, 0, 0 + mid_graph);

    graph.add_edge(2, 1, 0 + mid_graph, 1);
    graph.add_edge_to_sink(3, 1, 1);

    graph.add_edge(4, 1, 0 + mid_graph, 2);
    graph.add_edge(5, 1, 2, 1 + mid_graph);
    graph.add_edge_to_sink(6, 1, 1 + mid_graph);

    size_t cap  = 0;
    auto   path = graph.find_source_sink_path(&cap);


    for (const auto& e : path) {
        std::cerr << "Edge index: " << graph.get_edge(e).value_index << "\n";
    }


    std::vector<std::size_t> path_index;
    std::transform(path.begin(),
                   path.end(),
                   std::back_inserter(path_index),
                   [&graph](const EdgePtr& e) -> std::size_t {
                       return graph.get_edge(e).value_index;
                   });


    assert(cap == 1);
    assert(path_index == std::vector<size_t>({0, 1, 4, 5, 6}));
}

// void test_graphs()
// {
//     TethysGraph graph(10);

//     EdgePtr e_source_1 = graph.add_edge_from_source(0, 10, 1, 0);
//     EdgePtr e_source_2 = graph.add_edge_from_source(1, 40, 9, 0);

//     graph.add_edge(3, 30, 1, 8, ForcedRight);

//     EdgePtr e_sink_2 = graph.add_edge_to_sink(15, 30, 8, 1);
//     EdgePtr e_sink_1 = graph.add_edge_to_sink(8, 10, 7, 0);

//     graph.add_edge(7, 15, 9, 3, ForcedRight);
//     graph.add_edge(11, 15, 3, 3, ForcedLeft);
//     graph.add_edge(5, 7, 3, 6, ForcedRight);
//     graph.add_edge(14, 15, 6, 1, ForcedLeft);

//     graph.add_edge(4, 7, 3, 4, ForcedRight);
//     graph.add_edge(12, 10, 4, 6, ForcedLeft);
//     graph.add_edge(6, 10, 6, 6, ForcedRight);


//     // graph.add_edge(2, 6, 1, 4, ForcedRight);
//     // graph.add_edge(21, 6, 1, 2, ForcedRight);


//     // graph.add_edge(10, 5, 2, 7, ForcedLeft);


//     // graph.add_edge(13, 2, 5, 7, ForcedLeft);


//     graph.compute_residual_maxflow();
//     graph.transform_residual_to_flow();


//     size_t flow = graph.get_flow();

//     std::cerr << "Flow: " << flow << "\n";
//     std::cerr << "Source(1): " << graph.get_edge_flow(e_source_1) << "\n";
//     std::cerr << "Source(2): " << graph.get_edge_flow(e_source_2) << "\n";
//     std::cerr << "Sink(1): " << graph.get_edge_flow(e_sink_1) << "\n";
//     std::cerr << "Sink(2): " << graph.get_edge_flow(e_sink_2) << "\n";
// }

void test_graphs()
{
    const size_t graph_size = 6;
    const size_t mid_graph  = graph_size / 2;
    TethysGraph  graph(graph_size);

    graph.add_edge_from_source(0, 1, 0);
    graph.add_edge(1, 1, 0, 0 + mid_graph);

    graph.add_edge(2, 1, 0 + mid_graph, 1);
    graph.add_edge_to_sink(3, 1, 1);

    graph.add_edge(4, 1, 0 + mid_graph, 2);
    graph.add_edge(5, 1, 2, 1 + mid_graph);
    graph.add_edge_to_sink(6, 1, 1 + mid_graph);

    graph.compute_residual_maxflow();
    graph.transform_residual_to_flow();


    TethysGraph expected_graph(graph_size);

    expected_graph.add_edge_from_source(0, 1, 0);
    expected_graph.add_edge(1, 1, 0, 0 + mid_graph);

    expected_graph.add_edge(2, 1, 0 + mid_graph, 1);
    expected_graph.add_edge_to_sink(3, 1, 1);

    expected_graph.add_edge(4, 0, 0 + mid_graph, 2);
    expected_graph.add_edge(5, 0, 2, 1 + mid_graph);
    expected_graph.add_edge_to_sink(6, 0, 1 + mid_graph);
}

constexpr size_t kTableKeySize = 16; // 128 bits table keys
using key_type                 = std::array<uint8_t, kTableKeySize>;

struct Hasher
{
    TethysAllocatorKey operator()(const key_type& key)
    {
        TethysAllocatorKey tk;
        static_assert(sizeof(tk.h) == sizeof(key_type),
                      "Invalid source key size");

        memcpy(tk.h, key.data(), sizeof(tk.h));

        return tk;
    }
};

void test_store()
{
    const std::string test_dir = "test_dir";


    constexpr size_t kPageSize = 4096; // 4 kB

    TethysStoreBuilderParam builder_params;
    builder_params.max_n_elements    = 0;
    builder_params.tethys_table_path = test_dir + "/tethys_table.bin";
    builder_params.tethys_stash_path = test_dir + "/tethys_stash.bin";
    builder_params.epsilon           = 0.2;

    using encoder_type
        = encoders::EncodeSeparateEncoder<key_type, size_t, kPageSize>;

    sse::utility::remove_directory(test_dir);
    sse::utility::create_directory(test_dir, static_cast<mode_t>(0700));


    size_t              v_size = 450;
    key_type            key_0  = {{0x00}};
    std::vector<size_t> v_0(v_size, 0xABABABABABABABAB);
    for (size_t i = 0; i < v_0.size(); i++) {
        v_0[i] += i;
    }
    builder_params.max_n_elements
        += v_0.size() + encoder_type::kBucketControlValues;

    // force overflow
    key_type key_1 = key_0;
    key_1[8]       = 0x01;
    std::vector<size_t> v_1(v_size, 0xCDCDCDCDCDCDCDCD);
    for (size_t i = 0; i < v_1.size(); i++) {
        v_1[i] += i;
    }
    builder_params.max_n_elements
        += v_1.size() + encoder_type::kBucketControlValues;

    key_type key_2 = key_0;
    key_2[0]       = 0x01;
    key_2[8]       = 0x00;
    std::vector<size_t> v_2(v_size, 0xEFEFEFEFEFEFEFEF);
    for (size_t i = 0; i < v_2.size(); i++) {
        v_2[i] += i;
    }
    builder_params.max_n_elements
        += v_2.size() + encoder_type::kBucketControlValues;

    key_type key_3 = key_0;
    key_3[0]       = 0x01;
    key_3[8]       = 0x01;
    std::vector<size_t> v_3(v_size, 0x6969696969696969);
    for (size_t i = 0; i < v_3.size(); i++) {
        v_3[i] += i;
    }
    builder_params.max_n_elements
        += v_3.size() + encoder_type::kBucketControlValues;

    key_type key_4 = key_0;
    key_4[0]       = 0x01;
    key_4[8]       = 0x02;
    std::vector<size_t> v_4(v_size, 0x7070707070707070);
    for (size_t i = 0; i < v_4.size(); i++) {
        v_4[i] += i;
    }
    builder_params.max_n_elements
        += v_4.size() + encoder_type::kBucketControlValues;

    key_type key_5 = key_0;
    key_5[0]       = 0x02;
    key_5[8]       = 0x01;
    std::vector<size_t> v_5(v_size, 0x4242424242424242);
    for (size_t i = 0; i < v_5.size(); i++) {
        v_5[i] += i;
    }
    builder_params.max_n_elements
        += v_5.size() + encoder_type::kBucketControlValues;

    key_type key_6 = key_0;
    key_6[0]       = 0x02;
    key_6[8]       = 0x02;
    std::vector<size_t> v_6(v_size, 0x5353535353535353);
    for (size_t i = 0; i < v_6.size(); i++) {
        v_6[i] += i;
    }
    builder_params.max_n_elements
        += v_6.size() + encoder_type::kBucketControlValues;

    // key_type key_2 = key_0;
    // key_2[0]       = 0x01;
    // key_2[8]       = 0x00;


    // key_type key_3 = key_0;
    // key_3[0]       = 0x01;
    // key_3[8]       = 0x01;

    // key_type key_4 = key_0;
    // key_4[0]       = 0x01;
    // key_4[8]       = 0x01;

    // key_type key_5 = key_0;
    // key_5[0]       = 0x01;
    // key_5[8]       = 0x01;

    // key_type key_6 = key_0;
    // key_6[0]       = 0x01;
    // key_6[8]       = 0x01;

    {
        TethysStoreBuilder<kPageSize, key_type, size_t, Hasher, encoder_type>
            store_builder(builder_params);

        store_builder.insert_list(key_0, v_0);
        store_builder.insert_list(key_1, v_1);
        store_builder.insert_list(key_2, v_2);
        store_builder.insert_list(key_3, v_3);
        store_builder.insert_list(key_4, v_4);
        store_builder.insert_list(key_5, v_5);
        store_builder.insert_list(key_6, v_6);

        store_builder.build();
    }
    {
        TethysStore<
            kPageSize,
            key_type,
            size_t,
            Hasher,
            encoders::EncodeSeparateDecoder<key_type, size_t, kPageSize>>
            store(builder_params.tethys_table_path,
                  builder_params.tethys_stash_path);

        std::vector<size_t> res_0 = store.get_list(key_0);
        std::vector<size_t> res_1 = store.get_list(key_1);
        std::vector<size_t> res_2 = store.get_list(key_2);
        std::vector<size_t> res_3 = store.get_list(key_3);
        std::vector<size_t> res_4 = store.get_list(key_4);
        std::vector<size_t> res_5 = store.get_list(key_5);
        std::vector<size_t> res_6 = store.get_list(key_6);

        if (std::set<size_t>(res_0.begin(), res_0.end())
            != std::set<size_t>(v_0.begin(), v_0.end())) {
            std::cerr << "Invalid list 0\n";
        }
        if (std::set<size_t>(res_1.begin(), res_1.end())
            != std::set<size_t>(v_1.begin(), v_1.end())) {
            std::cerr << "Invalid list 1\n";
        }
        if (std::set<size_t>(res_2.begin(), res_2.end())
            != std::set<size_t>(v_2.begin(), v_2.end())) {
            std::cerr << "Invalid list 2\n";
        }
        if (std::set<size_t>(res_3.begin(), res_3.end())
            != std::set<size_t>(v_3.begin(), v_3.end())) {
            std::cerr << "Invalid list 3\n";
        }
        if (std::set<size_t>(res_4.begin(), res_4.end())
            != std::set<size_t>(v_4.begin(), v_4.end())) {
            std::cerr << "Invalid list 4\n";
        }
        if (std::set<size_t>(res_5.begin(), res_5.end())
            != std::set<size_t>(v_5.begin(), v_5.end())) {
            std::cerr << "Invalid list 5\n";
        }
        if (std::set<size_t>(res_6.begin(), res_6.end())
            != std::set<size_t>(v_6.begin(), v_6.end())) {
            std::cerr << "Invalid list 6\n";
        }
    }
}


void generate_random_store(size_t n_elements)
{
    const std::string test_dir = "tethys_test";

    if (sse::utility::is_directory(test_dir)) {
        std::cerr << "Random store already created\n";
        return;
    }
    sse::utility::create_directory(test_dir, static_cast<mode_t>(0700));

    constexpr size_t kPageSize = 4096; // 4 kB

    using value_type = uint64_t;
    using encoder_type
        = encoders::EncodeSeparateEncoder<key_type, value_type, kPageSize>;

    constexpr size_t kMaxListSize
        = kPageSize / sizeof(value_type) - encoder_type::kListControlValues;
    const size_t average_n_lists = 2 * (n_elements / kMaxListSize + 1);


    const size_t expected_tot_n_elements
        = n_elements + encoder_type::kListControlValues * average_n_lists;

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
    seed = 4171019158;
    gen.seed(seed);

    std::cerr << "RNG seed: " << seed << "\n";

    // key_type key;
    // key[0] = 'K';
    // key[1] = 'e';
    // key[2] = 'y';
    // key[3] = ':';
    // std::fill(key.begin() + 4, key.end(), 0x00);
    // size_t index_offset = 5;
    // // size_t index_offset = key.size() - sizeof(list_index);

    TethysStoreBuilder<kPageSize, key_type, value_type, Hasher, encoder_type>
        store_builder(builder_params);

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

    store_builder.build();
}

void store_queries(const size_t n_elements)
{
    const std::string test_dir = "tethys_test";

    if (!sse::utility::is_directory(test_dir)) {
        std::cerr << "Random store not created\n";
        return;
    }

    constexpr size_t kPageSize = 4096; // 4 kB

    using value_type = uint64_t;
    using encoder_type
        = encoders::EncodeSeparateEncoder<key_type, value_type, kPageSize>;

    constexpr size_t kMaxListSize
        = kPageSize / sizeof(value_type) - encoder_type::kListControlValues;
    const size_t average_n_lists = 2 * (n_elements / kMaxListSize + 1);

    constexpr size_t kKeySize = sse::crypto::Prf<kTableKeySize>::kKeySize;
    std::array<uint8_t, kKeySize> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);
    sse::crypto::Prf<kTableKeySize> prf(
        sse::crypto::Key<kKeySize>(prf_key.data()));

    using decoder_type
        = encoders::EncodeSeparateDecoder<key_type, value_type, kPageSize>;

    TethysStore<kPageSize, key_type, value_type, Hasher, decoder_type> store(
        test_dir + "/tethys_table.bin", test_dir + "/tethys_stash.bin");

    for (size_t i = 0; i < average_n_lists / 2; i++) {
        std::array<uint8_t, kTableKeySize> prf_out
            = prf.prf(reinterpret_cast<uint8_t*>(&i), sizeof(size_t));

        auto res = store.get_list(prf_out);

        if (res.size() > kMaxListSize) {
            std::cerr << "List too large??\n";
        }
        std::set<value_type> set(res.begin(), res.end());
        if (set.size() != 1) {
            std::cerr << set.size()
                      << " different results, while 1 was expected\n";
        }
        if (*set.begin() != i) {
            std::cerr << "Invalid element in the list: " << *set.begin()
                      << " was found instead of " << i << "\n";
        }
    }
}


int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();
    // test_dfs();
    // test_graphs();
    // test_store();

    const size_t n_elts = 1 << 19;
    generate_random_store(n_elts);
    store_queries(n_elts);

    sse::crypto::cleanup_crypto_lib();

    return 0;
}
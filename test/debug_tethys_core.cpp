#include "debug_tethys_core_utils.hpp"

#include <sse/schemes/tethys/details/tethys_graph.hpp>
#include <sse/schemes/tethys/encoders/encode_encrypt.hpp>
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
    auto   path = graph.find_source_sink_path(0, &cap);


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


    TethysStoreBuilderParam builder_params;
    builder_params.max_n_elements    = 0;
    builder_params.tethys_table_path = test_dir + "/tethys_table.bin";
    builder_params.tethys_stash_path = test_dir + "/tethys_stash.bin";
    builder_params.epsilon           = 0.1;

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

using value_type = uint64_t;

void generate_random_unencrypted_store(size_t n_elements)
{
    using encoder_type
        = encoders::EncodeSeparateEncoder<key_type, value_type, kPageSize>;
    using store_builder_type = TethysStoreBuilder<kPageSize,
                                                  key_type,
                                                  value_type,
                                                  Hasher,
                                                  encoder_type>;


    const std::string test_dir = "tethys_core_test";

    generate_random_store<store_builder_type>(n_elements, test_dir);
}

void unencrypted_store_queries(const size_t n_elements, bool check_results)
{
    const std::string test_dir = "tethys_core_test";

    using decoder_type
        = encoders::EncodeSeparateDecoder<key_type, value_type, kPageSize>;

    using store_type
        = TethysStore<kPageSize, key_type, value_type, Hasher, decoder_type>;

    store_read_queries<store_type>(n_elements, test_dir, check_results);
}

void async_unencrypted_store_queries(const size_t n_queries,
                                     const size_t n_elements,
                                     bool         decode,
                                     bool         check_results)
{
    const std::string test_dir = "tethys_core_test";

    using decoder_type
        = encoders::EncodeSeparateDecoder<key_type, value_type, kPageSize>;

    using store_type
        = TethysStore<kPageSize, key_type, value_type, Hasher, decoder_type>;

    async_store_read_queries<store_type>(
        n_queries, n_elements, test_dir, decode, check_results);
}


void generate_random_encrypted_store(size_t n_elements)
{
    using inner_encoder_type
        = encoders::EncodeSeparateEncoder<key_type, value_type, kPageSize>;
    using encoder_type
        = encoders::EncryptEncoder<inner_encoder_type, kPageSize>;
    using store_builder_type = TethysStoreBuilder<kPageSize,
                                                  key_type,
                                                  value_type,
                                                  Hasher,
                                                  encoder_type>;


    const std::string test_dir = "encrypted_tethys_core_test";

    std::array<uint8_t, 32> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);

    // encoder_type encryption_encoder(sse::crypto::Key<32>(prf_key.data()));

    encoder_type encryption_encoder(prf_key);

    generate_random_store<store_builder_type>(
        n_elements, test_dir, encryption_encoder, encryption_encoder);
}

void encrypted_store_queries(const size_t n_elements, bool check_results)
{
    const std::string test_dir = "encrypted_tethys_core_test";


    using inner_decoder_type
        = encoders::EncodeSeparateDecoder<key_type, value_type, kPageSize>;
    using decoder_type
        = encoders::DecryptDecoder<inner_decoder_type, kPageSize>;

    std::array<uint8_t, 32> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);

    // decoder_type encryption_decoder(sse::crypto::Key<32>(prf_key.data()));
    decoder_type encryption_decoder(prf_key);

    using store_type
        = TethysStore<kPageSize, key_type, value_type, Hasher, decoder_type>;

    store_read_queries<store_type>(
        n_elements, test_dir, check_results, encryption_decoder);
}

void async_encrypted_store_queries(const size_t n_queries,
                                   const size_t n_elements,
                                   bool         decode,
                                   bool         check_results)
{
    const std::string test_dir = "encrypted_tethys_core_test";


    using inner_decoder_type
        = encoders::EncodeSeparateDecoder<key_type, value_type, kPageSize>;
    using decoder_type
        = encoders::DecryptDecoder<inner_decoder_type, kPageSize>;

    std::array<uint8_t, 32> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);

    // decoder_type encryption_decoder(sse::crypto::Key<32>(prf_key.data()));
    decoder_type encryption_decoder(prf_key);


    using store_type
        = TethysStore<kPageSize, key_type, value_type, Hasher, decoder_type>;

    async_store_read_queries<store_type>(n_queries,
                                         n_elements,
                                         test_dir,
                                         decode,
                                         check_results,
                                         encryption_decoder);
}

int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();
    // test_dfs();
    // test_graphs();
    // test_store();

    sse::Benchmark::set_benchmark_file("benchmark_lat_tethys_core.out");

    const size_t n_elts = 1 << 23;
    // const size_t n_elts    = 1 << 27;
    const size_t n_queries = 1 << 20;
    (void)n_queries;
    generate_random_unencrypted_store(n_elts);
    // // unencrypted_store_queries(n_elts, true, false);
    // async_unencrypted_store_queries(n_elts, true,  false);


    // generate_random_encrypted_store(n_elts);
    // encrypted_store_queries(n_elts, true);
    // async_encrypted_store_queries(n_queries, n_elts, true, true);


    sse::crypto::cleanup_crypto_lib();

    return 0;
}
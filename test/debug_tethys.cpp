#include <sse/schemes/tethys/details/tethys_graph.hpp>
#include <sse/schemes/tethys/encoders/encode_encrypt.hpp>
#include <sse/schemes/tethys/encoders/encode_separate.hpp>
#include <sse/schemes/tethys/tethys_builder.hpp>
#include <sse/schemes/tethys/tethys_client.hpp>
#include <sse/schemes/tethys/tethys_server.hpp>
#include <sse/schemes/tethys/tethys_store.hpp>
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

using namespace sse::tethys;
using namespace sse::tethys::details;

constexpr size_t kPageSize = 4096; // 4 kB


void test_tethys_builder(size_t n_elements)
{
    using inner_encoder_type = encoders::
        EncodeSeparateEncoder<tethys_core_key_type, index_type, kPageSize>;
    using inner_decoder_type = inner_encoder_type::decoder_type;

    using tethys_builder_type = TethysBuilder<kPageSize, inner_encoder_type>;

    using value_encoder_type
        = tethys_builder_type::tethys_store_type::value_encoder_type;

    constexpr size_t kMaxListSize = kPageSize / sizeof(index_type)
                                    - value_encoder_type::kListControlValues;
    const size_t average_n_lists = 2 * (n_elements / kMaxListSize + 1);

    const size_t expected_tot_n_elements
        = n_elements + value_encoder_type::kListControlValues * average_n_lists;


    const std::string test_dir = "encrypted_tethys_test";

    if (!sse::utility::create_directory(test_dir, static_cast<mode_t>(0700))) {
        throw std::runtime_error(test_dir + ": unable to create directory");
    }

    const std::string counter_db_dir = test_dir + "/counters";

    TethysStoreBuilderParam builder_params;
    builder_params.max_n_elements    = expected_tot_n_elements;
    builder_params.tethys_table_path = test_dir + "/tethys_table.bin";
    builder_params.tethys_stash_path = test_dir + "/tethys_stash.bin";
    builder_params.epsilon           = 0.3;

    constexpr size_t              kKeySize = master_prf_type::kKeySize;
    std::array<uint8_t, kKeySize> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);

    std::array<uint8_t, kKeySize> client_prf_key = prf_key;

    constexpr size_t kEncryptionKeySize
        = tethys_builder_type::kEncryptionKeySize;

    std::array<uint8_t, kEncryptionKeySize> encryption_key;
    std::fill(encryption_key.begin(), encryption_key.end(), 0x11);

    {
        tethys_builder_type tethys_builder(
            builder_params,
            counter_db_dir,
            sse::crypto::Key<kKeySize>(prf_key.data()),
            encryption_key);


        tethys_builder.insert_list("alpha", {1, 2, 3, 4});
        tethys_builder.insert_list("beta", {5, 6, 7, 8});


        tethys_builder.build();
    }
    std::cerr << "Launch client & server\n";
    {
        TethysServer<tethys_server_store_type<kPageSize>> server(
            builder_params.tethys_table_path);

        TethysClient<inner_decoder_type> client(
            counter_db_dir,
            builder_params.tethys_stash_path,
            sse::crypto::Key<kKeySize>(client_prf_key.data()),
            encryption_key);

        auto sr  = client.search_request("alpha");
        auto bl  = server.search(sr);
        auto res = client.decode_search_results(sr, bl);

        for (auto&& i : res) {
            std::cerr << i << ",";
        }
        std::cerr << "\n";
    }
}


int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();
    // test_dfs();
    // test_graphs();
    // test_store();

    sse::Benchmark::set_benchmark_file("benchmark_lat_tethys.out");

    const size_t n_elts = 1 << 23;
    // const size_t n_elts    = 1 << 27;
    const size_t n_queries = 1 << 20;
    (void)n_queries;

    test_tethys_builder(n_elts);

    sse::crypto::cleanup_crypto_lib();

    return 0;
}
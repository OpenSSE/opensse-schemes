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

using inner_encoder_type = encoders::
    EncodeSeparateEncoder<tethys_core_key_type, index_type, kPageSize>;
using inner_decoder_type = inner_encoder_type::decoder_type;

using tethys_builder_type = TethysBuilder<kPageSize, inner_encoder_type>;

using value_encoder_type
    = tethys_builder_type::tethys_store_type::value_encoder_type;


constexpr size_t kMaxListSize
    = kPageSize / sizeof(index_type) - value_encoder_type::kListControlValues;


std::string counter_path(const std::string& path)
{
    return path + "/counters";
}


std::string table_path(const std::string& path)
{
    return path + "/tethys_table.bin";
}


std::string stash_path(const std::string& path)
{
    return path + "/tethys_stash.bin";
}


tethys_builder_type create_tethys_builder(
    const std::string&      path,
    sse::crypto::Key<32>&&  derivation_key,
    std::array<uint8_t, 32> encryption_key,
    size_t                  n_elts)
{
    if (!sse::utility::create_directory(path, static_cast<mode_t>(0700))) {
        throw std::runtime_error(path + ": unable to create directory");
    }

    const size_t average_n_lists = 2 * (n_elts / kMaxListSize + 1);

    const size_t expected_tot_n_elements
        = n_elts + value_encoder_type::kListControlValues * average_n_lists;

    const std::string counter_db_dir = counter_path(path);

    TethysStoreBuilderParam builder_params;
    builder_params.max_n_elements    = expected_tot_n_elements;
    builder_params.tethys_table_path = table_path(path);
    builder_params.tethys_stash_path = stash_path(path);
    builder_params.epsilon           = 0.3;


    return tethys_builder_type(builder_params,
                               counter_db_dir,
                               std::move(derivation_key),
                               encryption_key);
}


tethys_builder_type create_load_tethys_builder(
    const std::string&      path,
    sse::crypto::Key<32>&&  derivation_key,
    std::array<uint8_t, 32> encryption_key,
    size_t                  n_elts,
    const std::string&      json_path)
{
    auto builder = create_tethys_builder(
        path, std::move(derivation_key), std::move(encryption_key), n_elts);

    builder.load_inverted_index(json_path);

    return builder;
}

void print_list(const std::vector<index_type>& list)
{
    for (index_type i : list) {
        std::cerr << i << ",";
    }
    std::cerr << "\n";
}
void test_tethys_builder(size_t n_elements)
{
    const std::string test_dir = "encrypted_tethys_test";

    constexpr size_t              kKeySize = master_prf_type::kKeySize;
    std::array<uint8_t, kKeySize> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);

    std::array<uint8_t, kKeySize> client_prf_key = prf_key;

    constexpr size_t kEncryptionKeySize
        = tethys_builder_type::kEncryptionKeySize;

    std::array<uint8_t, kEncryptionKeySize> encryption_key;
    std::fill(encryption_key.begin(), encryption_key.end(), 0x11);

    {
        auto tethys_builder
            = create_tethys_builder(test_dir,
                                    sse::crypto::Key<kKeySize>(prf_key.data()),
                                    encryption_key,
                                    n_elements);

        std::list<index_type> long_list;
        for (size_t i = 0; i < 3 * kMaxListSize + 7; i++) {
            long_list.push_back(i);
        }


        tethys_builder.insert_list("alpha", long_list);
        tethys_builder.insert_list("beta", {5, 6, 7, 8});

        tethys_builder.load_inverted_index("../inverted_index_test.json");

        tethys_builder.build();
    }
    std::cerr << "Launch client & server\n";
    {
        TethysServer<tethys_server_store_type<kPageSize>> server(
            table_path(test_dir));

        TethysClient<inner_decoder_type> client(
            counter_path(test_dir),
            stash_path(test_dir),
            sse::crypto::Key<kKeySize>(client_prf_key.data()),
            encryption_key);

        auto sr  = client.search_request("alpha");
        auto bl  = server.search(sr);
        auto res = client.decode_search_results(sr, bl);
        print_list(res);


        sr  = client.search_request("igualada");
        bl  = server.search(sr);
        res = client.decode_search_results(sr, bl);
        print_list(res);
    }
}

// const std::string wp_path = "/home/rbost/Documents/WP_inv_index/"
//                             "inverted_index_100000.json";
// const size_t kDBSize = 1E5;

const std::string wp_path = "/home/rbost/Documents/WP_inv_index/"
                            "inverted_index_full.json";
const size_t kDBSize = 150e6;

void test_wikipedia(const std::string& db_path,
                    const std::string& wp_inverted_index)
{
    constexpr size_t              kKeySize = master_prf_type::kKeySize;
    std::array<uint8_t, kKeySize> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);

    std::array<uint8_t, kKeySize> client_prf_key = prf_key;

    constexpr size_t kEncryptionKeySize
        = tethys_builder_type::kEncryptionKeySize;

    std::array<uint8_t, kEncryptionKeySize> encryption_key;
    std::fill(encryption_key.begin(), encryption_key.end(), 0x11);

    (void)wp_inverted_index;

    {
        auto builder = create_load_tethys_builder(
            db_path,
            sse::crypto::Key<kKeySize>(prf_key.data()),
            encryption_key,
            kDBSize,
            wp_inverted_index);

        builder.build();
    }
    std::cerr << "Launch client & server\n";
    {
        TethysServer<tethys_server_store_type<kPageSize>> server(
            table_path(db_path));

        TethysClient<inner_decoder_type> client(
            counter_path(db_path),
            stash_path(db_path),
            sse::crypto::Key<kKeySize>(client_prf_key.data()),
            encryption_key);

        auto sr  = client.search_request("excav");
        auto bl  = server.search(sr);
        auto res = client.decode_search_results(sr, bl);

        print_list(res);
        std::cerr << "Size : " << res.size() << "\n";

        sr  = client.search_request("dvdfutur");
        bl  = server.search(sr);
        res = client.decode_search_results(sr, bl);

        print_list(res);
    }
}

int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();

    sse::Benchmark::set_benchmark_file("benchmark_lat_tethys.out");


    // test_tethys_builder(n_elts);
    test_wikipedia("wp_tethys", wp_path);

    sse::crypto::cleanup_crypto_lib();

    return 0;
}
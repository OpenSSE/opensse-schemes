#include "pluto_test_utils.hpp"

#include <sse/schemes/pluto/pluto_builder.hpp>
#include <sse/schemes/pluto/pluto_client.hpp>
#include <sse/schemes/pluto/pluto_server.hpp>
#include <sse/schemes/pluto/rocksdb_store.hpp>
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

using namespace sse::pluto;
using namespace sse::tethys;
using namespace sse::oceanus;

namespace sse {
namespace pluto {
namespace test {

void print_list(const std::vector<index_type>& list)
{
    for (index_type i : list) {
        std::cerr << i << ",";
    }
    std::cerr << "\n";
}

template<class Params>
void test_wikipedia(const std::string& db_path,
                    const std::string& wp_inverted_index,
                    const size_t       db_size)
{
    constexpr size_t              kKeySize = master_prf_type::kKeySize;
    std::array<uint8_t, kKeySize> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);

    std::array<uint8_t, kKeySize> client_prf_key = prf_key;

    constexpr size_t kEncryptionKeySize
        = pluto_builder_type::kEncryptionKeySize;

    std::array<uint8_t, kEncryptionKeySize> encryption_key;
    std::fill(encryption_key.begin(), encryption_key.end(), 0x11);

    {
        auto builder = create_load_pluto_builder<Params>(
            db_path,
            sse::crypto::Key<kKeySize>(prf_key.data()),
            encryption_key,
            db_size,
            wp_inverted_index);

        builder.build();
    }
    std::cerr << "Launch client & server\n";
    {
        PlutoServer<Params> server(tethys_table_path(db_path),
                                   make_pluto_ht_params<Params>(db_path));

        using inner_decoder_type =
            typename Params::tethys_inner_encoder_type::decoder_type;
        PlutoClient<inner_decoder_type> client(
            tethys_stash_path(db_path),
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

} // namespace test
} // namespace pluto
} // namespace sse

const std::string wp_path = "/home/rbost/Documents/WP_inv_index/"
                            "inverted_index_full.json";
const size_t kDBSize = 150e6;

int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();

    sse::Benchmark::set_benchmark_file("benchmark_lat_tethys.out");


    // test_tethys_builder(n_elts);
    sse::pluto::test::test_wikipedia<sse::pluto::test::default_param_type>(
        "wp_pluto", wp_path, kDBSize);

    sse::crypto::cleanup_crypto_lib();

    return 0;
}
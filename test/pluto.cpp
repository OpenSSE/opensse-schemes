
#include "pluto_test_utils.hpp"

#include <sse/schemes/pluto/pluto_client.hpp>
#include <sse/schemes/pluto/pluto_server.hpp>

#include <gtest/gtest.h>

namespace sse {
namespace pluto {
namespace test {

const std::string test_dir = "pluto_test";


template<class Params>
void test_pluto_builder(size_t n_elements, const std::string& json_path)
{
    constexpr size_t              kKeySize = 32;
    std::array<uint8_t, kKeySize> prf_key;
    std::fill(prf_key.begin(), prf_key.end(), 0x00);

    std::array<uint8_t, kKeySize> client_prf_key = prf_key;


    constexpr size_t kEncryptionKeySize
        = pluto_builder_type::kEncryptionKeySize;

    std::array<uint8_t, kEncryptionKeySize> encryption_key;
    std::fill(encryption_key.begin(), encryption_key.end(), 0x11);

    std::list<index_type> long_list;
    constexpr size_t      kMaxListSize = 500;
    for (size_t i = 0; i < 3 * kMaxListSize + 7; i++) {
        long_list.push_back(i);
    }
    std::list<index_type> short_list = {5, 6, 7, 8};

    {
        auto builder = create_pluto_builder<Params>(
            test_dir,
            sse::crypto::Key<kKeySize>(prf_key.data()),
            encryption_key,
            n_elements);

        builder.load_inverted_index(json_path);


        builder.insert_list("alpha", long_list);
        builder.insert_list("beta", short_list);

        builder.build();
    }
    std::cerr << "Launch client & server\n";
    {
        PlutoServer<Params> server(tethys_table_path(test_dir),
                                   make_pluto_ht_params<Params>(test_dir));
        using inner_decoder_type =
            typename Params::tethys_inner_encoder_type::decoder_type;
        PlutoClient<inner_decoder_type> client(
            tethys_stash_path(test_dir),
            sse::crypto::Key<kKeySize>(client_prf_key.data()),
            encryption_key);

        auto sr  = client.search_request("alpha");
        auto bl  = server.search(sr);
        auto res = client.decode_search_results(sr, bl);

        ASSERT_EQ(std::set<index_type>(res.begin(), res.end()),
                  std::set<index_type>(long_list.begin(), long_list.end()));

        sr  = client.search_request("beta");
        bl  = server.search(sr);
        res = client.decode_search_results(sr, bl);
        ASSERT_EQ(std::set<index_type>(res.begin(), res.end()),
                  std::set<index_type>(short_list.begin(), short_list.end()));

        sr  = client.search_request("igualada");
        bl  = server.search(sr);
        res = client.decode_search_results(sr, bl);
        ASSERT_EQ(std::set<index_type>(res.begin(), res.end()),
                  std::set<index_type>({12, 13, 14}));
    }
}

static void cleanup_store()
{
    sse::utility::remove_directory(test_dir);
}

// TEST(pluto, basic)
// {
//     cleanup_store();
//     test_pluto_builder<default_param_type>(1000,
//     "../inverted_index_test.json");
// }

template<typename T>
class PlutoTest : public testing::Test
{
    void SetUp() override
    {
        cleanup_store();
    }
    void TearDown() override
    {
        cleanup_store();
    }
};

using PlutoParamTypes
    = ::testing::Types<default_param_type, rocksdb_param_type>;

TYPED_TEST_SUITE(PlutoTest, PlutoParamTypes);

TYPED_TEST(PlutoTest, basic)
{
    test_pluto_builder<TypeParam>(1000, "../inverted_index_test.json");
}

} // namespace test
} // namespace pluto
} // namespace sse
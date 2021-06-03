#include "tethys_test_utils.hpp"

#include <sse/schemes/tethys/encoders/encode_encrypt.hpp>
#include <sse/schemes/tethys/encoders/encode_separate.hpp>
#include <sse/schemes/tethys/tethys_store.hpp>
#include <sse/schemes/tethys/tethys_store_builder.hpp>

#include <gtest/gtest.h>


namespace sse {
namespace tethys {
namespace test {

using namespace details;

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

const std::string test_dir   = "tethys_test";
const std::string table_path = test_dir + "/tethys_table.bin";
const std::string stash_path = test_dir + "/tethys_stash.bin";

// construct key-value pairs that force an overflow

std::vector<std::pair<key_type, std::vector<size_t>>> test_key_values(
    size_t v_size)
{
    std::vector<std::pair<key_type, std::vector<size_t>>> kv_vec;

    key_type            key_0 = {{0x00}};
    std::vector<size_t> v_0(v_size, 0xABABABABABABABAB);
    for (size_t i = 0; i < v_0.size(); i++) {
        v_0[i] += i;
    }

    kv_vec.emplace_back(std::make_pair(key_0, v_0));

    // force overflow
    key_type key_1 = key_0;
    key_1[8]       = 0x01;
    std::vector<size_t> v_1(v_size, 0xCDCDCDCDCDCDCDCD);
    for (size_t i = 0; i < v_1.size(); i++) {
        v_1[i] += i;
    }
    kv_vec.emplace_back(std::make_pair(key_1, v_1));

    key_type key_2 = key_0;
    key_2[0]       = 0x01;
    key_2[8]       = 0x00;
    std::vector<size_t> v_2(v_size, 0xEFEFEFEFEFEFEFEF);
    for (size_t i = 0; i < v_2.size(); i++) {
        v_2[i] += i;
    }
    kv_vec.emplace_back(std::make_pair(key_2, v_2));

    key_type key_3 = key_0;
    key_3[0]       = 0x01;
    key_3[8]       = 0x01;
    std::vector<size_t> v_3(v_size, 0x6969696969696969);
    for (size_t i = 0; i < v_3.size(); i++) {
        v_3[i] += i;
    }
    kv_vec.emplace_back(std::make_pair(key_3, v_3));

    key_type key_4 = key_0;
    key_4[0]       = 0x01;
    key_4[8]       = 0x02;
    std::vector<size_t> v_4(v_size, 0x7070707070707070);
    for (size_t i = 0; i < v_4.size(); i++) {
        v_4[i] += i;
    }
    kv_vec.emplace_back(std::make_pair(key_4, v_4));

    key_type key_5 = key_0;
    key_5[0]       = 0x02;
    key_5[8]       = 0x01;
    std::vector<size_t> v_5(v_size, 0x4242424242424242);
    for (size_t i = 0; i < v_5.size(); i++) {
        v_5[i] += i;
    }
    kv_vec.emplace_back(std::make_pair(key_5, v_5));

    key_type key_6 = key_0;
    key_6[0]       = 0x02;
    key_6[8]       = 0x02;
    std::vector<size_t> v_6(v_size, 0x5353535353535353);
    for (size_t i = 0; i < v_6.size(); i++) {
        v_6[i] += i;
    }
    kv_vec.emplace_back(std::make_pair(key_6, v_6));

    return kv_vec;
}

template<class Encoder>
size_t get_encoded_number_elements(
    const std::vector<std::pair<key_type, std::vector<size_t>>>& kv_vec)
{
    size_t n_elts = 0;
    for (const auto& kv : kv_vec) {
        n_elts += kv.second.size() + Encoder::kBucketControlValues;
    }

    return n_elts;
}

void build_store()
{
    TethysStoreBuilderParam builder_params;
    builder_params.max_n_elements    = 0;
    builder_params.tethys_table_path = table_path;
    builder_params.tethys_stash_path = stash_path;
    builder_params.epsilon           = 0.1;

    using encoder_type
        = encoders::EncodeSeparateEncoder<key_type, size_t, kPageSize>;

    sse::utility::remove_directory(test_dir);
    sse::utility::create_directory(test_dir, static_cast<mode_t>(0700));

    size_t v_size  = 450;
    auto   test_kv = test_key_values(v_size);

    builder_params.max_n_elements
        = get_encoded_number_elements<encoder_type>(test_kv);

    {
        TethysStoreBuilder<kPageSize, key_type, size_t, Hasher, encoder_type>
            store_builder(builder_params);

        for (const auto& kv : test_kv) {
            store_builder.insert_list(kv.first, kv.second);
        }
        store_builder.build();
    }
}

void test_store()
{
    TethysStore<kPageSize,
                key_type,
                size_t,
                Hasher,
                encoders::EncodeSeparateDecoder<key_type, size_t, kPageSize>>
        store(table_path, stash_path);

    size_t v_size  = 450;
    auto   test_kv = test_key_values(v_size);

    for (const auto& kv : test_kv) {
        std::vector<size_t> res = store.get_list(kv.first);

        ASSERT_EQ(std::set<size_t>(res.begin(), res.end()),
                  std::set<size_t>(kv.second.begin(), kv.second.end()));
    }
}

TEST(tethys_store, build_and_get)
{
    build_store();
    test_store();
}


} // namespace test
} // namespace tethys
} // namespace sse
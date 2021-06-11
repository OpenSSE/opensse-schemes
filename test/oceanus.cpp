#include <sse/schemes/oceanus/cuckoo.hpp>
#include <sse/schemes/oceanus/oceanus.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/utils.hpp>

#include <memory>

#include <gtest/gtest.h>

namespace sse {
namespace oceanus {
namespace test {

#define SSE_OCEANUS_TEST_FILE "oceanus_test.bin"

constexpr size_t kPageSize        = 4096; // 4 kB
constexpr double epsilon          = 0.1;
constexpr size_t max_search_depth = 200;

void build_server(const size_t                                 n_elts,
                  std::unique_ptr<Oceanus<kPageSize>>&         server,
                  std::unique_ptr<crypto::Prf<kTableKeySize>>& kdk)
{
    // check that the hash table file do not already exist
    ASSERT_FALSE(utility::exists(SSE_OCEANUS_TEST_FILE));

    // generate a new master prf (with a random key)
    kdk.reset(new crypto::Prf<kTableKeySize>());

    {
        OceanusBuilder<kPageSize> builder(
            SSE_OCEANUS_TEST_FILE, n_elts, epsilon, max_search_depth);

        for (uint64_t i = 0; i < n_elts; i++) {
            std::array<uint8_t, kTableKeySize> ht_key
                = kdk->prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));
            data_type<kPageSize> value;
            std::fill(value.begin(), value.end(), i);
            builder.insert(ht_key, value);
        }

        builder.commit();
        // the builder gets destructed here
    }
    // now construct the real server
    server.reset(new Oceanus<kPageSize>(SSE_OCEANUS_TEST_FILE));
}

void test_server_content(const size_t                               n_elts,
                         const std::unique_ptr<Oceanus<kPageSize>>& server,
                         const std::unique_ptr<crypto::Prf<kTableKeySize>>& kdk)
{
    for (uint64_t i = 0; i < n_elts; i++) {
        std::array<uint8_t, kTableKeySize> ht_key
            = kdk->prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));
        data_type<kPageSize> value = server->get(ht_key);
        data_type<kPageSize> expected_value;
        std::fill(expected_value.begin(), expected_value.end(), i);

        ASSERT_EQ(value, expected_value);
    }
}


void test_server_content_async(
    const size_t                                       n_elts,
    std::unique_ptr<Oceanus<kPageSize>>&               server,
    const std::unique_ptr<crypto::Prf<kTableKeySize>>& kdk)
{
    std::atomic<size_t> counter{0};
    {
        for (uint64_t i = 0; i < n_elts; i++) {
            std::array<uint8_t, kTableKeySize> ht_key
                = kdk->prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));

            auto callback =
                [i, &counter](
                    std::experimental::optional<data_type<kPageSize>> value) {
                    data_type<kPageSize> expected_value;
                    std::fill(expected_value.begin(), expected_value.end(), i);

                    ASSERT_TRUE(bool(value));
                    ASSERT_EQ(*value, expected_value);
                    counter++;
                };

            server->async_get(ht_key, callback);
        }
        server.reset(
            nullptr); // we do this to avoid having a more complicated
                      // synchronization to wait for the requests to complete
    }
    ASSERT_EQ(n_elts, counter);
}


void silent_cleanup_server()
{
    utility::remove_file(SSE_OCEANUS_TEST_FILE);
}


void cleanup_server()
{
    ASSERT_TRUE(utility::is_file(SSE_OCEANUS_TEST_FILE));

    ASSERT_TRUE(utility::remove_file(SSE_OCEANUS_TEST_FILE));
}

TEST(oceanus, build_and_get)
{
    const size_t                                n_elts = 10000;
    std::unique_ptr<Oceanus<kPageSize>>         server(nullptr);
    std::unique_ptr<crypto::Prf<kTableKeySize>> kdk(nullptr);

    silent_cleanup_server();
    build_server(n_elts, server, kdk);
    test_server_content(n_elts, server, kdk);

    cleanup_server();
}

TEST(oceanus, build_and_async_get)
{
    const size_t                                n_elts = 10000;
    std::unique_ptr<Oceanus<kPageSize>>         server(nullptr);
    std::unique_ptr<crypto::Prf<kTableKeySize>> kdk(nullptr);

    silent_cleanup_server();
    build_server(n_elts, server, kdk);
    test_server_content_async(n_elts, server, kdk);

    cleanup_server();
}

} // namespace test
} // namespace oceanus
} // namespace sse
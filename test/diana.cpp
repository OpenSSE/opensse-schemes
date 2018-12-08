#include "utility.hpp"

#include <sse/schemes/diana/diana_client.hpp>
#include <sse/schemes/diana/diana_server.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/utils.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <thread>


namespace sse {
namespace diana {
namespace test {

using TestDianaClient = sse::diana::DianaClient<uint64_t>;
using TestDianaServer = sse::diana::DianaServer<uint64_t>;


#define SSE_DIANA_TEST_DIR "test_diana"

constexpr auto client_master_key_path
    = SSE_DIANA_TEST_DIR "/derivation_master.key";
constexpr auto client_token_master_key_path
    = SSE_DIANA_TEST_DIR "/kw_token_master.key";

constexpr auto diana_test_dir   = SSE_DIANA_TEST_DIR;
constexpr auto client_data_path = SSE_DIANA_TEST_DIR "/client.dat";
constexpr auto server_data_path = SSE_DIANA_TEST_DIR "/server.dat";

void create_client_server(std::unique_ptr<TestDianaClient>& client,
                          std::unique_ptr<TestDianaServer>& server)
{
    // check that the key files do not already exist
    ASSERT_FALSE(utility::exists(client_master_key_path));
    ASSERT_FALSE(utility::exists(client_token_master_key_path));

    // start the client and the server from scratch

    // generate the keys
    std::array<uint8_t, TestDianaClient::kKeySize> master_key
        = sse::crypto::random_bytes<uint8_t, TestDianaClient::kKeySize>();
    std::array<uint8_t, TestDianaClient::kKeySize> token_master_key
        = sse::crypto::random_bytes<uint8_t, TestDianaClient::kKeySize>();

    // start by writing all the keys

    std::ofstream client_master_key_out(client_master_key_path);
    client_master_key_out << std::string(master_key.begin(), master_key.end());
    client_master_key_out.close();

    std::ofstream client_token_master_key_out(client_token_master_key_path);
    client_token_master_key_out
        << std::string(token_master_key.begin(), token_master_key.end());
    client_token_master_key_out.close();

    // create the client and the server

    client.reset(new TestDianaClient(
        client_data_path,
        sse::crypto::Key<TestDianaClient::kKeySize>(master_key.data()),
        sse::crypto::Key<TestDianaClient::kKeySize>(token_master_key.data())));

    server.reset(new TestDianaServer(server_data_path));
}

void restart_client_server(std::unique_ptr<TestDianaClient>& client,
                           std::unique_ptr<TestDianaServer>& server)
{
    std::ifstream client_master_key_in(client_master_key_path);
    std::ifstream client_token_master_key_in(client_token_master_key_path);

    // check that all the streams are in a valid state:
    // good() returns true if the file exists, false o/w
    ASSERT_TRUE(client_master_key_in.good());
    ASSERT_TRUE(client_token_master_key_in.good());
    // reload the keys from the key files


    std::stringstream client_master_key_buf, client_token_master_key_buf;

    client_master_key_buf << client_master_key_in.rdbuf();
    client_token_master_key_buf << client_token_master_key_in.rdbuf();

    std::array<uint8_t, 32> client_master_key_array;
    std::array<uint8_t, 32> client_token_master_key_array;

    ASSERT_EQ(client_master_key_buf.str().size(),
              client_master_key_array.size());
    ASSERT_EQ(client_token_master_key_buf.str().size(),
              client_token_master_key_array.size());

    auto client_master_key       = client_master_key_buf.str();
    auto client_token_master_key = client_token_master_key_buf.str();

    std::copy(client_master_key.begin(),
              client_master_key.end(),
              client_master_key_array.begin());
    std::copy(client_token_master_key.begin(),
              client_token_master_key.end(),
              client_token_master_key_array.begin());

    client.reset(
        new TestDianaClient(client_data_path,
                            sse::crypto::Key<TestDianaClient::kKeySize>(
                                client_master_key_array.data()),
                            sse::crypto::Key<TestDianaClient::kKeySize>(
                                client_token_master_key_array.data())));

    server.reset(new TestDianaServer(server_data_path));

    client_master_key_in.close();
    client_token_master_key_in.close();
}

TEST(diana, create_reload)
{
    std::unique_ptr<TestDianaClient> client;
    std::unique_ptr<TestDianaServer> server;

    // start by cleaning up the test directory
    sse::test::cleanup_directory(diana_test_dir);

    // first, create a client and a server from scratch
    create_client_server(client, server);

    // destroy them
    client.reset(nullptr);
    server.reset(nullptr);

    // reload them from the disk
    restart_client_server(client, server);
}

TEST(diana, insertion_search)
{
    std::unique_ptr<TestDianaClient> client;
    std::unique_ptr<TestDianaServer> server;

    // start by cleaning up the test directory
    sse::test::cleanup_directory(diana_test_dir);

    // first, create a client and a server from scratch
    create_client_server(client, server);

    const std::map<std::string, std::list<uint64_t>> test_db
        = {{"kw_1", {0, 1}}, {"kw_2", {0}}, {"kw_3", {0}}};

    sse::test::insert_database(client, server, test_db);
    sse::test::test_search_correctness(client, server, test_db);
}

template<class U, class V>
inline void check_same_results(const U& l1, const V& l2)
{
    std::set<uint64_t> s1(l1.begin(), l1.end());
    std::set<uint64_t> s2(l2.begin(), l2.end());

    ASSERT_EQ(s1, s2);
}

// To test all the different search algorithms
// We do not try to find any kind of concurrency bug here:
// this is kept for an other test, so the concurrency level is often set to 1
TEST(diana, search_algorithms)
{
    std::unique_ptr<TestDianaClient> client;
    std::unique_ptr<TestDianaServer> server;

    // start by cleaning up the test directory
    sse::test::cleanup_directory(diana_test_dir);

    // first, create a client and a server from scratch
    create_client_server(client, server);

    std::list<uint64_t> long_list;
    for (size_t i = 0; i < 1000; i++) {
        long_list.push_back(i);
    }
    const std::string                                keyword = "kw_1";
    const std::map<std::string, std::list<uint64_t>> test_db
        = {{keyword, long_list}};

    sse::test::insert_database(client, server, test_db);

    diana::SearchRequest u_req;


    std::mutex res_list_mutex;


    // Search requests can only be used once
    u_req    = client->search_request(keyword);
    auto res = server->search(u_req);

    u_req        = client->search_request(keyword);
    auto res_par = server->search_simple_parallel(u_req, 1);

    std::vector<uint64_t> res_par_vec;
    u_req = client->search_request(keyword);
    server->search_simple_parallel(u_req, 1, res_par_vec);
    // u_req, std::thread::hardware_concurrency());

    // u_req             = client->search_request(keyword);
    // auto res_par_full = server->search_parallel_full(u_req);

    check_same_results(long_list, res);
    check_same_results(long_list, res_par);
    check_same_results(long_list, res_par_vec);
    // check_same_results(long_list, res_par_full);


    auto search_callback
        = [&res_list_mutex](std::list<uint64_t>* res_list, uint64_t index) {
              std::lock_guard<std::mutex> lock(res_list_mutex);
              res_list->push_back(index);
          };
    std::function<void(uint64_t)> cb;

    std::list<uint64_t> res_callback;
    std::list<uint64_t> res_simple_callback;
    std::list<uint64_t> res_simple_par_callback;

    u_req = client->search_request(keyword);
    cb    = std::bind(search_callback, &res_callback, std::placeholders::_1);
    server->search(u_req, cb);
    check_same_results(long_list, res_callback);

    u_req = client->search_request(keyword);
    cb    = std::bind(
        search_callback, &res_simple_callback, std::placeholders::_1);
    server->search_simple(u_req, cb);
    check_same_results(long_list, res_simple_callback);

    u_req = client->search_request(keyword);
    cb    = std::bind(
        search_callback, &res_simple_par_callback, std::placeholders::_1);
    server->search_simple_parallel(u_req, cb, 1, false);
    check_same_results(long_list, res_simple_par_callback);

    res_simple_par_callback.clear();
    auto thread_local_callback
        = [&res_list_mutex, &res_simple_par_callback](uint64_t index, uint8_t) {
              std::lock_guard<std::mutex> lock(res_list_mutex);
              res_simple_par_callback.push_back(index);
          };
    u_req = client->search_request(keyword);
    server->search_simple_parallel(u_req, thread_local_callback, 1, false);
    check_same_results(long_list, res_simple_par_callback);
}

TEST(diana, bulk_update)
{
    std::unique_ptr<TestDianaClient> client;
    std::unique_ptr<TestDianaServer> server;

    // start by cleaning up the test directory
    sse::test::cleanup_directory(diana_test_dir);

    // first, create a client and a server from scratch
    create_client_server(client, server);

    std::list<std::pair<std::string, uint64_t>> update_list;
    constexpr size_t                            n_test_entries = 1000;

    for (size_t i = 0; i < n_test_entries; i++) {
        uint8_t kw_index = static_cast<uint8_t>(i);
        update_list.push_back(
            std::make_pair("kw_" + std::to_string(kw_index), i));
    }

    auto bulk_up_req = client->bulk_update_request(update_list);
    for (auto it = bulk_up_req.begin(); it != bulk_up_req.end(); ++it) {
        server->update(*it);
    }

    // test the results
    for (uint16_t kw_index = 0; kw_index <= 0xFF; kw_index++) {
        auto req = client->search_request(
            "kw_" + std::to_string(static_cast<uint16_t>(kw_index)));
        auto response = server->search_simple_parallel(req, 1);

        std::list<uint64_t> expected;
        for (size_t i = kw_index; i < n_test_entries; i += 0xFF + 1) {
            expected.push_back(i);
        }

        check_same_results(expected, response);
    }
}
} // namespace test
} // namespace diana
} // namespace sse
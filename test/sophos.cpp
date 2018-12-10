#include "utility.hpp"

#include <sse/schemes/sophos/sophos_client.hpp>
#include <sse/schemes/sophos/sophos_server.hpp>
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
namespace sophos {
namespace test {

#define SSE_SOPHOS_TEST_DIR "test_sophos"

constexpr auto client_sk_path = SSE_SOPHOS_TEST_DIR "/tdp_sk.key";
constexpr auto client_master_key_path
    = SSE_SOPHOS_TEST_DIR "/derivation_master.key";
constexpr auto client_tdp_prg_key_path = SSE_SOPHOS_TEST_DIR "/tdp_prg.key";
constexpr auto server_pk_path          = SSE_SOPHOS_TEST_DIR "/tdp_pk.key";


constexpr auto sophos_test_dir  = SSE_SOPHOS_TEST_DIR;
constexpr auto client_data_path = SSE_SOPHOS_TEST_DIR "/client.dat";
constexpr auto server_data_path = SSE_SOPHOS_TEST_DIR "/server.dat";

void create_client_server(std::unique_ptr<sophos::SophosClient>& client,
                          std::unique_ptr<sophos::SophosServer>& server)
{
    // check that the key files do not already exist
    ASSERT_FALSE(utility::exists(client_sk_path));
    ASSERT_FALSE(utility::exists(client_master_key_path));
    ASSERT_FALSE(utility::exists(client_tdp_prg_key_path));
    ASSERT_FALSE(utility::exists(server_pk_path));

    // start the client and the server from scratch

    // generate the keys
    std::array<uint8_t, sophos::SophosClient::kKeySize> derivation_master_key
        = sse::crypto::random_bytes<uint8_t, sophos::SophosClient::kKeySize>();
    std::array<uint8_t, sophos::SophosClient::kKeySize> rsa_prg_key
        = sse::crypto::random_bytes<uint8_t, sophos::SophosClient::kKeySize>();
    sse::crypto::TdpInverse tdp;

    // start by writing all the keys

    std::ofstream client_sk_out(client_sk_path);
    client_sk_out << tdp.private_key();
    client_sk_out.close();

    std::ofstream client_master_key_out(client_master_key_path);
    client_master_key_out << std::string(derivation_master_key.begin(),
                                         derivation_master_key.end());
    client_master_key_out.close();

    std::ofstream client_tdp_prg_key_out(client_tdp_prg_key_path);
    client_tdp_prg_key_out << std::string(rsa_prg_key.begin(),
                                          rsa_prg_key.end());
    client_tdp_prg_key_out.close();

    std::ofstream server_pk_out(server_pk_path);
    server_pk_out << tdp.public_key();
    server_pk_out.close();

    // create the client and the server

    client.reset(new sophos::SophosClient(
        client_data_path,
        tdp.private_key(),
        sse::crypto::Key<SophosClient::kKeySize>(derivation_master_key.data()),
        sse::crypto::Key<SophosClient::kKeySize>(rsa_prg_key.data())));

    server.reset(new sophos::SophosServer(server_data_path, tdp.public_key()));
}

void restart_client_server(std::unique_ptr<sophos::SophosClient>& client,
                           std::unique_ptr<sophos::SophosServer>& server)
{
    std::ifstream client_sk_in(client_sk_path);
    std::ifstream client_master_key_in(client_master_key_path);
    std::ifstream client_tdp_prg_key_in(client_tdp_prg_key_path);
    std::ifstream server_pk_in(server_pk_path);

    // check that all the streams are in a valid state:
    // good() returns true if the file exists, false o/w
    ASSERT_TRUE(client_sk_in.good());
    ASSERT_TRUE(client_master_key_in.good());
    ASSERT_TRUE(client_tdp_prg_key_in.good());
    ASSERT_TRUE(server_pk_in.good());
    // reload the keys from the key filesi


    std::stringstream client_sk_buf, client_master_key_buf, server_pk_buf,
        client_tdp_prg_key_buf;

    client_sk_buf << client_sk_in.rdbuf();
    client_master_key_buf << client_master_key_in.rdbuf();
    server_pk_buf << server_pk_in.rdbuf();
    client_tdp_prg_key_buf << client_tdp_prg_key_in.rdbuf();

    std::array<uint8_t, 32> client_master_key_array;
    std::array<uint8_t, 32> client_tdp_prg_key_array;

    ASSERT_EQ(client_master_key_buf.str().size(),
              client_master_key_array.size());
    ASSERT_EQ(client_tdp_prg_key_buf.str().size(),
              client_tdp_prg_key_array.size());

    auto client_master_key  = client_master_key_buf.str();
    auto client_tdp_prg_key = client_tdp_prg_key_buf.str();

    std::copy(client_master_key.begin(),
              client_master_key.end(),
              client_master_key_array.begin());
    std::copy(client_tdp_prg_key.begin(),
              client_tdp_prg_key.end(),
              client_tdp_prg_key_array.begin());

    client.reset(new sophos::SophosClient(
        client_data_path,
        client_sk_buf.str(),
        sse::crypto::Key<sophos::SophosClient::kKeySize>(
            client_master_key_array.data()),
        sse::crypto::Key<sophos::SophosClient::kKeySize>(
            client_tdp_prg_key_array.data())));

    server.reset(
        new sophos::SophosServer(server_data_path, server_pk_buf.str()));

    client_sk_in.close();
    client_master_key_in.close();
    server_pk_in.close();

    // check that the TDP is correct
    sse::crypto::TdpInverse tdp(client_sk_buf.str());
    ASSERT_EQ(tdp.public_key(), server->public_key());
}

TEST(sophos, create_reload)
{
    std::unique_ptr<sophos::SophosClient> client;
    std::unique_ptr<sophos::SophosServer> server;

    // start by cleaning up the test directory
    sse::test::cleanup_directory(sophos_test_dir);

    // first, create a client and a server from scratch
    create_client_server(client, server);

    // destroy them
    client.reset(nullptr);
    server.reset(nullptr);

    // reload them from the disk
    restart_client_server(client, server);
}

TEST(sophos, insertion_search)
{
    std::unique_ptr<sophos::SophosClient> client;
    std::unique_ptr<sophos::SophosServer> server;

    // start by cleaning up the test directory
    sse::test::cleanup_directory(sophos_test_dir);

    // first, create a client and a server from scratch
    create_client_server(client, server);

    const std::map<std::string, std::list<uint64_t>> test_db
        = {{"kw_1", {0, 1}}, {"kw_2", {0}}, {"kw_3", {0}}};

    sse::test::insert_database(client, server, test_db);
    sse::test::test_search_correctness(client, server, test_db);
}

inline void check_same_results(const std::list<uint64_t>& l1,
                               const std::list<uint64_t>& l2)
{
    std::set<uint64_t> s1(l1.begin(), l1.end());
    std::set<uint64_t> s2(l2.begin(), l2.end());

    EXPECT_EQ(s1, s2);
}

// To test all the different search algorithms
// We do not try to find any kind of concurrency bug here:
// this is kept for an other test, so the concurrency level is often set to 1
TEST(sophos, search_algorithms)
{
    std::unique_ptr<sophos::SophosClient> client;
    std::unique_ptr<sophos::SophosServer> server;

    // start by cleaning up the test directory
    sse::test::cleanup_directory(sophos_test_dir);

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

    sophos::SearchRequest u_req;

    // first check that a search request on a non-existent keyword has an
    // add_count set to 0
    u_req = client->search_request("??");
    EXPECT_EQ(u_req.add_count, 0);

    std::mutex res_list_mutex;

    auto search_callback
        = [&res_list_mutex](std::list<uint64_t>* res_list, uint64_t index) {
              std::lock_guard<std::mutex> lock(res_list_mutex);
              res_list->push_back(index);
          };

    // Search requests can only be used once
    u_req    = client->search_request(keyword);
    auto res = server->search(u_req);

    u_req        = client->search_request(keyword);
    auto res_par = server->search_parallel(u_req, 1);
    // = server->search_parallel(u_req, std::thread::hardware_concurrency());

    u_req              = client->search_request(keyword);
    auto res_par_light = server->search_parallel_light(
        u_req, std::thread::hardware_concurrency());
    // u_req, std::thread::hardware_concurrency());

    check_same_results(long_list, res);
    check_same_results(long_list, res_par);
    check_same_results(long_list, res_par_light);

    std::list<uint64_t> res_callback;
    std::list<uint64_t> res_par_callback;
    std::list<uint64_t> res_par_light_callback;

    u_req = client->search_request(keyword);
    server->search_callback(
        u_req,
        std::bind(search_callback, &res_callback, std::placeholders::_1));
    check_same_results(long_list, res_callback);

    u_req = client->search_request(keyword);
    server->search_parallel_callback(
        u_req,
        std::bind(search_callback, &res_par_callback, std::placeholders::_1),
        std::thread::hardware_concurrency() - 2,
        1,
        1);
    check_same_results(long_list, res_par_callback);

    u_req = client->search_request(keyword);
    server->search_parallel_light_callback(u_req,
                                           std::bind(search_callback,
                                                     &res_par_light_callback,
                                                     std::placeholders::_1),
                                           std::thread::hardware_concurrency());
    check_same_results(long_list, res_par_light_callback);
}
} // namespace test
} // namespace sophos
} // namespace sse
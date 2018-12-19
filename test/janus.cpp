#include "utility.hpp"

#include <sse/schemes/janus/janus_client.hpp>
#include <sse/schemes/janus/janus_server.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/utils.hpp>

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

namespace sse {
namespace janus {
namespace test {


using Client = sse::janus::JanusClient;
using Server = sse::janus::JanusServer;

#define SSE_JANUS_TEST_DIR "test_janus"

constexpr auto client_master_key_path = SSE_JANUS_TEST_DIR "/client_master.key";

constexpr auto janus_test_dir = SSE_JANUS_TEST_DIR;

constexpr auto client_add_data_path = SSE_JANUS_TEST_DIR "/client.add.dat";
constexpr auto client_del_data_path = SSE_JANUS_TEST_DIR "/client.del.dat";
constexpr auto client_search_data_path
    = SSE_JANUS_TEST_DIR "/client.search.dat";

constexpr auto server_add_data_path   = SSE_JANUS_TEST_DIR "/server.add.dat";
constexpr auto server_del_data_path   = SSE_JANUS_TEST_DIR "/server.del.dat";
constexpr auto server_cache_data_path = SSE_JANUS_TEST_DIR "/server.cache.dat";

using master_key_type = sse::crypto::Key<sse::crypto::punct::kMasterKeySize>;
constexpr size_t kMasterKeySize = sse::crypto::punct::kMasterKeySize;

void create_client_server(std::unique_ptr<Client>& client,
                          std::unique_ptr<Server>& server)
{
    // check that the key files do not already exist
    ASSERT_FALSE(utility::exists(client_master_key_path));

    // start the client and the server from scratch

    // generate the keys
    std::array<uint8_t, kMasterKeySize> master_key
        = sse::crypto::random_bytes<uint8_t, kMasterKeySize>();

    // start by writing all the keys

    std::ofstream client_master_key_out(client_master_key_path);
    client_master_key_out << std::string(master_key.begin(), master_key.end());
    client_master_key_out.close();

    // create the client and the server

    client.reset(
        new Client(client_search_data_path,
                   client_add_data_path,
                   client_del_data_path,
                   sse::crypto::Key<kMasterKeySize>(master_key.data())));

    server.reset(new Server(
        server_add_data_path, server_del_data_path, server_cache_data_path));
}


void restart_client_server(std::unique_ptr<Client>& client,
                           std::unique_ptr<Server>& server)
{
    std::ifstream client_master_key_in(client_master_key_path);

    // check that all the streams are in a valid state:
    // good() returns true if the file exists, false o/w
    ASSERT_TRUE(client_master_key_in.good());

    // reload the keys from the key files


    std::stringstream client_master_key_buf;

    client_master_key_buf << client_master_key_in.rdbuf();

    std::array<uint8_t, 32> client_master_key_array;

    ASSERT_EQ(client_master_key_buf.str().size(),
              client_master_key_array.size());

    auto client_master_key = client_master_key_buf.str();

    std::copy(client_master_key.begin(),
              client_master_key.end(),
              client_master_key_array.begin());

    client.reset(new Client(
        client_search_data_path,
        client_add_data_path,
        client_del_data_path,
        sse::crypto::Key<kMasterKeySize>(client_master_key_array.data())));

    server.reset(new Server(
        server_add_data_path, server_del_data_path, server_cache_data_path));

    client_master_key_in.close();
}


TEST(janus, create_reload)
{
    std::unique_ptr<Client> client;
    std::unique_ptr<Server> server;

    // start by cleaning up the test directory
    sse::test::cleanup_directory(janus_test_dir);

    // first, create a client and a server from scratch
    create_client_server(client, server);

    // destroy them
    client.reset(nullptr);
    server.reset(nullptr);

    // reload them from the disk
    restart_client_server(client, server);
}

TEST(janus, insertion_search)
{
    std::unique_ptr<Client> client;
    std::unique_ptr<Server> server;

    // start by cleaning up the test directory
    sse::test::cleanup_directory(janus_test_dir);

    // first, create a client and a server from scratch
    create_client_server(client, server);

    const std::map<std::string, std::list<uint64_t>> test_db
        = {{"kw_1", {0, 1}}, {"kw_2", {0}}, {"kw_3", {0}}};

    sse::test::insert_database(client, server, test_db);
    sse::test::test_search_correctness(client, server, test_db);
}

template<class SearchFun>
static void test_search_removal(SearchFun search_fun)
{
    std::unique_ptr<Client> client;
    std::unique_ptr<Server> server;

    // start by cleaning up the test directory
    sse::test::cleanup_directory(janus_test_dir);

    // first, create a client and a server from scratch
    create_client_server(client, server);

    std::map<std::string, std::list<uint64_t>> test_db = {{"kw_1", {0, 1}},
                                                          {"kw_2", {0}},
                                                          {"kw_3", {0}},
                                                          {"kw_4", {1, 2, 3}},
                                                          {"kw_5", {5}}};

    sse::test::insert_database(client, server, test_db);

    // remove entries before searching
    auto r_request = client->removal_request("kw_4", 1);
    server->remove(r_request);
    test_db["kw_4"].remove(1);

    r_request = client->removal_request("kw_5", 5);
    server->remove(r_request);
    test_db["kw_5"].remove(5);

    // search
    // sse::test::test_search_correctness(client, server, test_db);
    auto search_req_fun = [](Client& client, const std::string& kw) {
        return client.search_request(kw);
    };
    sse::test::test_search_correctness(
        client, server, test_db, search_req_fun, search_fun);

    // remove additional entries
    r_request = client->removal_request("kw_1", 0);
    server->remove(r_request);
    test_db["kw_1"].remove(0);

    r_request = client->removal_request("kw_2", 0);
    server->remove(r_request);
    test_db["kw_2"].remove(0);

    sse::test::test_search_correctness(
        client, server, test_db, search_req_fun, search_fun);

    // do it twice to test the cache
    sse::test::test_search_correctness(
        client, server, test_db, search_req_fun, search_fun);
}


TEST(janus, insertion_removal_search)
{
    auto search_fun = [](Server& server, janus::SearchRequest& req) {
        return server.search(req);
    };
    test_search_removal(search_fun);
}

TEST(janus, insertion_removal_parallel_search)
{
    auto search_fun = [](Server& server, janus::SearchRequest& req) {
        return server.search_parallel(req, 1);
    };
    test_search_removal(search_fun);
}

} // namespace test
} // namespace janus
} // namespace sse
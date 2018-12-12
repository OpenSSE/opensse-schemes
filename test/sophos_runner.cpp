#include "utility.hpp"

#include <sse/runners/sophos/sophos_client_runner.hpp>
#include <sse/runners/sophos/sophos_server_runner.hpp>
#include <sse/schemes/sophos/sophos_client.hpp>
#include <sse/schemes/sophos/sophos_server.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/utils.hpp>

#include <grpc++/create_channel.h>
#include <grpc++/impl/codegen/service_type.h>
#include <grpc++/server_builder.h>

#include <condition_variable>
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

// class SophosImpl
// {
// public:
//     explicit SophosImpl(std::string path);
// };

namespace test {

#define SSE_SOPHOS_TEST_DIR "test_sophos_runners"

constexpr auto sophos_test_dir       = SSE_SOPHOS_TEST_DIR;
constexpr auto sophos_server_db_path = SSE_SOPHOS_TEST_DIR "/server.db";
constexpr auto sophos_client_db_path = SSE_SOPHOS_TEST_DIR "/client.db";
constexpr auto sophos_server_address = "127.0.0.1:4242";

static void create_client_server(const std::string& client_db_path,
                                 const std::string& server_db_path,
                                 const std::string& server_address,
                                 std::unique_ptr<SophosClientRunner>& client,
                                 std::unique_ptr<grpc::Service>&      service,
                                 std::unique_ptr<grpc::Server>&       server)
{
    server
        = build_sophos_server(server_address, server_db_path, false, service);

    // Create the channel
    std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(
        server_address, grpc::InsecureChannelCredentials()));
    // Create the client
    client.reset(new SophosClientRunner(channel, client_db_path));
}

TEST(sophos_runner, insertion_search)
{
    sse::test::cleanup_directory(sophos_test_dir);

    std::unique_ptr<SophosClientRunner> client;
    std::unique_ptr<grpc::Service>      service;
    std::unique_ptr<grpc::Server>       server;

    create_client_server(sophos_client_db_path,
                         sophos_server_db_path,
                         sophos_server_address,
                         client,
                         service,
                         server);

    const std::map<std::string, std::list<uint64_t>> test_db
        = {{"kw_1", {0, 1}}, {"kw_2", {0}}, {"kw_3", {0}}};

    sse::test::insert_database(client, test_db);
    sse::test::test_search_correctness(client, test_db);

    server->Shutdown();
}

TEST(sophos_runner, start_stop)
{
    sse::test::cleanup_directory(sophos_test_dir);

    std::unique_ptr<SophosClientRunner> client;
    std::unique_ptr<grpc::Service>      service;
    std::unique_ptr<grpc::Server>       server;

    create_client_server(sophos_client_db_path,
                         sophos_server_db_path,
                         sophos_server_address,
                         client,
                         service,
                         server);
    const std::map<std::string, std::list<uint64_t>> test_db
        = {{"kw_1", {0, 1}}, {"kw_2", {0}}, {"kw_3", {0}}};

    sse::test::insert_database(client, test_db);

    // close/destroy the client
    client.reset(nullptr);
    // shutdown the server
    server->Shutdown();
    // close the service
    service.reset(nullptr);

    create_client_server(sophos_client_db_path,
                         sophos_server_db_path,
                         sophos_server_address,
                         client,
                         service,
                         server);

    // do the tests
    sse::test::test_search_correctness(client, test_db);

    server->Shutdown();
}
} // namespace test
} // namespace sophos
} // namespace sse

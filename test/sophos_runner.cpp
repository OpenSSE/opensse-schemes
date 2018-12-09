#include "utility.hpp"

#include <sse/runners/sophos/sophos_client_runner.hpp>
#include <sse/runners/sophos/sophos_server_runner.hpp>
#include <sse/schemes/sophos/sophos_client.hpp>
#include <sse/schemes/sophos/sophos_server.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/utils.hpp>

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

class SophosImpl
{
public:
    explicit SophosImpl(std::string path);
};

namespace test {

#define SSE_SOPHOS_TEST_DIR "test_sophos_runners"

constexpr auto sophos_test_dir = SSE_SOPHOS_TEST_DIR;
constexpr auto server_db_path  = SSE_SOPHOS_TEST_DIR "/server.db";
constexpr auto client_db_path  = SSE_SOPHOS_TEST_DIR "/client.db";

TEST(sophos_runner, insertion_search)
{
    sse::test::cleanup_directory(sophos_test_dir);

    grpc::ServerBuilder            builder;
    std::unique_ptr<grpc::Service> service;

    auto server = build_sophos_server(builder, server_db_path, false, service);

    // Get the in-process channel
    std::shared_ptr<grpc::Channel> channel
        = server->InProcessChannel(grpc::ChannelArguments());
    // Create the client
    std::unique_ptr<SophosClientRunner> client(
        new SophosClientRunner(channel, client_db_path));

    const std::map<std::string, std::list<uint64_t>> test_db
        = {{"kw_1", {0, 1}}, {"kw_2", {0}}, {"kw_3", {0}}};

    sse::test::insert_database(client, test_db);
    sse::test::test_search_correctness(client, test_db);

    server->Shutdown()
}

} // namespace test
} // namespace sophos
} // namespace sse

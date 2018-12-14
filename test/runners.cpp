#include "diana_runner.hpp"
#include "sophos_runner.hpp"
#include "utility.hpp"

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
namespace test {
// The runners class should be as follows
// class SophosRunner
// {
// public:
//     using ClientRunner = SophosClientRunner;
//     using ServerRunner = SophosServerRunner;

//     constexpr auto test_dir;
//     constexpr auto server_db_path = SSE_DIANA_TEST_DIR "/server.db";
//     constexpr auto client_db_path = SSE_DIANA_TEST_DIR "/client.db";
//     constexpr auto server_address = "127.0.0.1:4343";
// }

template<typename Runner>
class RunnerTest : public ::testing::Test
{
public:
    using ClientRunner = typename Runner::ClientRunner;
    using ServerRunner = typename Runner::ServerRunner;

protected:
    void create_client_server()
    {
        server_.reset(
            new ServerRunner(Runner::server_address, Runner::server_db_path));
        server_->set_async_search(false);

        // Create the channel
        std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(
            Runner::server_address, grpc::InsecureChannelCredentials()));
        // Create the client
        client_.reset(new ClientRunner(channel, Runner::client_db_path));
    }

    void destroy_client_server()
    {
        client_.reset(nullptr);
        server_->shutdown();
        server_.reset(nullptr);
    }

    virtual void SetUp()
    {
        sse::test::cleanup_directory(Runner::test_dir);

        create_client_server();
    }

    // You can define per-test tear-down logic as usual.
    virtual void TearDown()
    {
        destroy_client_server();
    }

    std::unique_ptr<ClientRunner> client_;
    std::unique_ptr<ServerRunner> server_;
};

// TYPED_TEST_CASE(RunnerTest);

using RunnerTypes = ::testing::Types<sse::sophos::test::SophosRunner,
                                     sse::diana::test::DianaRunner>;
TYPED_TEST_CASE(RunnerTest, RunnerTypes);


TYPED_TEST(RunnerTest, insertion_search)
{
    const std::map<std::string, std::list<uint64_t>> test_db
        = {{"kw_1", {0, 1}}, {"kw_2", {0}}, {"kw_3", {0}}};

    sse::test::insert_database(this->client_, test_db);
    sse::test::test_search_correctness(this->client_, test_db);
}


TYPED_TEST(RunnerTest, start_stop)
{
    const std::map<std::string, std::list<uint64_t>> test_db
        = {{"kw_1", {0, 1}}, {"kw_2", {0}}, {"kw_3", {0}}};

    sse::test::insert_database(this->client_, test_db);

    this->destroy_client_server();

    this->create_client_server();

    sse::test::test_search_correctness(this->client_, test_db);
}

// REGISTER_TYPED_TEST_CASE_P(RunnerTest, insertion_search, start_stop);

} // namespace test
} // namespace sse
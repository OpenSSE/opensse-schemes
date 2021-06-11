#include "diana_runner.hpp"
#include "sophos_runner.hpp"
#include "test.hpp"
#include "utility.hpp"

#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/utils.hpp>
#include <sse/dbparser/json/DBParserJSON.h>

#include <grpcpp/grpcpp.h>

#include <algorithm>
#include <condition_variable>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

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
TYPED_TEST_SUITE(RunnerTest, RunnerTypes);


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


TYPED_TEST(RunnerTest, search_async)
{
    this->server_->set_async_search(true);

    std::list<uint64_t> long_list;
    for (size_t i = 0; i < 1000; i++) {
        long_list.push_back(i);
    }
    const std::string                                keyword = "kw_1";
    const std::map<std::string, std::list<uint64_t>> test_db
        = {{keyword, long_list}};


    sse::test::insert_database(this->client_, test_db);
    sse::test::test_search_correctness(this->client_, test_db);
}

TYPED_TEST(RunnerTest, insert_session)
{
    this->client_->start_update_session();
    const std::map<std::string, std::list<uint64_t>> test_db
        = {{"kw_1", {0, 1}}, {"kw_2", {0}}, {"kw_3", {0}}};
    iterate_database(test_db, [this](const std::string& kw, uint64_t index) {
        this->client_->insert_in_session(kw, index);
    });

    this->client_->end_update_session();
    sse::test::test_search_correctness(this->client_, test_db);
}

TYPED_TEST(RunnerTest, load_JSON)
{
    // this test is a bit inefficient as it loads the same JSON library twice :
    // once by the test itself to get the reference library, and once by the
    // client to perform the actual insertions.
    // However, this is unavoidable as long as we cannot hook the parser in the
    // client

    ASSERT_TRUE(sse::utility::exists(sse::test::JSON_test_library));

    // parse the JSON to create the reference database
    dbparser::DBParserJSON test_parser(sse::test::JSON_test_library);

    std::map<std::string, std::list<uint64_t>> ref_db;

    auto db_callback
        = [&ref_db](const std::string kw, const std::list<unsigned> docs) {
              std::list<uint64_t>& elts = ref_db[kw];
              elts.insert(elts.end(), docs.begin(), docs.end());
          };
    test_parser.addCallbackList(db_callback);

    test_parser.parse();

    // now, call the JSON invertion method of the client
    this->client_->load_inverted_index(sse::test::JSON_test_library);


    // check that everything happened correctly
    sse::test::test_search_correctness(this->client_, ref_db);
}
} // namespace test
} // namespace sse
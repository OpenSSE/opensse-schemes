
#include <sse/schemes/sophos/sophos_client.hpp>
#include <sse/schemes/sophos/sophos_server.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/utils.hpp>

#include <gtest/gtest.h>

#include <fstream>
#include <iostream>
#include <memory>

namespace sse {
namespace sophos {
namespace test {

constexpr auto client_sk_path          = "test_sophos/tdp_sk.key";
constexpr auto client_master_key_path  = "test_sophos/derivation_master.key";
constexpr auto client_tdp_prg_key_path = "test_sophos/tdp_prg.key";
constexpr auto server_pk_path          = "test_sophos/tdp_pk.key";

#define SSE_SOPHOS_TEST_DIR "test_sophos"

constexpr auto sophos_test_dir  = SSE_SOPHOS_TEST_DIR;
constexpr auto client_data_path = SSE_SOPHOS_TEST_DIR "/client.dat";
constexpr auto server_data_path = SSE_SOPHOS_TEST_DIR "/server.dat";

void create_client_server(std::unique_ptr<sophos::SophosClient>& client,
                          std::unique_ptr<sophos::SophosServer>& server)
{
    std::ifstream client_sk_in(client_sk_path);
    std::ifstream client_master_key_in(client_master_key_path);
    std::ifstream client_tdp_prg_key_in(client_tdp_prg_key_path);
    std::ifstream server_pk_in(server_pk_path);

    // check that all the streams are in an invalid state:
    // good() returns true if the file exists, false o/w
    ASSERT_FALSE(client_sk_in.good());
    ASSERT_FALSE(client_master_key_in.good());
    ASSERT_FALSE(client_tdp_prg_key_in.good());
    ASSERT_FALSE(server_pk_in.good());

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

    client_sk_in.close();
    client_master_key_in.close();
    server_pk_in.close();
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
}

TEST(sophos, create_reload)
{
    std::unique_ptr<sophos::SophosClient> client;
    std::unique_ptr<sophos::SophosServer> server;

    // start by cleaning up the test directory
    utility::remove_directory(sophos_test_dir);

    // create an empty directory
    int result = mkdir(sophos_test_dir, 0777);
    ASSERT_NE(result, -1);

    // first, create a client and a server from scratch
    create_client_server(client, server);

    // destroy them
    client.reset(nullptr);
    server.reset(nullptr);

    // reload them from the disk
    restart_client_server(client, server);
}

} // namespace test
} // namespace sophos
} // namespace sse
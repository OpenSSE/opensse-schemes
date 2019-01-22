//
//  test_janus.cpp
//  sophos
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

#include <sse/schemes/janus/janus_client.hpp>
#include <sse/schemes/janus/janus_server.hpp>

#include <sse/crypto/puncturable_enc.hpp>
#include <sse/crypto/random.hpp>
#include <sse/crypto/utils.hpp>

#include <cassert>

#include <chrono>
#include <fstream>
#include <iostream>
#include <ostream>

using namespace sse::crypto;
using namespace sse::janus;
using namespace std;

using master_key_type = sse::crypto::Key<sse::crypto::punct::kMasterKeySize>;

void benchmark_sk0_generation(ostream& out)
{
    const size_t bench_count = 100;

    std::chrono::duration<double, std::milli> keyshare_time(0);

    for (size_t i = 0; i < bench_count; i++) {
        punct::master_key_type master_key;
        auto t_start = std::chrono::high_resolution_clock::now();

        PuncturableEncryption cryptor(std::move(master_key));
        auto volatile sk0 = cryptor.initial_keyshare(i);
        (void)sk0;

        auto t_end = std::chrono::high_resolution_clock::now();

        keyshare_time = t_end - t_start;

        out << "SK0 \t" << keyshare_time.count() << endl;
    }
}

void benchmark_puncture_generation(ostream& out)
{
    const size_t puncture_count = 20;
    const size_t bench_count    = 20;


    for (size_t j = 0; j < bench_count; j++) {
        auto master_key_array = sse::crypto::random_bytes<uint8_t, 32>();

        std::chrono::duration<double, std::milli> keyshare_time(0);

        for (size_t i = 1; i < puncture_count + 1; i++) {
            punct::tag_type tag{{0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00}};
            tag[0] = i & 0xFF;
            tag[1] = (i >> 8) & 0xFF;
            tag[2] = (i >> 16) & 0xFF;
            tag[3] = (i >> 24) & 0xFF;
            tag[4] = (i >> 32) & 0xFF;
            tag[5] = (i >> 40) & 0xFF;
            tag[6] = (i >> 48) & 0xFF;
            tag[7] = (i >> 56) & 0xFF;

            // to do the benchmark, we have to copy the key as it is going to be
            // erased otherwise
            auto master_key_array_cp = master_key_array;

            auto t_start = std::chrono::high_resolution_clock::now();

            PuncturableEncryption cryptor(
                master_key_type(master_key_array_cp.data()));
            auto volatile sk_i = cryptor.inc_puncture(i, tag);
            (void)sk_i;

            auto t_end = std::chrono::high_resolution_clock::now();

            keyshare_time = t_end - t_start;

            out << "Puncture \t" << keyshare_time.count() << endl;
        }
    }
}

void benchmark_encrypt(ostream& out)
{
    const size_t encrypt_count = 20;
    const size_t bench_count   = 20;

    uint64_t M;


    for (size_t j = 0; j < bench_count; j++) {
        auto master_key_array = sse::crypto::random_bytes<uint8_t, 32>();

        std::chrono::duration<double, std::milli> time(0);

        for (size_t i = 0; i < encrypt_count; i++) {
            punct::tag_type tag{{0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00,
                                 0x00}};
            sse::crypto::random_bytes(tag);
            tag[0] = i & 0xFF;
            tag[1] = (i >> 8) & 0xFF;
            tag[2] = (i >> 16) & 0xFF;
            tag[3] = (i >> 24) & 0xFF;
            tag[4] = (i >> 32) & 0xFF;
            tag[5] = (i >> 40) & 0xFF;
            tag[6] = (i >> 48) & 0xFF;
            tag[7] = (i >> 56) & 0xFF;


            sse::crypto::random_bytes(sizeof(uint64_t), (uint8_t*)&M);

            // to do the benchmark, we have to copy the key as it is going to be
            // erased otherwise
            auto master_key_array_cp = master_key_array;


            auto t_start = std::chrono::high_resolution_clock::now();

            PuncturableEncryption cryptor(
                master_key_type(master_key_array_cp.data()));
            auto sk_i = cryptor.encrypt(M, tag);
            (void)sk_i;

            auto t_end = std::chrono::high_resolution_clock::now();

            time = t_end - t_start;

            out << "Encrypt \t" << time.count() << endl;
        }
    }
}

void benchmark_decrypt(ostream& out)
{
    const size_t decrypt_count = 20;
    const size_t bench_count   = 20;

    uint64_t M, dec_M;

    const std::vector<size_t> puncture_count_list = {0, 5, 15, 30, 50, 100};

    for (size_t j = 0; j < bench_count; j++) {
        cout << "Decryption round " << j;

        punct::master_key_type master_key;

        std::chrono::duration<double, std::milli> time(0);

        PuncturableEncryption cryptor(std::move(master_key));

        std::vector<punct::key_share_type> keyshares;

        size_t current_p_count = 0;

        punct::tag_type punctured_tag{{0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00}};
        sse::crypto::random_bytes(punctured_tag);

        keyshares.push_back(cryptor.initial_keyshare(0));

        for (size_t p : puncture_count_list) {
            cout << " " << p << flush;

            // add new punctures
            for (; current_p_count < p; current_p_count++) {
                punctured_tag[15] = current_p_count & 0xFF;
                punctured_tag[14] = (current_p_count >> 8) & 0xFF;
                punctured_tag[13] = (current_p_count >> 16) & 0xFF;
                punctured_tag[12] = (current_p_count >> 24) & 0xFF;
                punctured_tag[11] = (current_p_count >> 32) & 0xFF;
                punctured_tag[10] = (current_p_count >> 40) & 0xFF;
                punctured_tag[9]  = (current_p_count >> 48) & 0xFF;
                //            punctured_tag[8] = (current_p_count>>56)&0xFF;
                punctured_tag[8] = 0xFF;

                auto share
                    = cryptor.inc_puncture(current_p_count + 1, punctured_tag);

                keyshares.push_back(share);
            }

            keyshares[0] = cryptor.initial_keyshare(current_p_count);

            PuncturableDecryption decryptor(keyshares);

            for (size_t i = 0; i < decrypt_count; i++) {
                punct::tag_type tag{{0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00,
                                     0x00}};
                sse::crypto::random_bytes(tag);
                tag[0] = i & 0xFF;
                tag[1] = (i >> 8) & 0xFF;
                tag[2] = (i >> 16) & 0xFF;
                tag[3] = (i >> 24) & 0xFF;
                tag[4] = (i >> 32) & 0xFF;
                tag[5] = (i >> 40) & 0xFF;
                tag[6] = (i >> 48) & 0xFF;
                tag[7] = (i >> 56) & 0xFF;

                sse::crypto::random_bytes(sizeof(uint64_t), (uint8_t*)&M);


                auto ct = cryptor.encrypt(M, tag);

                auto t_start = std::chrono::high_resolution_clock::now();

                bool success = decryptor.decrypt(ct, dec_M);

                auto t_end = std::chrono::high_resolution_clock::now();

                (void)success;
                assert(success);

                time = t_end - t_start;

                out << "Decrypt_" << std::to_string(current_p_count) << " \t "
                    << time.count() << endl;
                out << "Decrypt_per_punct"
                    << " \t " << time.count() / (keyshares.size()) << endl;
            }
        }
        cout << endl;
    }
}

void benchmark_puncturable_encryption()
{
    ofstream benchmark_file("bench_janus.out");

    assert(benchmark_file.is_open());

    cout << "SK0 generation " << endl;
    benchmark_sk0_generation(benchmark_file);
    cout << "Puncture generation " << endl;
    benchmark_puncture_generation(benchmark_file);
    cout << "Encryption " << endl;
    benchmark_encrypt(benchmark_file);
    cout << "Decryption " << endl;
    benchmark_decrypt(benchmark_file);
}

void test_client_server()
{
    sse::logger::set_logging_level(spdlog::level::debug);

    string   client_master_key_path = "janus_master.key";
    ifstream client_master_key_in(client_master_key_path.c_str());

    typedef uint64_t index_type;

    unique_ptr<JanusClient> client;
    unique_ptr<JanusServer> server;

    if (client_master_key_in.good() == true) {
        // the files exist
        cout << "Restart Janus client and server" << endl;

        stringstream client_master_key_buf;
        string       client_master_key;

        client_master_key_buf << client_master_key_in.rdbuf();
        client_master_key = client_master_key_buf.str();

        std::array<uint8_t, 32> client_master_key_array;

        assert(client_master_key.size() == client_master_key_array.size());

        std::copy(client_master_key.begin(),
                  client_master_key.end(),
                  client_master_key_array.begin());

        client.reset(new JanusClient(
            "janus_client.search.dat",
            "janus_client.add.dat",
            "janus_client.del.dat",
            Key<JanusClient::kPRFKeySize>(client_master_key_array.data())));

        server.reset(new JanusServer("janus_server.add.dat",
                                     "janus_server.del.dat",
                                     "janus_server.cache.dat"));


        std::string   key   = "toto";
        SearchRequest s_req = client->search_request(key);
        //        auto res = server->search(s_req);
        auto res = server->search_parallel(s_req, 8);

        cout << "Search " << key << ". Results: [";
        for (index_type i : res) {
            cout << i << ", ";
        }
        cout << "]" << endl;

        DeletionRequest del_req;
        del_req = client->removal_request("toto", 2);
        server->remove(del_req);

        InsertionRequest add_req;
        add_req = client->insertion_request("tata", 6);
        server->insert(add_req);

    } else {
        cout << "Create new Janus client-server instances" << endl;

        // generate new keys
        std::array<uint8_t, 32> client_master_key
            = sse::crypto::random_bytes<uint8_t, 32>();


        // write keys to files

        ofstream client_master_key_out(client_master_key_path.c_str());
        client_master_key_out
            << std::string(client_master_key.begin(), client_master_key.end());
        client_master_key_out.close();

        client.reset(new JanusClient(
            "janus_client.search.dat",
            "janus_client.add.dat",
            "janus_client.del.dat",
            Key<JanusClient::kPRFKeySize>(client_master_key.data())));

        server.reset(new JanusServer("janus_server.add.dat",
                                     "janus_server.del.dat",
                                     "janus_server.cache.dat"));

        InsertionRequest add_req;

        add_req = client->insertion_request("toto", 0);
        server->insert(add_req);

        add_req = client->insertion_request("titi", 0);
        server->insert(add_req);

        add_req = client->insertion_request("toto", 1);
        server->insert(add_req);

        add_req = client->insertion_request("toto", 2);
        server->insert(add_req);

        add_req = client->insertion_request("tata", 0);
        server->insert(add_req);
        add_req = client->insertion_request("tata", 3);
        server->insert(add_req);
        add_req = client->insertion_request("tata", 5);
        server->insert(add_req);

        DeletionRequest del_req;
        del_req = client->removal_request("tata", 3);
        server->remove(del_req);
    }

    std::string   key   = "toto";
    SearchRequest s_req = client->search_request(key);
    //    auto res = server->search(s_req);
    auto res = server->search_parallel(s_req, 8);

    cout << "Search " << key << ". Results: [";
    for (index_type i : res) {
        cout << i << ", ";
    }
    cout << "]" << endl;

    key   = "tata";
    s_req = client->search_request(key);
    //    res = server->search(s_req);
    res = server->search_parallel(s_req, 8);

    cout << "Search " << key << ". Results: [";
    for (index_type i : res) {
        cout << i << ", ";
    }
    cout << "]" << endl;


    client_master_key_in.close();
}

int main(int /*argc*/, const char** /*argv*/)
{
    init_crypto_lib();

    benchmark_puncturable_encryption();
    //    test_client_server();

    cleanup_crypto_lib();

    return 0;
}

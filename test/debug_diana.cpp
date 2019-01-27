//
//  test_diana
//  diana
//
//  Created by Raphael Bost on 19/07/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include <sse/schemes/diana/diana_client.hpp>
#include <sse/schemes/diana/diana_server.hpp>
#include <sse/schemes/utils/logger.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/utils.hpp>

#include <fstream>
#include <iostream>
#include <memory>

using namespace sse::diana;
using namespace std;

void test_client_server()
{
    sse::logger::set_logging_level(spdlog::level::debug);

    string client_master_key_path          = "diana_derivation_master.key";
    string client_kw_token_master_key_path = "diana_kw_token_master.key";


    ifstream client_master_key_in(client_master_key_path.c_str());
    ifstream client_kw_token_master_key_in(
        client_kw_token_master_key_path.c_str());

    typedef uint64_t index_type;

    unique_ptr<DianaClient<index_type>> client;
    unique_ptr<DianaServer<index_type>> server;

    UpdateRequest<index_type> u_req;

    if ((client_kw_token_master_key_in.good() != client_master_key_in.good())) {
        client_master_key_in.close();
        client_kw_token_master_key_in.close();

        throw std::runtime_error("All streams are not in the same state");
    }

    if (client_master_key_in.good() == true) {
        // the files exist
        cout << "Restart Diana client and server" << endl;

        stringstream client_master_key_buf, client_kw_token_key_buf;
        string       client_master_key, client_kw_token_key;

        client_master_key_buf << client_master_key_in.rdbuf();
        client_master_key = client_master_key_buf.str();

        client_kw_token_key_buf << client_kw_token_master_key_in.rdbuf();
        client_kw_token_key = client_kw_token_key_buf.str();

        std::array<uint8_t, 32> client_master_key_array,
            client_kw_token_key_array;

        assert(client_master_key.size() == client_master_key_array.size());
        assert(client_kw_token_key.size() == client_kw_token_key_array.size());

        std::copy(client_master_key.begin(),
                  client_master_key.end(),
                  client_master_key_array.begin());
        std::copy(client_kw_token_key.begin(),
                  client_kw_token_key.end(),
                  client_kw_token_key_array.begin());


        client.reset(new DianaClient<index_type>(
            "diana_client.sav",
            sse::crypto::Key<DianaClient<index_type>::kKeySize>(
                client_master_key_array.data()),
            sse::crypto::Key<DianaClient<index_type>::kKeySize>(
                client_kw_token_key_array.data())));

        server.reset(new DianaServer<index_type>("diana_server.dat"));

    } else {
        cout << "Create new Diana client-server instances" << endl;

        // generate new keys
        std::array<uint8_t, DianaClient<index_type>::kKeySize>
            master_derivation_key
            = sse::crypto::random_bytes<uint8_t,
                                        DianaClient<index_type>::kKeySize>();
        std::array<uint8_t, DianaClient<index_type>::kKeySize>
            kw_token_master_key
            = sse::crypto::random_bytes<uint8_t,
                                        DianaClient<index_type>::kKeySize>();


        // write keys to files

        ofstream client_master_key_out(client_master_key_path.c_str());
        client_master_key_out << std::string(master_derivation_key.begin(),
                                             master_derivation_key.end());
        client_master_key_out.close();

        ofstream client_kw_token_master_key_out(
            client_kw_token_master_key_path.c_str());
        client_kw_token_master_key_out << std::string(
            kw_token_master_key.begin(), kw_token_master_key.end());
        client_kw_token_master_key_out.close();


        client.reset(new DianaClient<index_type>(
            "diana_client.sav",
            sse::crypto::Key<DianaClient<index_type>::kKeySize>(
                master_derivation_key.data()),
            sse::crypto::Key<DianaClient<index_type>::kKeySize>(
                kw_token_master_key.data())));

        server.reset(new DianaServer<index_type>("diana_server.dat"));

        // insert stuff

        u_req = client->insertion_request("toto", 0);
        server->insert(u_req);

        u_req = client->insertion_request("titi", 0);
        server->insert(u_req);

        u_req = client->insertion_request("toto", 1);
        server->insert(u_req);

        u_req = client->insertion_request("toto", 2);
        server->insert(u_req);

        u_req = client->insertion_request("tata", 0);
        server->insert(u_req);
    }


    std::list<index_type> res;
    string                key;

    key = "toto";
    SearchRequest s_req(client->search_request(key));
    res = server->search(s_req);
    //    res = server->search_parallel(s_req,8);

    cout << "Search " << key << ". Results: [";
    for (index_type i : res) {
        cout << i << ", ";
    }
    cout << "]" << endl;

    key   = "titi";
    s_req = client->search_request(key);
    res   = server->search(s_req);

    cout << "Search " << key << ". Results: [";
    for (index_type i : res) {
        cout << i << ", ";
    }
    cout << "]" << endl;

    key   = "tata";
    s_req = client->search_request(key);
    res   = server->search(s_req);

    cout << "Search " << key << ". Results: [";
    for (index_type i : res) {
        cout << i << ", ";
    }
    cout << "]" << endl;

    client_master_key_in.close();
    client_kw_token_master_key_in.close();
}

int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();
    test_client_server();
    sse::crypto::cleanup_crypto_lib();

    return 0;
}

//
//  main.cpp
//  sophos
//
//  Created by Raphael Bost on 29/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include <sse/schemes/sophos/sophos_client.hpp>
#include <sse/schemes/sophos/sophos_server.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/utils.hpp>

#include <fstream>
#include <iostream>
#include <memory>

using namespace sse::sophos;
using namespace std;

void test_client_server()
{
    sse::logger::set_logging_level(spdlog::level::debug);

    string client_sk_path          = "sophos_client_test/tdp_sk.key";
    string client_master_key_path  = "sophos_client_test/derivation_master.key";
    string client_tdp_prg_key_path = "sophos_client_test/tdp_prg.key";
    string server_pk_path          = "sophos_server_test/tdp_pk.key";


    ifstream client_sk_in(client_sk_path.c_str());
    ifstream client_master_key_in(client_master_key_path.c_str());
    ifstream client_tdp_prg_key_in(client_tdp_prg_key_path.c_str());
    ifstream server_pk_in(server_pk_path.c_str());

    unique_ptr<SophosClient> client;
    unique_ptr<SophosServer> server;

    SearchRequest         s_req;
    UpdateRequest         u_req;
    std::list<index_type> res;
    string                key;

    if ((client_sk_in.good() != client_master_key_in.good())
        || (client_sk_in.good() != server_pk_in.good())
        || (client_sk_in.good() != client_tdp_prg_key_in.good())) {
        client_sk_in.close();
        client_master_key_in.close();
        server_pk_in.close();
        client_tdp_prg_key_in.close();

        throw std::runtime_error("All streams are not in the same state");
    }

    if (client_sk_in.good() == true) {
        // the files exist
        cout << "Restart client and server" << endl;

        stringstream client_sk_buf, client_master_key_buf, server_pk_buf,
            client_tdp_prg_key_buf;

        client_sk_buf << client_sk_in.rdbuf();
        client_master_key_buf << client_master_key_in.rdbuf();
        server_pk_buf << server_pk_in.rdbuf();
        client_tdp_prg_key_buf << client_tdp_prg_key_in.rdbuf();

        std::array<uint8_t, 32> client_master_key_array,
            client_tdp_prg_key_array;

        assert(client_master_key_buf.str().size()
               == client_master_key_array.size());
        assert(client_tdp_prg_key_buf.str().size()
               == client_tdp_prg_key_array.size());

        auto client_master_key  = client_master_key_buf.str();
        auto client_tdp_prg_key = client_tdp_prg_key_buf.str();

        std::copy(client_master_key.begin(),
                  client_master_key.end(),
                  client_master_key_array.begin());
        std::copy(client_tdp_prg_key.begin(),
                  client_tdp_prg_key.end(),
                  client_tdp_prg_key_array.begin());

        client.reset(new SophosClient("sophos_client_test/client.sav",
                                      client_sk_buf.str(),
                                      sse::crypto::Key<SophosClient::kKeySize>(
                                          client_master_key_array.data()),
                                      sse::crypto::Key<SophosClient::kKeySize>(
                                          client_tdp_prg_key_array.data())));

        server.reset(new SophosServer("sophos_server_test/server.dat",
                                      server_pk_buf.str()));

    } else {
        cout << "Create new client-server instances" << endl;

        // generate the keys
        std::array<uint8_t, SophosClient::kKeySize> derivation_master_key
            = sse::crypto::random_bytes<uint8_t, SophosClient::kKeySize>();
        std::array<uint8_t, SophosClient::kKeySize> rsa_prg_key
            = sse::crypto::random_bytes<uint8_t, SophosClient::kKeySize>();
        sse::crypto::TdpInverse tdp;

        // start by writing all the keys

        ofstream client_sk_out(client_sk_path.c_str());
        client_sk_out << tdp.private_key();
        client_sk_out.close();

        ofstream client_master_key_out(client_master_key_path.c_str());
        client_master_key_out << std::string(derivation_master_key.begin(),
                                             derivation_master_key.end());
        client_master_key_out.close();

        ofstream client_tdp_prg_key_out(client_tdp_prg_key_path.c_str());
        client_tdp_prg_key_out
            << std::string(rsa_prg_key.begin(), rsa_prg_key.end());
        client_tdp_prg_key_out.close();

        ofstream server_pk_out(server_pk_path.c_str());
        server_pk_out << tdp.public_key();
        server_pk_out.close();

        // create the client and the server

        client.reset(new SophosClient(
            "sophos_client_test/client.sav",
            tdp.private_key(),
            sse::crypto::Key<SophosClient::kKeySize>(
                derivation_master_key.data()),
            sse::crypto::Key<SophosClient::kKeySize>(rsa_prg_key.data())));

        server.reset(new SophosServer("sophos_server_test/server.dat",
                                      tdp.public_key()));


        // make a few requests

        u_req = client->insertion_request("toto", 0);
        server->insert(u_req);

        u_req = client->insertion_request("titi", 0);
        server->insert(u_req);

        u_req = client->insertion_request("toto", 1);
        server->insert(u_req);

        u_req = client->insertion_request("tata", 0);
        server->insert(u_req);
    }


    key   = "toto";
    s_req = client->search_request(key);
    res   = server->search(s_req);

    cout << "Search " << key << ". Results: [";
    for (index_type i : res) {
        cout << i << ", ";
    }
    cout << "]" << endl;

    //    key = "titi";
    //    s_req = client->search_request(key);
    //    res = server->search(s_req);
    //
    //    cout << "Search " << key << ". Results: [";
    //    for(index_type i : res){
    //        cout << i << ", ";
    //    }
    //    cout << "]" << endl;
    //
    //    key = "tata";
    //    s_req = client->search_request(key);
    //    res = server->search(s_req);
    //
    //    cout << "Search " << key << ". Results: [";
    //    for(index_type i : res){
    //        cout << i << ", ";
    //    }
    //    cout << "]" << endl;


    client_sk_in.close();
    client_master_key_in.close();
    server_pk_in.close();
}

int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();
    test_client_server();
    sse::crypto::cleanup_crypto_lib();

    return 0;
}

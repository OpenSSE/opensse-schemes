//
//  main.cpp
//  sophos
//
//  Created by Raphael Bost on 29/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include <iostream>
#include <fstream>
#include <memory>

#include "src/diane/diane_client.hpp"
#include "src/diane/diane_server.hpp"
#include "utils.hpp"

using namespace sse::diane;
using namespace std;

void test_client_server()
{
    string client_master_key_path = "diane_derivation_master.key";
    string client_kw_token_master_key_path = "diane_ kw_token_master.key";

    
    ifstream client_master_key_in(client_master_key_path.c_str());
    ifstream client_kw_token_master_key_in(client_kw_token_master_key_path.c_str());
    
    unique_ptr<DianeClient> client;
    unique_ptr<DianeServer> server;
    
    SearchRequest s_req;
    UpdateRequest u_req;
    std::list<index_type> res;
    string key;

    if((client_kw_token_master_key_in.good() != client_master_key_in.good()) )
    {
        client_master_key_in.close();
        client_kw_token_master_key_in.close();

        throw std::runtime_error("All streams are not in the same state");
    }
    
    if (client_master_key_in.good() == true) {
        // the files exist
        cout << "Restart Diane client and server" << endl;
        
        stringstream client_master_key_buf, client_kw_token_key_buf;

        client_master_key_buf << client_master_key_in.rdbuf();
        client_kw_token_key_buf << client_kw_token_master_key_in.rdbuf();

//        client.reset(new  LargeStorageSophosClient("client.sav", "client.csv", client_sk_buf.str(), client_master_key_buf.str()));
        client.reset(new  DianeClient("diane_client.sav", client_master_key_buf.str(), client_kw_token_key_buf.str()));
        
//        server.reset(new SophosServer("diane_server.dat", server_pk_buf.str()));
        server.reset(new DianeServer("diane_server.dat"));
        
        SearchRequest s_req;
        std::list<index_type> res;
        string key;

    }else{
        cout << "Create new Diane client-server instances" << endl;
        
        client.reset(new DianeClient("diane_client.sav", 1000));

        server.reset(new DianeServer("diane_server.dat", 1000));
        
        // write keys to files
        
        ofstream client_master_key_out(client_master_key_path.c_str());
        client_master_key_out << client->master_derivation_key();
        client_master_key_out.close();

        ofstream client_kw_token_master_key_out(client_kw_token_master_key_path.c_str());
        client_kw_token_master_key_out << client->kw_token_master_key();
        client_kw_token_master_key_out.close();


        u_req = client->update_request("toto", 0);
        server->update(u_req);
        
        u_req = client->update_request("titi", 0);
        server->update(u_req);
        
        u_req = client->update_request("toto", 1);
        server->update(u_req);
        
        u_req = client->update_request("tata", 0);
        server->update(u_req);
        

    }
    

    
    key = "toto";
    s_req = client->search_request(key);
    res = server->search(s_req);

    cout << "Search " << key << ". Results: [";
    for(index_type i : res){
        cout << i << ", ";
    }
    cout << "]" << endl;

    key = "titi";
    s_req = client->search_request(key);
    res = server->search(s_req);
    
    cout << "Search " << key << ". Results: [";
    for(index_type i : res){
        cout << i << ", ";
    }
    cout << "]" << endl;

    key = "tata";
    s_req = client->search_request(key);
    res = server->search(s_req);
    
    cout << "Search " << key << ". Results: [";
    for(index_type i : res){
        cout << i << ", ";
    }
    cout << "]" << endl;

    client_master_key_in.close();
    client_kw_token_master_key_in.close();

}

void test_kw_indexer()
{
    
    map<string, uint32_t> m, n;
    
    m["toto"] = 0;
    m["titi"] = 1;
    m["tata"] = 2;
    m["tutu"] = 34;
    
    ofstream out("test.csv");
    
    write_keyword_map(out, m);
    
    out.close();
    
    ifstream in("test.csv");
    
    bool ret = parse_keyword_map(in, n);
    
    if (ret) {
        cout << "Success" << endl;
    }else{
        cout << "Failed" << endl;
    }
    
    for (auto p : n) {
        cout << p.first << "| , |" << p.second << endl;
    }
    
}

int main(int argc, const char * argv[]) {

    test_client_server();
    
    return 0;
}

//
//  main.cpp
//  sophos
//
//  Created by Raphael Bost on 29/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include <iostream>
#include <fstream>

#include "sophos_core.hpp"

using namespace sse::sophos;
using namespace std;

int main(int argc, const char * argv[]) {
    
    string client_sk_path = "tdp_sk.key";
    string client_master_key_path = "derivation_master.key";
    string server_pk_path = "tdp_pk.key";
    
    
    ifstream client_sk_in(client_sk_path.c_str());
    ifstream client_master_key_in(client_master_key_path.c_str());
    ifstream server_pk_in(server_pk_path.c_str());
    
    if((client_sk_in.good() != client_master_key_in.good()) || (client_sk_in.good() != server_pk_in.good()))
    {
        client_sk_in.close();
        client_master_key_in.close();
        server_pk_in.close();

        throw std::runtime_error("All streams are not in the same state");
    }
    
    if (client_sk_in.good() == true) {
        // the files exist
        cout << "Restart client and server" << endl;
        
        stringstream client_sk_buf, client_master_key_buf, server_pk_buf;

        client_sk_buf << client_sk_in.rdbuf();
        client_master_key_buf << client_master_key_in.rdbuf();
        server_pk_buf << server_pk_in.rdbuf();

        SophosClient client("client.sav", client_sk_buf.str(), client_master_key_buf.str());
        
        SophosServer server("server.dat", server_pk_buf.str());

        SearchRequest s_req;
        std::list<index_type> res;
        string key;

        key = "toto";
        s_req = client.search_request(key);
        res = server.search(s_req);
        
        cout << "Search " << key << ". Results: [";
        for(index_type i : res){
            cout << i << ", ";
        }
        cout << "]" << endl;

    }else{
        cout << "Create new client-server instances" << endl;
        
        SophosClient client("client.sav",1000);

        SophosServer server("server.dat", 1000, client.public_key());
        
        // write keys to files
        ofstream client_sk_out(client_sk_path.c_str());
        client_sk_out << client.private_key();
        client_sk_out.close();
        
        ofstream client_master_key_out(client_master_key_path.c_str());
        client_master_key_out << client.master_derivation_key();
        client_master_key_out.close();

        ofstream server_pk_out(server_pk_path.c_str());
        server_pk_out << server.public_key();
        server_pk_out.close();

        
        
        SearchRequest s_req;
        UpdateRequest u_req;
        std::list<index_type> res;
        string key;

        u_req = client.update_request("toto", 0);
        server.update(u_req);

    //    u_req = client.update_request("titi", 0);
    //    server.update(u_req);
        
        u_req = client.update_request("toto", 1);
        server.update(u_req);
        
    //    u_req = client.update_request("tata", 0);
    //    server.update(u_req);

        key = "toto";
        s_req = client.search_request(key);
        res = server.search(s_req);
        
        cout << "Search " << key << ". Results: [";
        for(index_type i : res){
            cout << i << ", ";
        }
        cout << "]" << endl;

    //    key = "titi";
    //    s_req = client.search_request(key);
    //    res = server.search(s_req);
    //    
    //    cout << "Search " << key << ". Results: [";
    //    for(index_type i : res){
    //        cout << i << ", ";
    //    }
    //    cout << "]" << endl;
    //
    //    key = "tata";
    //    s_req = client.search_request(key);
    //    res = server.search(s_req);
    //    
    //    cout << "Search " << key << ". Results: [";
    //    for(index_type i : res){
    //        cout << i << ", ";
    //    }
    //    cout << "]" << endl;

    }
    
    client_sk_in.close();
    client_master_key_in.close();
    server_pk_in.close();
    
    return 0;
}

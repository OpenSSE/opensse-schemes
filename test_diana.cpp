//
//  test_diana
//  diana
//
//  Created by Raphael Bost on 19/07/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include <iostream>
#include <fstream>
#include <memory>

#include "diana/diana_client.hpp"
#include "diana/diana_server.hpp"
#include "utils/utils.hpp"
#include "utils/logger.hpp"

using namespace sse::diana;
using namespace std;

void test_client_server()
{
    sse::logger::set_severity(sse::logger::DBG);
    
    string client_master_key_path = "diana_derivation_master.key";
    string client_kw_token_master_key_path = "diana_kw_token_master.key";

    
    ifstream client_master_key_in(client_master_key_path.c_str());
    ifstream client_kw_token_master_key_in(client_kw_token_master_key_path.c_str());
    
    typedef uint64_t index_type;
    
    unique_ptr<DianaClient<index_type>> client;
    unique_ptr<DianaServer<index_type>> server;
    
    SearchRequest s_req;
    UpdateRequest<index_type> u_req;
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
        cout << "Restart Diana client and server" << endl;
        
        stringstream client_master_key_buf, client_kw_token_key_buf;

        client_master_key_buf << client_master_key_in.rdbuf();
        client_kw_token_key_buf << client_kw_token_master_key_in.rdbuf();

        client.reset(new  DianaClient<index_type>("diana_client.sav", client_master_key_buf.str(), client_kw_token_key_buf.str()));
        
        server.reset(new DianaServer<index_type>("diana_server.dat"));
        
        SearchRequest s_req;
        std::list<index_type> res;
        string key;

    }else{
        cout << "Create new Diana client-server instances" << endl;
        
        client.reset(new DianaClient<index_type>("diana_client.sav"));

        server.reset(new DianaServer<index_type>("diana_server.dat", 1000));
        
        // write keys to files
        
        ofstream client_master_key_out(client_master_key_path.c_str());
        client_master_key_out << client->master_derivation_key();
        client_master_key_out.close();

        ofstream client_kw_token_master_key_out(client_kw_token_master_key_path.c_str());
        client_kw_token_master_key_out << client->kw_token_master_key();
        client_kw_token_master_key_out.close();


        u_req = client->update_request("toto", 0);
        server->update(u_req);
        
//        u_req = client->update_request("titi", 0);
//        server->update(u_req);
        
        u_req = client->update_request("toto", 1);
        server->update(u_req);
        
        u_req = client->update_request("toto", 2);
        server->update(u_req);
        
//        u_req = client->update_request("tata", 0);
//        server->update(u_req);
        

    }
    

    
    key = "toto";
    s_req = client->search_request(key);
//    res = server->search(s_req);
    res = server->search_simple_parallel(s_req,8);

    cout << "Search " << key << ". Results: [";
    for(index_type i : res){
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

    client_master_key_in.close();
    client_kw_token_master_key_in.close();

}

int main(int argc, const char * argv[]) {

    test_client_server();
    
    return 0;
}

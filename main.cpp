//
//  main.cpp
//  sophos
//
//  Created by Raphael Bost on 29/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include <iostream>

#include "sophos_core.hpp"

using namespace sse::sophos;
using namespace std;

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << kSearchTokenSize << std::endl;
    
    SophosClient client("client.sav");

    SophosServer server("server.dat", client.public_key());
    
    
    
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

    
    return 0;
}

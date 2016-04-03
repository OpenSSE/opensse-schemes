//
//  client_main.cpp
//  sophos
//
//  Created by Raphael Bost on 03/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_client.hpp"

#include <stdio.h>


int main(int argc, char** argv) {
    // Expect only arg: --db_path=path/to/route_guide_db.json.
    std::string save_path = "test.csdb";
    sse::sophos::SophosClientRunner client("localhost:4242", save_path);
    
    std::cout << "-------------- Update --------------" << std::endl;
    client.update("toto", 0);
    client.update("titi", 0);
    client.update("toto", 1);
    client.update("tata", 0);
    
    
    std::cout << "-------------- Search --------------" << std::endl;
    client.search("toto");
    std::cout << "-------------- Search --------------" << std::endl;
    client.search("tata");
    
    
    return 0;
}

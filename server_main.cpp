//
//  server_main.cpp
//  sophos
//
//  Created by Raphael Bost on 03/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_server.hpp"
#include "logger.hpp"

#include <stdio.h>
#include <csignal>

grpc::Server *server_ptr__ = NULL;

void exit_handler(int signal)
{
    std::cout << "\nExiting ... " << server_ptr__ << std::endl;
    
    if (server_ptr__) {
        server_ptr__->Shutdown();
    }
};


int main(int argc, char** argv) {

    sse::logger::set_severity(sse::logger::INFO);

    std::signal(SIGTERM, exit_handler);
    std::signal(SIGINT, exit_handler);
    std::signal(SIGQUIT, exit_handler);
    
    sse::sophos::run_sophos_server("0.0.0.0:4242", "/Users/rbost/Code/sse/sophos/test.ssdb", &server_ptr__);
    
    std::cout << "Done" << std::endl;
    
    return 0;
}
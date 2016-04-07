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
    sse::logger::log(sse::logger::INFO) << "\nExiting ... " << std::endl;
    
    if (server_ptr__) {
        server_ptr__->Shutdown();
    }
};


int main(int argc, char** argv) {

    sse::logger::set_severity(sse::logger::INFO);
    sse::logger::set_benchmark_file("benchmark_server.out");

    std::signal(SIGTERM, exit_handler);
    std::signal(SIGINT, exit_handler);
    std::signal(SIGQUIT, exit_handler);

    opterr = 0;
    int c;

    std::string server_db;
    while ((c = getopt (argc, argv, "b:")) != -1)
        switch (c)
    {
        case 'b':
            server_db = std::string(optarg);
            break;
        case '?':
            if (optopt == 'i')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            return 1;
        default:
            exit(-1);
    }
    
    if (server_db.size()==0) {
        sse::logger::log(sse::logger::ERROR) << "Server database not specified" << std::endl;
        sse::logger::log(sse::logger::ERROR) << "Using \'test.ssdb\' by default" << std::endl;
        server_db = "test.ssdb";
    }else{
        sse::logger::log(sse::logger::INFO) << "Running client with database " << server_db << std::endl;
    }

    sse::sophos::run_sophos_server("0.0.0.0:4242", server_db, &server_ptr__);
//    sse::sophos::run_sophos_server("0.0.0.0:4242", "/Users/raphaelbost/Code/sse/sophos/test.ssdb", &server_ptr__);
    
    sse::logger::log(sse::logger::INFO) << "Done" << std::endl;
    
    return 0;
}
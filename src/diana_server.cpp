//
//  diana_server.cpp
//  Diana
//
//  Created by Raphael Bost on 20/07/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include <sse/runners/diana/server_runner.hpp>
#include <sse/schemes/utils/logger.hpp>

#include <sse/crypto/utils.hpp>

#include <grpc++/server.h>

#include <csignal>
#include <cstdio>
#include <unistd.h>

sse::diana::DianaServerRunner* server_ptr__ = nullptr;

void exit_handler(__attribute__((unused)) int signal)
{
    sse::logger::logger()->info("Exiting ... ");

    if (server_ptr__ != nullptr) {
        server_ptr__->shutdown();
    }
};


int main(int argc, char** argv)
{
    sse::logger::set_logging_level(spdlog::level::info);
    sse::logger::set_benchmark_file("benchmark_diana_server.out");

    std::signal(SIGTERM, exit_handler);
    std::signal(SIGINT, exit_handler);
    std::signal(SIGQUIT, exit_handler);

    sse::crypto::init_crypto_lib();

    opterr = 0;
    int c;

    bool async_search = true;

    std::string server_db;
    while ((c = getopt(argc, argv, "b:s")) != -1) {
        switch (c) {
        case 'b':
            server_db = std::string(optarg);
            break;
        case 's':
            async_search = false;
            break;

        case '?':
            if (optopt == 'i') {
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            } else if (isprint(optopt) != 0) {
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            } else {
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
            return 1;
        default:
            exit(-1);
        }
    }

    if (async_search) {
        sse::logger::logger()->info("Use asynchronous searches");
    } else {
        sse::logger::logger()->info("Use synchronous searches");
    }

    if (server_db.empty()) {
        sse::logger::logger()->warn(
            "Server database not specified. Using \'test.dsdb\' by default");
        server_db = "test.dsdb";
    } else {
        sse::logger::logger()->info("Running server with database "
                                    + server_db);
    }
    server_ptr__ = new sse::diana::DianaServerRunner("0.0.0.0:4241", server_db);
    server_ptr__->set_async_search(async_search);

    server_ptr__->wait();

    sse::crypto::cleanup_crypto_lib();

    sse::logger::logger()->info("Diana exited");

    return 0;
}

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

#include <csignal>
#include <cstdio>
#include <grpcpp/grpcpp.h>
#include <unistd.h>

sse::diana::DianaServerRunner* g_diana_server_ptr_ = nullptr;

void exit_handler(__attribute__((unused)) int signal)
{
    sse::logger::logger()->info("Exiting ... ");

    if (g_diana_server_ptr_ != nullptr) {
        g_diana_server_ptr_->shutdown();
    }
};


int main(int argc, char** argv)
{
    sse::logger::set_logging_level(spdlog::level::info);
    sse::Benchmark::set_benchmark_file("benchmark_diana_server.out");

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
    g_diana_server_ptr_
        = new sse::diana::DianaServerRunner("0.0.0.0:4241", server_db);
    g_diana_server_ptr_->set_async_search(async_search);

    g_diana_server_ptr_->wait();

    sse::crypto::cleanup_crypto_lib();

    sse::logger::logger()->info("Diana exited");

    return 0;
}

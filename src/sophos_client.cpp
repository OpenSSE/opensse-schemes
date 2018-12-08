//
//  client_main.cpp
//  sophos
//
//  Created by Raphael Bost on 03/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include <sse/runners/sophos/sophos_client_runner.hpp>
#include <sse/schemes/utils/db_generator.hpp>
#include <sse/schemes/utils/logger.hpp>

#include <sse/crypto/utils.hpp>

#include <cstdio>
#include <unistd.h>

#include <mutex>

int main(int argc, char** argv)
{
    sse::logger::set_severity(sse::logger::LoggerSeverity::INFO);
    sse::logger::set_benchmark_file("benchmark_sophos_client.out");

    sse::crypto::init_crypto_lib();

    opterr = 0;
    int c;

    std::list<std::string> input_files;
    std::list<std::string> keywords;
    std::string            client_db;
    uint32_t               rnd_entries_count = 0;

    while ((c = getopt(argc, argv, "l:b:o:i:dr:")) != -1) {
        switch (c) {
        case 'l':
            input_files.emplace_back(optarg);
            break;
        case 'b':
            client_db = std::string(optarg);
            break;
        case 'd': // load a default file, only for debugging
            //            input_files.push_back("/Volumes/Storage/WP_Inverted/inverted_index_all_sizes/inverted_index_10000.json");
            input_files.emplace_back(
                "/Users/raphaelbost/Documents/inverted_index_1000.json");
            break;
        case 'r':
            rnd_entries_count = static_cast<uint32_t>(
                std::stod(std::string(optarg), nullptr));
            // atol(optarg);
            break;
        case '?':
            if (optopt == 'l' || optopt == 'b' || optopt == 't'
                || optopt == 'r') {
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


    for (int index = optind; index < argc; index++) {
        keywords.emplace_back(argv[index]);
    }

    if (client_db.empty()) {
        sse::logger::log(sse::logger::LoggerSeverity::WARNING)
            << "Client database not specified" << std::endl;
        sse::logger::log(sse::logger::LoggerSeverity::WARNING)
            << "Using \'test.csdb\' by default" << std::endl;
        client_db = "test.csdb";
    } else {
        sse::logger::log(sse::logger::LoggerSeverity::INFO)
            << "Running client with database " << client_db << std::endl;
    }

    std::unique_ptr<sse::sophos::SophosClientRunner> client_runner;

    client_runner.reset(
        new sse::sophos::SophosClientRunner("localhost:4240", client_db));

    for (std::string& path : input_files) {
        sse::logger::log(sse::logger::LoggerSeverity::INFO)
            << "Load file " << path << std::endl;
        client_runner->load_inverted_index(path);
        sse::logger::log(sse::logger::LoggerSeverity::INFO)
            << "Done loading file " << path << std::endl;
    }

    if (rnd_entries_count > 0) {
        sse::logger::log(sse::logger::LoggerSeverity::INFO)
            << "Randomly generating database with " << rnd_entries_count
            << " docs" << std::endl;

        //        auto post_callback = [&writer, &res_size,
        //        &writer_lock](index_type i)

        auto gen_callback = [&client_runner](const std::string& s, size_t i) {
            client_runner->async_insert(s, i);
        };

        client_runner->start_update_session();
        sse::sophos::gen_db(rnd_entries_count, gen_callback);
        client_runner->end_update_session();
    }

    for (std::string& kw : keywords) {
        std::cout << "-------------- Search --------------" << std::endl;

        std::mutex    logger_mtx;
        std::ostream& log_stream
            = sse::logger::log(sse::logger::LoggerSeverity::INFO);
        bool first = true;

        auto print_callback = [&logger_mtx, &log_stream, &first](uint64_t res) {
            logger_mtx.lock();

            if (!first) {
                log_stream << ", ";
            }
            first = false;
            log_stream << res;

            logger_mtx.unlock();
        };

        log_stream << "Search results: \n{";

        auto res = client_runner->search(kw, print_callback);

        log_stream << "}" << std::endl;
    }

    //    if (bench_count > 0) {
    //        std::cout << "-------------- Search Benchmarks --------------" <<
    //        std::endl; client_runner->search_benchmark(bench_count);
    //    }

    client_runner.reset();

    sse::crypto::cleanup_crypto_lib();


    return 0;
}

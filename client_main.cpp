//
//  client_main.cpp
//  sophos
//
//  Created by Raphael Bost on 03/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_client.hpp"
#include "logger.hpp"
#include "thread_pool.hpp"

#include <sse/dbparser/DBParserJSON.h>
#include <sse/crypto/utils.hpp>

#include <stdio.h>

void load_inverted_index(sse::sophos::SophosClientRunner &runner, const std::string& path)
{
    sse::dbparser::DBParserJSON parser(path.c_str());
    ThreadPool pool(8);
    
    std::atomic_size_t counter(0);
    
    auto add_list_callback = [&runner,&pool,&counter](const string kw, const list<unsigned> docs)
    {
        auto work = [&runner,&counter](const string& keyword, const list<unsigned> &documents)
        {
            for (unsigned doc : documents) {
                runner.async_update(keyword, doc);
            }
            counter++;

            if ((counter % 100) == 0) {
                sse::logger::log(sse::logger::INFO) << "\rLoading: " << counter << " keywords processed" << std::flush;
            }
        };
        pool.enqueue(work,kw,docs);
        
    };
    
    parser.addCallbackList(add_list_callback);
    parser.parse();
    
    pool.join();
    sse::logger::log(sse::logger::INFO) << "\rLoading: " << counter << " keywords processed" << std::endl;
    
    runner.wait_updates_completion();
}

int main(int argc, char** argv) {
    sse::logger::set_severity(sse::logger::INFO);
    sse::logger::set_benchmark_file("benchmark_client.out");
    
    sse::crypto::init_crypto_lib();
    
    std::string save_path = "/Users/rbost/Code/sse/sophos/test.csdb";
//    std::string save_path = "/Users/raphaelbost/Code/sse/sophos/test.csdb";
    
    sse::sophos::SophosClientRunner client_runner("localhost:4242", save_path, 1e6, 1e5);
    
    opterr = 0;
    int c;

    std::list<std::string> input_files;
    std::list<std::string> keywords;

    
    while ((c = getopt (argc, argv, "i:d")) != -1)
        switch (c)
    {
        case 'i':
            input_files.push_back(std::string(optarg));
            break;
        case 'd': // load a default file, only for debugging
            input_files.push_back("/Volumes/Storage/WP_Inverted/inverted_index_all_sizes/inverted_index_1000.json");
//            input_files.push_back("/Users/raphaelbost/Documents/inverted_index_1000.json");
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
            exit(0);
    }
    
    for (int index = optind; index < argc; index++)
    {
        keywords.push_back(std::string(argv[index]));
    }


    for (std::string &path : input_files) {
        sse::logger::log(sse::logger::INFO) << "Load file " << path << std::endl;
        load_inverted_index(client_runner, path);
        sse::logger::log(sse::logger::INFO) << "Done loading file " << path << std::endl;
    }
    
    for (std::string &kw : keywords) {
        std::cout << "-------------- Search --------------" << std::endl;
        auto res = client_runner.search(kw);
        
        bool first = true;
        sse::logger::log(sse::logger::INFO) << "{";
        for (auto i : res) {
            if (!first) {
                sse::logger::log(sse::logger::INFO) << ", ";
            }
            
            first = false;
            sse::logger::log(sse::logger::INFO) << i;
        }
        sse::logger::log(sse::logger::INFO) << "}" << std::endl;
    }
    sse::crypto::cleanup_crypto_lib();

    
    return 0;
}

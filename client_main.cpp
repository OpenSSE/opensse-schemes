//
//  client_main.cpp
//  sophos
//
//  Created by Raphael Bost on 03/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_client.hpp"
#include "logger.hpp"

#include <sse/crypto/utils.hpp>

#include <stdio.h>

int main(int argc, char** argv) {
    sse::logger::set_severity(sse::logger::INFO);
    sse::logger::set_benchmark_file("benchmark_client.out");
    
    sse::crypto::init_crypto_lib();
    
    opterr = 0;
    int c;

    std::list<std::string> input_files;
    std::list<std::string> keywords;
    std::string json_file;
    std::string client_db;
    std::string output_path;
    bool print_stats = false;
    
    while ((c = getopt (argc, argv, "l:b:o:i:dp")) != -1)
        switch (c)
    {
        case 'l':
            input_files.push_back(std::string(optarg));
            break;
        case 'b':
            client_db = std::string(optarg);
            break;
        case 'o':
            output_path = std::string(optarg);
            break;
        case 'i':
            json_file = std::string(optarg);
            break;
        case 'd': // load a default file, only for debugging
//            input_files.push_back("/Volumes/Storage/WP_Inverted/inverted_index_all_sizes/inverted_index_10000.json");
            input_files.push_back("/Users/raphaelbost/Documents/inverted_index_1000.json");
            break;
        case 'p':
            print_stats = true;
            break;
        case '?':
            if (optopt == 'l' || optopt == 'b' || optopt == 'o' || optopt == 'i')
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
    
    
    for (int index = optind; index < argc; index++)
    {
          keywords.push_back(std::string(argv[index]));
    }

    if (client_db.size()==0) {
        sse::logger::log(sse::logger::ERROR) << "Client database not specified" << std::endl;
        sse::logger::log(sse::logger::ERROR) << "Using \'test.csdb\' by default" << std::endl;
        client_db = "test.csdb";
    }else{
        sse::logger::log(sse::logger::INFO) << "Running client with database " << client_db << std::endl;
    }
    
    std::unique_ptr<sse::sophos::SophosClientRunner> client_runner;
    
    if (json_file.size() > 0) {
        client_runner.reset( new sse::sophos::SophosClientRunner("localhost:4242", client_db, json_file) );
    }else{
         client_runner.reset( new sse::sophos::SophosClientRunner("localhost:4242", client_db, 1e6, 1e5) );
    }

    for (std::string &path : input_files) {
        sse::logger::log(sse::logger::INFO) << "Load file " << path << std::endl;
        client_runner->load_inverted_index(path);
        sse::logger::log(sse::logger::INFO) << "Done loading file " << path << std::endl;
    }
    
    for (std::string &kw : keywords) {
        std::cout << "-------------- Search --------------" << std::endl;
        auto res = client_runner->search(kw);
        
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
    
    
    if (output_path.size()>0) {
        client_runner->output_db(output_path);
    }
    
    if (print_stats)
    {
        client_runner->print_stats(std::cout);
    }
    
    client_runner.reset();
    
    sse::crypto::cleanup_crypto_lib();

    
    return 0;
}

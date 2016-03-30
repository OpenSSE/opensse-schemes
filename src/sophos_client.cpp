//
//  sophos_client.cpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_client.hpp"

#include <chrono>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>

#include <grpc/grpc.h>
#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

#include "sophos.grpc.pb.h"

class SophosClientRunner {
public:
    SophosClientRunner(std::shared_ptr<grpc::Channel> channel, const std::string& path)
    : stub_(sophos::Sophos::NewStub(channel)) {

    }
    
    void search(const std::string& keyword)
    {
        grpc::ClientContext context;
        sophos::SearchRequest request;
        sophos::SearchReply reply;
        
        request.set_search_token(keyword);
        request.set_add_count(32);
        
        
        std::unique_ptr<grpc::ClientReader<sophos::SearchReply> > reader( stub_->search(&context, request) );
        while (reader->Read(&reply)) {
            std::cout << "New result: "
            << reply.result() << std::endl;
        }
        grpc::Status status = reader->Finish();
        if (status.ok()) {
            std::cout << "Search succeeded." << std::endl;
        } else {
            std::cout << "Search failed." << std::endl;
        }
    }
    
    void update(const std::string& keyword, uint64_t index)
    {
        grpc::ClientContext context;
        sophos::UpdateRequest request;
        google::protobuf::Empty e;
        
        request.set_update_token(keyword);
        request.set_index(index);
        
        grpc::Status status = stub_->update(&context, request, &e);
        
        if (status.ok()) {
            std::cout << "Update succeeded." << std::endl;
        } else {
            std::cout << "Update failed." << std::endl;
        }

    }
    std::unique_ptr<sophos::Sophos::Stub> stub_;
};

int main(int argc, char** argv) {
    // Expect only arg: --db_path=path/to/route_guide_db.json.
    std::string save_path = "save.dat";
    SophosClientRunner client(
                           grpc::CreateChannel("localhost:4242",
                                               grpc::InsecureChannelCredentials()),
                           save_path);
    
    std::cout << "-------------- Search --------------" << std::endl;
    client.search("toto");
    std::cout << "-------------- Search --------------" << std::endl;
    client.search("coucou");
    
    std::cout << "-------------- Update --------------" << std::endl;
    client.update("kiki", 45);
    
    return 0;
}

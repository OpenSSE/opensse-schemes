//
//  sophos_server.cpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_server.hpp"

#include "utils.hpp"

#include <fstream>

#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <grpc++/security/server_credentials.h>


namespace sse {
    namespace sophos {

        const std::string SophosImpl::pk_file = "tdp_pk.key";
        const std::string SophosImpl::pairs_map_file = "pairs.dat";

SophosImpl::SophosImpl(const std::string& path) :
storage_path_(path)
{
    if (is_directory(storage_path_)) {
        // try to initialize everything from this directory
        
        std::string pk_path     = storage_path_ + "/" + pk_file;
        std::string pairs_map_path  = storage_path_ + "/" + pairs_map_file;

        if (!is_file(pk_path)) {
            // error, the secret key file is not there
            throw std::runtime_error("Missing secret key file");
        }
        if (!is_directory(pairs_map_path)) {
            // error, the token map data is not there
            throw std::runtime_error("Missing data");
        }
        
        std::ifstream pk_in(pk_path.c_str());
        std::stringstream pk_buf;
        
        pk_buf << pk_in.rdbuf();

        server_.reset(new SophosServer(pairs_map_path, pk_buf.str()));
    }else if (exists(storage_path_)){
        // there should be nothing else than a directory at path, but we found something  ...
        throw std::runtime_error(storage_path_ + ": not a directory");
    }else{
        // postpone creation upon the reception of the setup message
    }
}

grpc::Status SophosImpl::setup(grpc::ServerContext* context,
                    const sophos::SetupMessage* message,
                    google::protobuf::Empty* e)
{
    
    std::cout << "Setup!" << std::endl;
    
    if (server_) {
        // problem, the server is already set up
        std::cerr << "Info: server received a setup message but is already set up" << std::endl;

        return grpc::Status(grpc::FAILED_PRECONDITION, "The server was already set up");
    }
    
    // create the content directory but first check that nothing is already there
    
    if (exists(storage_path_))
    {
        std::cerr << "Error: Unable to create the server's content directory" << std::endl;

        return grpc::Status(grpc::ALREADY_EXISTS, "Unable to create the server's content directory");
    }
    
    if (!create_directory(storage_path_, (mode_t)0700)) {
        std::cerr << "Error: Unable to create the server's content directory" << std::endl;

        return grpc::Status(grpc::PERMISSION_DENIED, "Unable to create the server's content directory");
    }
    
    // now, we have the directory, and we should be able to conclude the setup
    // however, the bucket_map constructor in SophosServer's constructor can raise an exception, so we need to take care of it
    
    std::string pairs_map_path  = storage_path_ + "/" + pairs_map_file;

    try {
        server_.reset(new SophosServer(pairs_map_path, message->setup_size(), message->public_key()));
    } catch (std::exception &e) {
        std::cerr << "Error when setting up the server's core" << std::endl;
        
        server_.reset();
        return grpc::Status(grpc::FAILED_PRECONDITION, "Unable to create the server's core. Error in libssdmap");
    }

    // write the public key in a file
    std::string pk_path     = storage_path_ + "/" + pk_file;

    std::ofstream pk_out(pk_path.c_str());
    if (!pk_out.is_open()) {
        // error
        
        std::cerr << "Error when writing the public key" << std::endl;

        return grpc::Status(grpc::PERMISSION_DENIED, "Unable to write the public key to disk");
    }
    pk_out << message->public_key();
    pk_out.close();

    std::cout << "Successful setup" << std::endl;

    return grpc::Status::OK;
}

grpc::Status SophosImpl::search(grpc::ServerContext* context,
                    const sophos::SearchRequestMessage* mes,
                    grpc::ServerWriter<sophos::SearchReply>* writer)
{
    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
    }

    std::cout << "Search!" << std::endl;

    
    auto res_list = server_->search(message_to_request(mes));
    
    for (auto& i : res_list) {
        sophos::SearchReply reply;
        reply.set_result((uint64_t) i);
        
        writer->Write(reply);
    }
    
    return grpc::Status::OK;
}

grpc::Status SophosImpl::update(grpc::ServerContext* context,
                    const sophos::UpdateRequestMessage* mes,
                    google::protobuf::Empty* e)
{

    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
    }

    std::cout << "Update!" << std::endl;

    server_->update(message_to_request(mes));
    
    return grpc::Status::OK;
}


SearchRequest message_to_request(const SearchRequestMessage* mes)
{
    SearchRequest req;
    
    req.add_count = mes->add_count();
    req.derivation_key = mes->derivation_key();
    std::copy(mes->search_token().begin(), mes->search_token().end(), req.token.begin());

    return req;
}

UpdateRequest message_to_request(const UpdateRequestMessage* mes)
{
    UpdateRequest req;
    
    req.index = mes->index();
    std::copy(mes->update_token().begin(), mes->update_token().end(), req.token.begin());

    return req;
}
       
void run_sophos_server(const std::string &address, const std::string& server_db_path, grpc::Server **server_ptr) {
    std::string server_address(address);
    SophosImpl service(server_db_path);
    
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
    
    *server_ptr = server.get();

    server->Wait();
}

} // namespace sophos
} // namespace sse
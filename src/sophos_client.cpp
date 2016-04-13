//
//  sophos_client.cpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_client.hpp"

#include "sophos_net_types.hpp"
#include "large_storage_sophos_client.hpp"
#include "medium_storage_sophos_client.hpp"

#include "utils.hpp"
#include "logger.hpp"

#include <chrono>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <fstream>

#include <grpc/grpc.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

namespace sse {
namespace sophos {


SophosClientRunner::SophosClientRunner(const std::string& address, const std::string& path, size_t setup_size, size_t n_keywords)
    : update_launched_count_(0), update_completed_count_(0)
{
    std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address,
                                                               grpc::InsecureChannelCredentials()));
    stub_ = std::move(sophos::Sophos::NewStub(channel));
                    
    if (is_directory(path)) {
        // try to initialize everything from this directory

        load_client(path);
        
    }else if (exists(path)){
        // there should be nothing else than a directory at path, but we found something  ...
        throw std::runtime_error(path + ": not a directory");
    }else{
        // initialize a brand new Sophos client
        
        setup_client(path, setup_size, n_keywords);
    }
    
    // start the thread that will look for completed updates
    update_completion_thread_ = new std::thread(&SophosClientRunner::update_completion_loop, this);
}

//    SophosClientRunner::SophosClientRunner(const std::string& address, const std::string& db_path, const std::string& json_path)
//    : update_launched_count_(0), update_completed_count_(0)
//    {
//        std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address,
//                                                                   grpc::InsecureChannelCredentials()));
//        stub_ = std::move(sophos::Sophos::NewStub(channel));
//        
//        std::string sk_path = db_path + "/tdp_sk.key";
//        std::string master_key_path = db_path + "/derivation_master.key";
//        std::string token_map_path = db_path + "/tokens.dat";
//        std::string keyword_index_path = db_path + "/keywords.csv";
//        
//        if (exists(db_path)){
//            throw std::runtime_error("File or directory already exists at " + db_path);
//        }else{
//            // initialize a brand new Sophos client
//            
//            // start by creating a new directory
//            
//            if (!create_directory(db_path, (mode_t)0700)) {
//                throw std::runtime_error(db_path + ": unable to create directory");
//            }
//            
//            client_ = std::move(LargeStorageSophosClient::construct_from_json(token_map_path, keyword_index_path, json_path));
//            
//            // write keys to files
//            std::ofstream sk_out(sk_path.c_str());
//            if (!sk_out.is_open()) {
//                throw std::runtime_error(sk_path + ": unable to write the secret key");
//            }
//            
//            sk_out << client_->private_key();
//            sk_out.close();
//            
//            std::ofstream master_key_out(master_key_path.c_str());
//            if (!master_key_out.is_open()) {
//                throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
//            }
//            
//            master_key_out << client_->master_derivation_key();
//            master_key_out.close();
//            
//        }
//        
//        // start the thread that will look for completed updates
//        update_completion_thread_ = new std::thread(&SophosClientRunner::update_completion_loop, this);
//    }
    

SophosClientRunner::~SophosClientRunner()
{
    update_cq_.Shutdown();
    wait_updates_completion();
//    update_completion_thread_->join();
}
    
    
void SophosClientRunner::load_client(const std::string& path)
{
    // try to initialize everything from this directory
    std::string sk_path = path + "/tdp_sk.key";
    std::string master_key_path = path + "/derivation_master.key";
    std::string rsa_prg_key_path = path + "/rsa_prg.key";
    std::string token_map_path = path + "/tokens.dat";
    std::string keyword_index_path = path + "/keywords.csv";
    

    if (!is_file(sk_path)) {
        // error, the secret key file is not there
        throw std::runtime_error("Missing secret key file");
    }
    if (!is_file(master_key_path)) {
        // error, the derivation key file is not there
        throw std::runtime_error("Missing master derivation key file");
    }
    if (!is_file(rsa_prg_key_path)) {
        // error, the rsa prg key file is not there
        throw std::runtime_error("Missing rsa prg key file");
    }
    if (!is_directory(token_map_path)) {
        // error, the token map data is not there
        throw std::runtime_error("Missing token data");
    }
    if (!is_file(keyword_index_path)) {
        // error, the derivation key file is not there
        throw std::runtime_error("Missing keyword indices");
    }
    
    std::ifstream sk_in(sk_path.c_str());
    std::ifstream master_key_in(master_key_path.c_str());
    std::ifstream rsa_prg_key_in(rsa_prg_key_path.c_str());
    std::stringstream sk_buf, master_key_buf, rsa_prg_key_buf;
    
    sk_buf << sk_in.rdbuf();
    master_key_buf << master_key_in.rdbuf();
    rsa_prg_key_buf << rsa_prg_key_in.rdbuf();
    
    client_.reset(new  MediumStorageSophosClient(token_map_path, keyword_index_path, sk_buf.str(), master_key_buf.str(), rsa_prg_key_buf.str()));
}

    void SophosClientRunner::setup_client(const std::string& path, size_t setup_size, size_t n_keywords)
    {
        std::string sk_path = path + "/tdp_sk.key";
        std::string master_key_path = path + "/derivation_master.key";
        std::string rsa_prg_key_path = path + "/rsa_prg.key";
        std::string token_map_path = path + "/tokens.dat";
        std::string keyword_index_path = path + "/keywords.csv";

        // start by creating a new directory
        
        if (!create_directory(path, (mode_t)0700)) {
            throw std::runtime_error(path + ": unable to create directory");
        }
        
        client_.reset(new MediumStorageSophosClient(token_map_path, keyword_index_path, n_keywords));
        
        // write keys to files
        std::ofstream sk_out(sk_path.c_str());
        if (!sk_out.is_open()) {
            throw std::runtime_error(sk_path + ": unable to write the secret key");
        }
        
        sk_out << client_->private_key();
        sk_out.close();
        
        std::ofstream master_key_out(master_key_path.c_str());
        if (!master_key_out.is_open()) {
            throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
        }
        
        master_key_out << client_->master_derivation_key();
        master_key_out.close();
        
        std::ofstream rsa_prg_key_out(rsa_prg_key_path.c_str());
        if (!rsa_prg_key_out.is_open()) {
            throw std::runtime_error(rsa_prg_key_path + ": unable to write the rsa prg key");
        }
        
        rsa_prg_key_out << dynamic_cast<MediumStorageSophosClient*>(client_.get())->rsa_prg_key();
        rsa_prg_key_out.close();

        // send a setup message to the server
        bool success = send_setup(setup_size);
        
        if (!success) {
            throw std::runtime_error("Unsuccessful server setup");
        }

    }

bool SophosClientRunner::send_setup(const size_t setup_size) const
{
    grpc::ClientContext context;
    sophos::SetupMessage message;
    google::protobuf::Empty e;

    message.set_setup_size(setup_size);
    message.set_public_key(client_->public_key());
    
    grpc::Status status = stub_->setup(&context, message, &e);

    if (status.ok()) {
        logger::log(logger::TRACE) << "Setup succeeded." << std::endl;
    } else {
        logger::log(logger::ERROR) << "Setup failed: " << std::endl;
        logger::log(logger::ERROR) << status.error_message() << std::endl;
        return false;
    }

    return true;
}
    
    
const SophosClient& SophosClientRunner::client() const
{
    if (!client_) {
        throw std::logic_error("Invalid state");
    }
    return *client_;
}
    
std::list<uint64_t> SophosClientRunner::search(const std::string& keyword) const
{
    logger::log(logger::TRACE) << "Search " << keyword << std::endl;
    
    grpc::ClientContext context;
    sophos::SearchRequestMessage message;
    sophos::SearchReply reply;
    
    message = request_to_message(client_->search_request(keyword));
    
    std::unique_ptr<grpc::ClientReader<sophos::SearchReply> > reader( stub_->search(&context, message) );
    std::list<uint64_t> results;
    
    
    while (reader->Read(&reply)) {
        logger::log(logger::TRACE) << "New result: "
        << std::dec << reply.result() << std::endl;
        results.push_back(reply.result());
    }
    grpc::Status status = reader->Finish();
    if (status.ok()) {
        logger::log(logger::TRACE) << "Search succeeded." << std::endl;
    } else {
        logger::log(logger::ERROR) << "Search failed:" << std::endl;
        logger::log(logger::ERROR) << status.error_message() << std::endl;
    }
    
    return results;
}

void SophosClientRunner::update(const std::string& keyword, uint64_t index)
{
    grpc::ClientContext context;
    sophos::UpdateRequestMessage message;
    google::protobuf::Empty e;
    
    message = request_to_message(client_->update_request(keyword, index));

    grpc::Status status = stub_->update(&context, message, &e);
    
    if (status.ok()) {
        logger::log(logger::TRACE) << "Update succeeded." << std::endl;
    } else {
        logger::log(logger::ERROR) << "Update failed:" << std::endl;
        logger::log(logger::ERROR) << status.error_message() << std::endl;
    }

}

void SophosClientRunner::async_update(const std::string& keyword, uint64_t index)
{
    grpc::ClientContext context;
    sophos::UpdateRequestMessage message;
//    google::protobuf::Empty *e = new google::protobuf::Empty();
//    grpc::Status *status = new grpc::Status();

    update_tag_type *tag = new update_tag_type();
    
    message = request_to_message(client_->update_request(keyword, index));
    
    std::unique_ptr<grpc::ClientAsyncResponseReader<google::protobuf::Empty> > rpc(
                                                                stub_->Asyncupdate(&context, message, &update_cq_));

    tag->reply.reset(new google::protobuf::Empty());
    tag->status.reset(new grpc::Status());
    tag->index.reset(new size_t(update_launched_count_++));
    
    rpc->Finish(tag->reply.get(), tag->status.get(), tag);

//    if (status.ok()) {
//        logger::log(logger::TRACE) << "Update succeeded." << std::endl;
//    } else {
//        logger::log(logger::ERROR) << "Update failed:" << std::endl;
//        logger::log(logger::ERROR) << status.error_message() << std::endl;
//    }
    
}

void SophosClientRunner::wait_updates_completion()
{
    std::unique_lock<std::mutex> lock(update_completion_mtx_);
    update_completion_cv_.wait(lock, [this]{ return update_launched_count_ == update_completed_count_; });
}

void SophosClientRunner::update_completion_loop()
{
    update_tag_type* tag;
    bool ok = false;

    for (; ; ok = false) {
        bool r = update_cq_.Next((void**)&tag, &ok);
        if (!r) {
            logger::log(logger::TRACE) << "Close asynchronous update loop" << std::endl;
            return;
        }

        logger::log(logger::TRACE) << "Asynchronous update " << std::dec << *(tag->index) << " succeeded." << std::endl;
        delete tag;
        
        
        {
            std::lock_guard<std::mutex> lock(update_completion_mtx_);
            update_completed_count_++;
            
            if (update_launched_count_ == update_completed_count_) {
                update_completion_cv_.notify_all();
            }
        }
    }
}
    
bool SophosClientRunner::output_db(const std::string& out_path)
{
    std::ofstream os(out_path);

    if (!os.is_open()) {
        os.close();
        
        logger::log(logger::ERROR) << "Unable to create output file " << out_path << std::endl;

        return false;
    }

    client_->db_to_json(os);
    
    os.close();
    
    return true;
}

std::ostream& SophosClientRunner::print_stats(std::ostream& out) const
{
    return client_->print_stats(out);
}

SearchRequestMessage request_to_message(const SearchRequest& req)
{
    SearchRequestMessage mes;
    
    mes.set_add_count(req.add_count);
    mes.set_derivation_key(req.derivation_key);
    mes.set_search_token(req.token.data(), req.token.size());
    
    return mes;
}

UpdateRequestMessage request_to_message(const UpdateRequest& req)
{
    UpdateRequestMessage mes;
    
    mes.set_update_token(req.token.data(), req.token.size());
    mes.set_index(req.index);
    
    return mes;
}


} // namespace sophos
} // namespace sse
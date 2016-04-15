//
//  sophos_client.cpp
//  sophos
//
//  Created by Raphael Bost on 30/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include "sophos_client_runner.hpp"

#include "sophos_net_types.hpp"
#include "large_storage_sophos_client.hpp"
#include "medium_storage_sophos_client.hpp"

#include "thread_pool.hpp"
#include "utils.hpp"
#include "logger.hpp"

#include <sse/dbparser/DBParserJSON.h>

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


SophosClientRunner::SophosClientRunner(const std::string& address, const std::string& path, size_t setup_size, uint32_t n_keywords)
    : update_launched_count_(0), update_completed_count_(0)
{
    std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address,
                                                               grpc::InsecureChannelCredentials()));
    stub_ = std::move(sophos::Sophos::NewStub(channel));
                    
    if (is_directory(path)) {
        // try to initialize everything from this directory

        client_ = MediumStorageSophosClient::construct_from_directory(path);
        
    }else if (exists(path)){
        // there should be nothing else than a directory at path, but we found something  ...
        throw std::runtime_error(path + ": not a directory");
    }else{
        // initialize a brand new Sophos client
        
        // start by creating a new directory
        
        if (!create_directory(path, (mode_t)0700)) {
            throw std::runtime_error(path + ": unable to create directory");
        }
        
        client_ = MediumStorageSophosClient::init_in_directory(path,n_keywords);
        
        // send a setup message to the server
        bool success = send_setup(setup_size);
        
        if (!success) {
            throw std::runtime_error("Unsuccessful server setup");
        }
    }
    
    // start the thread that will look for completed updates
    update_completion_thread_ = new std::thread(&SophosClientRunner::update_completion_loop, this);
}

    SophosClientRunner::SophosClientRunner(const std::string& address, const std::string& db_path, const std::string& json_path)
    : update_launched_count_(0), update_completed_count_(0)
    {
        std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address,
                                                                   grpc::InsecureChannelCredentials()));
        stub_ = std::move(sophos::Sophos::NewStub(channel));
        
        if (exists(db_path)){
            throw std::runtime_error("File or directory already exists at " + db_path);
        }else{
            // initialize a brand new Sophos client
            
            // start by creating a new directory
            
            if (!create_directory(db_path, (mode_t)0700)) {
                throw std::runtime_error(db_path + ": unable to create directory");
            }
            
            client_ = MediumStorageSophosClient::construct_from_json(db_path, json_path);
        }
        
        // start the thread that will look for completed updates
        update_completion_thread_ = new std::thread(&SophosClientRunner::update_completion_loop, this);
    }
    

SophosClientRunner::~SophosClientRunner()
{
    update_cq_.Shutdown();
    wait_updates_completion();
    update_completion_thread_->join();
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
    stop_update_completion_thread_ = true;
    std::unique_lock<std::mutex> lock(update_completion_mtx_);
    update_completion_cv_.wait(lock, [this]{ return update_launched_count_ == update_completed_count_; });
}

void SophosClientRunner::update_completion_loop()
{
    update_tag_type* tag;
    bool ok = false;

    for (; stop_update_completion_thread_ == false ; ok = false) {
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
    
bool SophosClientRunner::load_inverted_index(const std::string& path)
{
    try {
        
        dbparser::DBParserJSON parser(path.c_str());
        ThreadPool pool(std::thread::hardware_concurrency());
        
        std::atomic_size_t counter(0);
        
        auto add_list_callback = [this,&pool,&counter](const string kw, const list<unsigned> docs)
        {
            auto work = [this,&counter](const string& keyword, const list<unsigned> &documents)
            {
                for (unsigned doc : documents) {
                    this->async_update(keyword, doc);
                }
                counter++;
                
                if ((counter % 100) == 0) {
                    logger::log(sse::logger::INFO) << "\rLoading: " << counter << " keywords processed" << std::flush;
                }
            };
            pool.enqueue(work,kw,docs);
            
        };
        
        parser.addCallbackList(add_list_callback);
        parser.parse();
        
        pool.join();
        logger::log(sse::logger::INFO) << "\rLoading: " << counter << " keywords processed" << std::endl;
        
        wait_updates_completion();
        
        return true;
    } catch (std::exception& e) {
        logger::log(logger::ERROR) << "\nFailed to load file " << path << " : " << e.what() << std::endl;
        return false;
    }
    return false;
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